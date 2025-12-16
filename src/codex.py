#!/usr/bin/env python3

from __future__ import annotations
from random import shuffle
import re
import subprocess
import threading
from typing import Any, Mapping, Optional, Sequence
import concurrent.futures
import json

from src.models import *
from . import db, ctfd

STOP_EVENT = threading.Event()
RUNNING_CODEX: dict[int: subprocess.Popen] = {}


def build_flag_regex(flag_regex: str | None, flag_format: str) -> re.Pattern:
    if flag_regex:
        try:
            flag_regex = re.compile(flag_regex)
        except re.error as exc:
            raise ValueError(f"FLAG_REGEX {flag_regex!r} is not a valid regex") from exc
    else:
        escaped_spec = re.escape(flag_format)
        placeholder = re.escape("{}")
        flag_regex = escaped_spec.replace(placeholder, r"\{[^}]+\}")
        try:
            flag_regex = re.compile(flag_regex)
        except re.error as exc:
            raise ValueError(f"FLAG_FORMAT {spec!r} is not a valid format. Example: testCTF{{}}") from exc
    
    return flag_regex

FLAG_RE = build_flag_regex(FLAG_REGEX, FLAG_FORMAT)


def strip_ansi(text: str) -> str:
    return re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)


def extract_tokens(output: str = "", task: Task = None) -> int:
    if output:
        clean = strip_ansi(output)
    elif task:
        log_path = CODEX_DIR / task.name / "thinking.log"
        try:
            with open(log_path, "r", encoding="utf-8") as f:
                clean = strip_ansi(f.read())
        except FileNotFoundError:
            return 0
    else:
        error("extract_tokens has invalid parameters")
        return 0

    match = re.search(r"tokens used\s*([\d,]+)", clean, flags=re.IGNORECASE)
    if match:
        try:
            return int(match.group(1).replace(",", ""))
        except (ValueError, IndexError):
            error("Failed to extract_tokens")
            return 0
    return 0


def extract_thinking(output: str) -> str:
    clean = strip_ansi(output)
    lower = clean.lower()
    idx = lower.find("thinking")
    if idx == -1:
        return clean
    snippet = clean[idx:].splitlines()
    if snippet:
        snippet = snippet[1:]  # drop the 'thinking' label line
    return "\n".join(snippet).rstrip()


def persist_task_logs(task: Task, output: str) -> None:
    try:
        logs_root = CODEX_DIR / task.name
        logs_root.mkdir(parents=True, exist_ok=True)
        (logs_root / "thinking.log").write_text(output, encoding="utf-8")
    except OSError as exc:
        warning("failed to write logs under %s: %s", task.name, exc)


def run_codex_with_logs(
    command: list[str],
    task: Task,
) -> str:
    logs_root = CODEX_DIR / task.name
    logs_root.mkdir(parents=True, exist_ok=True)

    output_log = logs_root / "thinking.log"
    completed_normally = False

    with output_log.open("wb") as fh:
        proc = subprocess.Popen(
            command,
            cwd=TASKS_DIR / task.name,
            stdout=fh,
            stderr=subprocess.STDOUT,
            env=dict(os.environ),
        )
        if task.id is not None:
            RUNNING_CODEX[task.id] = proc
        try:
            proc.wait(timeout=CODEX_TIMEOUT)
            completed_normally = True
        except Exception:
            completed_normally = False
        finally:
            if task.id is not None:
                RUNNING_CODEX.pop(task.id, None)

    output = output_log.read_text(encoding="utf-8", errors="ignore")
    tokens = extract_tokens(output=output)
    if tokens:
        info(f"tokens used: {tokens}")
    return output


def run_codex(
    task: Task,
    prompt: str,
) -> str:
    info("running codex for %s", task.name)
    command = CODEX_COMMAND + [prompt]
    return run_codex_with_logs(command, task)


def local_attachment_names(task: Task) -> list[str]:
    task_dir = TASKS_DIR / task.name
    return sorted(
        p.name
        for p in task_dir.iterdir()
        if p.is_file() and p.name != "metadata.json"
    )


def build_codex_prompt(task: Task, instance_url: str | None = None) -> str:
    context_path = TASKS_DIR / task.name / "codex_context.txt"
    if context_path.exists():
        context = context_path.read_text(encoding="utf-8", errors="replace").strip()
    else:
        context = ""

    parts = [
        "Solve this Jeopardy CTF challenge inside the current directory. Do not read anything above that directory.",
        f"Flag format (regex): {FLAG_FORMAT}",
        "Do not install new tools or use sudo.",
    ]
    if instance_url:
        parts.append(f"The challenge is available at this URL: {instance_url}")
    if context:
        parts.extend(
            [
                "Previous attempts summary (continue from here, do not repeat work):",
                context,
            ]
        )
    return "\n".join(parts)


def mark_all_running_failed(reason: str = "interrupted") -> None:
    entries = db.read_entries(DB_PATH)
    for task in entries:
        if entry.status == "running":
            db.insert_entry(task.id, "failed", error=reason)


def process_task(task: Task) -> int:
    session = ctfd.create_session()

    task_dir = TASKS_DIR / task.name
    task_json_path = task_dir / "task.json"
    task_info = {}
    if task_json_path.exists():
        with open(task_json_path, 'r', encoding='utf-8') as f:
            task_info = json.load(f)

    is_docker_task = task_info.get("type") == "dynamic_check_docker"

    if not session:
        warning("could not login to CTFd; running without submissions", CTFD_URL)
        if is_docker_task:
            error("Cannot process docker task without a session.")
            db.insert_entry(task.id, "failed", error="login failed")
            return 1
    elif task.id in [t.id for t in ctfd.fetch_tasks(session) if t.status == "solved"]:
        db.insert_entry(task.id, "solved", error="solved by a human")
        info("skipping %s (%s): solved while queued", task.name, task.id)
        return 0

    instance_url = None
    try:
        if is_docker_task:
            if not session:
                # This should not be reached due to the check above, but as a safeguard:
                error("Cannot process docker task without a session.")
                db.insert_entry(task.id, "failed", error="login failed")
                return 1

            instance_url = ctfd.get_instance_url(session, task.id)
            if not instance_url:
                info(f"No running instance for {task.name}, launching one.")
                instance_url = ctfd.launch_instance(session, task.id)

            if instance_url:
                info(f"Instance for {task.name} is at: {instance_url}")
            else:
                warning(f"Failed to get or launch instance for {task.name}")

        prompt = build_codex_prompt(task, instance_url)
        db.insert_entry(task.id, "running")
        last_output = ""

        for attempt in range(1, MAX_CODEX_ATTEMPTS + 1):
            if STOP_EVENT.is_set():
                return
            try:
                output = run_codex(task, prompt)
            except FileNotFoundError:
                db.insert_entry(task.id, "failed", error="codex command not found")
                return 1
            last_output = output

            persist_task_logs(task, output)
            flags = [m.group(0) for m in FLAG_RE.finditer(output)]

            validated = False
            for flag in reversed(flags):
                if session and ctfd.submit_flag(session, task.id, flag):
                    info(f"successfull flag found for {task.name}: {flag}")
                    db.insert_entry(task.id, "done", flag=flag, tokens=extract_tokens(output=output))
                    return 0
                else:
                    info(f"incorrect flag found for {task.name}: {flag}")

            prompt = (
                prompt
                + "\n\nThis is incorrect flag."
                " Keep working and print ONLY the correct final flag."
            )

        warning(f"max attempts reached for {task.name}")
        db.insert_entry(task.id, "failed", tokens=extract_tokens(output=last_output), error="max attempts reached")
        return 0
    finally:
        if is_docker_task and instance_url and session:
            info(f"Deleting instance for {task.name}")
            ctfd.delete_instance(session, task.id)


def run_tasks():
    if not TASKS_DIR.exists():
        error(f"task directory does not exist: {TASKS_DIR}")
        return 1

    pending: list[Task] = db.read_entries(DB_PATH)
    if not pending:
        error("no tasks in the database")
        return 1

    shuffle(pending)
    pending: list[Task] = list(pending)
    active: set[concurrent.futures.Future] = set()
    future_to_task: dict[concurrent.futures.Future, Task] = {}

    executor = concurrent.futures.ThreadPoolExecutor(max_workers=MAX_CODEX_WORKERS)
    try:
        while pending or active:
            while pending and len(active) < MAX_CODEX_WORKERS:
                task = pending.pop(0)
                fut = executor.submit(process_task, task)
                active.add(fut)
                future_to_task[fut] = task

            done, active = concurrent.futures.wait(active, return_when=concurrent.futures.FIRST_COMPLETED)

            for f in done:
                task = future_to_task.pop(f)
                f.result()
    except KeyboardInterrupt:
        info("Stopping signal recieved")
    finally:
        info("Exiting")
        for fut, task in future_to_task.items():
            db.insert_entry(task.id, "failed", tokens=extract_tokens(task=task), error="interrupted")
            fut.cancel()
        STOP_EVENT.set()
        for proc in RUNNING_CODEX.values():
            proc.kill()
        executor.shutdown(wait=True)
        info("Exited")


def handle_sigterm(signum, frame):
    raise KeyboardInterrupt


def main():
    info(f"FLAG_REGEX: {flag_regex}")
    signal(SIGTERM, handle_sigterm)
    db.move_status(DB_PATH, "running", "failed")
    info("Starting Codex worker …")
    run_tasks()


if __name__ == "__main__":
    main()

