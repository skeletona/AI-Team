#!/usr/bin/env python3
"""
Run `codex` for each downloaded task, capture flags, and optionally submit them to the
same CTFd instance that `autonomous_ctfd.py` targets.

The runner loads credentials from `.env` (via `dotenv`) and follows `FLAG_FORMAT` for
matching. Flags are always sought in Codex's combined output, but submissions only
happen in normal mode;
"""

from __future__ import annotations
from random import shuffle
import re
import subprocess
import threading
from typing import Any, Mapping, Optional, Sequence
import concurrent.futures

from src.models import *
from . import db, ctfd

STOP_EVENT = threading.Event()
RUNNING_CODEX: dict = {int: subprocess.Popen}


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
    
    logging.info(f"FLAG_REGEX: {flag_regex}")
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
        logging.error("extract_tokens has invalid parameters")
        return 0

    match = re.search(r"tokens used\s*([\d,]+)", clean, flags=re.IGNORECASE)
    try:
        if match:
            return int(match.group(1).replace(",", ""))
    finally:
        logging.error("Failed to extract_tokens")
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
        (logs_root / "thinking.log").write_text(extract_thinking(output), encoding="utf-8")
    except OSError as exc:
        logging.warning("failed to write logs under %s: %s", task.name, exc)


def run_codex_with_logs(
    command: list[str],
    task: Task,
) -> str:
    logs_root = CODEX_DIR / task.name
    logs_root.mkdir(parents=True, exist_ok=True)

    output_log = logs_root / "thinking.log"
    completed_normally = False

    timeout = None if CODEX_TIMEOUT <= 0 else CODEX_TIMEOUT
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
            proc.wait(timeout=timeout)
            completed_normally = True
        except subprocess.TimeoutExpired:
            completed_normally = False
        finally:
            if task.id is not None:
                RUNNING_CODEX.pop(task.id, None)

    output = output_log.read_text(encoding="utf-8", errors="ignore")
    if completed_normally:
        tokens = extract_tokens(output=output)
        if tokens is not None:
            print(f"tokens used: {tokens}", flush=True)
    return output


def run_codex(
    task: Task,
    prompt: str,
) -> str:
    task_dir = TASKS_DIR / task.name

    logging.info("running codex for %s", task.name)
    command = DEFAULT_CODEX_COMMAND + [prompt]
    return run_codex_with_logs(command, task)


def local_attachment_names(task: Task) -> list[str]:
    task_dir = TASKS_DIR / task.name
    return sorted(
        p.name
        for p in task_dir.iterdir()
        if p.is_file() and p.name != "metadata.json"
    )


def build_codex_prompt(task: Task) -> str:
    context_path = TASKS_DIR / task.name / "codex_context.txt"
    if context_path.exists():
        context = context_path.read_text(encoding="utf-8", errors="replace").strip()
    else:
        context = ""

    parts = [
        "Solve this Jeopardy CTF challenge inside the current directory.",
        f"Flag format (regex): {FLAG_FORMAT}",
        "Do not install new tools or use sudo.",
    ]
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
    if session is None:
        logging.warning("could not login to CTFd; running without submissions", CTFD_URL)
    elif task.id in ctfd.solved_ids_cached(session):
        db.insert_entry(task.id, "solved", error="solved by a human")
        logging.info("skipping %s (%s): solved while queued", task.name, task.id)
        return 0

    prompt = build_codex_prompt(task)
    db.insert_entry(task.id, "running")
    last_output = ""

    for attempt in range(1, MAX_CODEX_ATTEMPTS + 1):
        if STOP_EVENT.is_set():
            return
        try:
            output = run_codex(task, prompt)
        except FileNotFoundError:
            return 1
        last_output = output

        persist_task_logs(task, output)
        flags = [m.group(0) for m in FLAG_RE.finditer(output)]

        validated = False
        for flag in reversed(flags):
            if submit_flag(session, tasl.id, flag):
                logging.info(f"successfull flag found for {task.name}: {flag}")
                db.insert_entry(task.id, "done", flag=flag, tokens=extract_tokens(output=output))
                return 0
            else:
                logging.info(f"incorrect flag found for {task.name}: {candidate}")

        prompt = (
            prompt
            + "\n\nThis is incorrect flag."
            " Keep working and print ONLY the correct final flag."
        )

    logging.warning(f"max attempts reached for {task.name}")
    db.insert_entry(task.id, "failed", tokens=extract_tokens(output=last_output), error="max attempts reached")
    return 0


def run_tasks() -> int:
    if not TASKS_DIR.exists():
        logging.error(f"task directory does not exist: {TASKS_DIR}")
        return 1

    pending: list[Task] = db.read_entries(DB_PATH)
    if not pending:
        logging.error("no tasks in the database")
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
        print()
        for fut, task in future_to_task.items():
            db.insert_entry(task.id, "failed", tokens=extract_tokens(task=task), error="interrupted")
            fut.cancel()
        return
    finally:
        STOP_EVENT.set()
        executor.shutdown(wait=True)
        logging.info("All done!")


def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s", force=True)
    db.move_status(DB_PATH, "running", "failed")
    print("Starting Codex worker …")
    run_tasks()


if __name__ == "__main__":
    main()

