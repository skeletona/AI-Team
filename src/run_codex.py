#!/usr/bin/env python3
"""
Run `codex` for each downloaded task, capture flags, and optionally submit them to the
same CTFd instance that `autonomous_ctfd.py` targets.

The runner loads credentials from `.env` (via `dotenv`) and follows `FLAG_FORMAT` for
matching. Flags are always sought in Codex's combined output, but submissions only
happen in normal mode;
"""

from __future__ import annotations

import logging
import os
from random import shuffle
import re
import subprocess
import threading
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence
import concurrent.futures
from time import time
from dotenv import load_dotenv

from ctfd import *
import stats_db
from models import *

load_dotenv()

MAX_CODEX_ATTEMPTS = int(os.environ.get("MAX_CODEX_ATTEMPTS", "3"))
CODEX_TIMEOUT = int(os.environ.get("CODEX_TIMEOUT")) * 60
TASKS_ROOT = Path(os.environ.get("TASKS_ROOT", "tasks"))
FLAG_FORMAT = os.environ.get("FLAG_FORMAT")
FLAG_REGEX = os.environ.get("FLAG_REGEX")
DB_PATH = Path(os.environ.get("DB_PATH", "codex_stats.db"))
THINKING_LOGS_DIR = Path(os.environ.get("THINKING_LOGS_DIR", "thinking_logs"))
MAX_CODEX_WORKERS = int(os.environ.get("MAX_CODEX_WORKERS"))
STATS_LOCK = threading.Lock()
SOLVED_LOCK = threading.Lock()
_SOLVED_CACHE: dict[str, object] = {"ts": 0.0, "ids": set()}
SOLVED_CACHE_SECONDS = int(os.environ.get("SOLVED_CACHE_SECONDS", "30"))
DEFAULT_CODEX_COMMAND = ["codex", "exec", "-s", "danger-full-access", "-m", "gpt-5.1-codex-mini", "--skip-git-repo-check"]
RUNNING_CODEX: dict[int, subprocess.Popen] = {}
STOP_EVENT = threading.Event()


flag_regex: re.Pattern[str]


def run_codex_main():
    global flag_regex
    flag_regex = build_flag_regex()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s", force=True)
    
    stats_db.move_status(DB_PATH, "running", "failed")
    run_tasks()


def kill_all_codex():
    for task_id, proc in list(RUNNING_CODEX.items()):
        proc.kill()
        stats_db.insert_entry(task_id, "interrupted")
        RUNNING_CODEX.pop(task_id, None)


def strip_ansi(text: str) -> str:
    return re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)


def extract_tokens_used(output: str) -> Optional[int]:
    clean = strip_ansi(output)
    match = re.search(r"tokens used\s*([\d,]+)", clean, flags=re.IGNORECASE)
    if not match:
        return None
    try:
        return int(match.group(1).replace(",", ""))
    except ValueError:
        return None


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
        logs_root = THINKING_LOGS_DIR / task.name
        logs_root.mkdir(parents=True, exist_ok=True)
        (logs_root / "thinking.log").write_text(extract_thinking(output), encoding="utf-8")
    except OSError as exc:
        logging.warning("failed to write logs under %s: %s", task.name, exc)


def build_flag_regex() -> re.Pattern[str]:
    if FLAG_REGEX:
        try:
            flag_regex = re.compile(FLAG_REGEX)
        except re.error as exc:
            raise ValueError(f"FLAG_REGEX {FLAG_REGEX!r} is not a valid regex") from exc
    else:
        spec = FLAG_FORMAT
        regex_candidate = spec
        if "{}" in spec:
            escaped_spec = re.escape(spec)
            placeholder = re.escape("{}")
            regex_candidate = escaped_spec.replace(placeholder, r"\{[^}]+\}")
            logging.info(
                "FLAG_REGEX: %s",
                regex_candidate,
            )
        try:
            return re.compile(regex_candidate)
        except re.error as exc:
            raise ValueError(f"FLAG_FORMAT {spec!r} is not a valid format. Example: testCTF{{}}") from exc
    return flag_regex


def run_codex_with_logs(
    command: list[str],
    task: Task,
) -> str:
    logs_root = THINKING_LOGS_DIR / task.name
    logs_root.mkdir(parents=True, exist_ok=True)

    output_log = logs_root / "thinking.log"
    completed_normally = False

    timeout = None if CODEX_TIMEOUT <= 0 else CODEX_TIMEOUT
    with output_log.open("wb") as fh:
        proc = subprocess.Popen(
            command,
            cwd=TASKS_ROOT / task.name,
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
        tokens = extract_tokens_used(output)
        if tokens is not None:
            print(f"tokens used: {tokens}", flush=True)
    return output


def run_codex(
    task: Task,
    prompt: str,
) -> str:
    task_dir = TASKS_ROOT / task.name

    logging.info("running codex for %s", task.name)
    command = DEFAULT_CODEX_COMMAND + [prompt]
    return run_codex_with_logs(command, task)


def local_attachment_names(task: Task) -> list[str]:
    task_dir = TASKS_ROOT / task.name
    return sorted(
        p.name
        for p in task_dir.iterdir()
        if p.is_file() and p.name != "metadata.json"
    )


def build_codex_prompt(task: Task) -> str:
    context_path = TASKS_ROOT / task.name / "codex_context.txt"
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
    entries = stats_db.read_entries(DB_PATH)
    for entry in entries:
        if entry["status"] == "running":
            cid = entry["id"]
            stats_db.insert_entry(cid, "failed", error=reason)


def process_task(task: Task) -> int:
    session = create_session()
    if session is None:
        logging.warning("could not login to CTFd; running without submissions", CTFD_URL)
    elif task.id in solved_ids_cached(session):
        stats_db.insert_entry(task.id, "solved", error="solved by a human")
        logging.info("skipping %s (%s): solved while queued", task.name, task.id)
        return 0

    prompt = build_codex_prompt(task)
    stats_db.insert_entry(task.id, "running")
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
        candidates = [m.group(0) for m in flag_regex.finditer(output)]
        flag = candidates[-1] if candidates else None
        stats_db.insert_entry(task.id, "done", flag=flag, tokens_used=extract_tokens_used(output))

        if not candidates:
            prompt = (
                prompt
                + "\n\nNo valid flag was found in the previous output. Continue solving and print ONLY the final flag."
            )
            continue

        validated = False
        for candidate in reversed(candidates):
            if submit_flag(session, id, candidate):
                logging.info(f"successfull flag for {task.name}: {candidate}")
                return 0
            else:
                logging.info(f"incorrect flag for {task.name}: {candidate}")

        prompt = (
            prompt
            + "\n\nThis is incorrect flag."
            " Keep working and print ONLY the correct final flag."
        )

    logging.warning(f"max attempts reached for {task.name}")
    stats_db.insert_entry(task.id, "stopped", tokens_used=extract_tokens_used(last_output), error="max attempts reached")
    return 0


def run_tasks() -> int:
    if not TASKS_ROOT.exists():
        logging.error(f"task directory does not exist: {TASKS_ROOT}")
        return 1

    db_entries = stats_db.read_entries(DB_PATH)
    if not db_entries:
        logging.error("no tasks found in the database")
        return 0

    tasks: list[Tasks] = []
    for entry in db_entries:
        challenge_id = entry["id"]
        task = Task(**entry)
        
        task_dir = TASKS_ROOT / task.name
        if not task_dir.is_dir():
            logging.warning(f"task directory not found for task '{task.name}'")
            continue
        tasks.append(task)

    executor = concurrent.futures.ThreadPoolExecutor(max_workers=MAX_CODEX_WORKERS)
    pending = tasks
    shuffle(pending)
    active = set()

    pending: list[Task] = list(tasks)
    active: set[concurrent.futures.Future] = set()

    try:
        task = pending.pop(0)
        task_dir = TASKS_ROOT / task.name
        fut = executor.submit(process_task, task)
        active.add(fut)

        while active:
            while pending and len(active) < MAX_CODEX_WORKERS:
                task = pending.pop(0)
                task_dir = TASKS_ROOT / task.name
                fut = executor.submit(process_task, task_dir, task.id)
                active.add(fut)
            done, active = concurrent.futures.wait(
                active, return_when=concurrent.futures.FIRST_COMPLETED
            )
            for f in done:
                f.result()

    except KeyboardInterrupt:
        print()
        logging.info("Killing all processes")
        STOP_EVENT.set()
        kill_all_codex()
        for f in active:
            f.cancel()
        executor.shutdown(wait=False, cancel_futures=True)
        return
    else:
        executor.shutdown(wait=False)
    finally:
        logging.info("All done!")

if __name__ == "__main__":
    run_codex_main()
