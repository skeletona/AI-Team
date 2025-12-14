#!/usr/bin/env python3
"""
Run `codex` for each downloaded task, capture flags, and optionally submit them to the
same CTFd instance that `autonomous_ctfd.py` targets.

The runner loads credentials from `.env` (via `dotenv`) and follows `FLAG_FORMAT` for
matching. Flags are always sought in Codex's combined output, but submissions only
happen in normal mode;
"""

from __future__ import annotations

import json
import logging
import os
import random
import re
import shlex
import shutil
import signal
import subprocess
import sys
import threading
import traceback
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence
import concurrent.futures
from time import time
from dotenv import load_dotenv
from ctfd import *
import stats_db

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
OVERRIDES_PATH = Path(os.environ.get("OVERRIDES_PATH", "task_overrides.json"))
DEFAULT_CODEX_COMMAND = ["codex", "exec", "-s", "danger-full-access", "-m", "gpt-5.1-codex-mini", "--skip-git-repo-check"]
RUNNING_CODEX: dict[int, subprocess.Popen] = {}
STOP_EVENT = threading.Event()


def kill_all_codex():
    for task_id, proc in list(RUNNING_CODEX.items()):
        proc.kill()
        RUNNING_CODEX.pop(task_id, None)


def summarize_description(description: str, limit: int = 120) -> str:
    normalized = " ".join(description.replace("\n", " ").split())
    if len(normalized) <= limit:
        return normalized
    return normalized[: limit - 3].rstrip() + "..."


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


def persist_task_logs(task_id: int, task_info: dict[int, dict[str, Any]], output: str) -> None:
    task_name = task_info["task"]
    try:
        logs_root = THINKING_LOGS_DIR / task_name
        logs_root.mkdir(parents=True, exist_ok=True)
        (logs_root / "thinking.log").write_text(extract_thinking(output), encoding="utf-8")
    except OSError as exc:
        logging.warning("failed to write logs under %s: %s", task_name, exc)


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


def get_codex_command(prompt: str) -> list[str]:
    """
    Build the Codex command, appending the prompt unless a placeholder is present.
    If CODEX_COMMAND contains "{prompt}" or "{}", it will be substituted; otherwise,
    the prompt is appended as the final argument.
    """
    command_spec = os.environ.get("CODEX_COMMAND")
    if command_spec:
        parts = shlex.split(command_spec)
        formatted = [
            part.replace("{prompt}", prompt).replace("{}", prompt) for part in parts
        ]
        if formatted != parts:
            return formatted
        return parts + [prompt]
    return [*DEFAULT_CODEX_COMMAND, prompt]


def prepare_codex_environment(home_override: Optional[Path] = None) -> Mapping[str, str]:
    env = dict(os.environ)
    desired_home = home_override or Path.cwd()
    env["HOME"] = str(desired_home)
    target_state = desired_home / ".codex"
    if target_state.exists():
        return env
    source_state = Path.home() / ".codex"
    try:
        if source_state.exists():
            shutil.copytree(source_state, target_state)
        else:
            target_state.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        logging.warning("failed to prepare codex state in %s: %s", target_state, exc)
        target_state.mkdir(parents=True, exist_ok=True)
    return env


def run_codex_with_logs(
    command: list[str],
    task_dir: Path,
    env: Mapping[str, str],
    challenge_id: Optional[int] = None,
) -> str:
    """
    Запускает Codex, пишет stdout/stderr в thinking.log и выводит информацию
    о токенах только после естественного завершения.
    """
    logs_root = THINKING_LOGS_DIR / task_dir.name
    logs_root.mkdir(parents=True, exist_ok=True)

    output_log = logs_root / "thinking.log"
    completed_normally = False

    timeout = None if CODEX_TIMEOUT <= 0 else CODEX_TIMEOUT
    with output_log.open("wb") as fh:
        proc = subprocess.Popen(
            command,
            cwd=task_dir,
            stdout=fh,
            stderr=subprocess.STDOUT,
            env=env,
        )
        if challenge_id is not None:
            RUNNING_CODEX[challenge_id] = proc
        try:
            proc.wait(timeout=timeout)
            completed_normally = True
        except subprocess.TimeoutExpired:
            completed_normally = False
        finally:
            if challenge_id is not None:
                RUNNING_CODEX.pop(challenge_id, None)

    output = output_log.read_text(encoding="utf-8", errors="ignore")
    if completed_normally:
        tokens = extract_tokens_used(output)
        if tokens is not None:
            print(f"tokens used: {tokens}", flush=True)
    return output

def run_codex(
    task_id: int,
    task_info: dict[int, dict[str, Any]],
    prompt: str,
    env: Mapping[str, str],
) -> str:
    task_name = task_info["task"]
    task_dir = TASKS_ROOT / task_name

    command = get_codex_command(prompt)
    if not command:
        raise ValueError("CODEX_COMMAND must not be empty")

    # Находим реальный исполняемый бинарник
    executable = shutil.which(command[0])
    if not executable:
        logging.error("Codex binary %s not found on PATH", command[0])
        raise FileNotFoundError(command[0])
    command[0] = executable

    logging.info("running codex for %s", task_name)
    return run_codex_with_logs(command, task_dir, env, challenge_id=task_id)


def local_attachment_names(task_id: int, task_info: dict[int, dict[str, Any]]) -> list[str]:
    task_dir = task_info[task_id]["dir"]
    return sorted(
        p.name
        for p in task_dir.iterdir()
        if p.is_file() and p.name != "metadata.json"
    )


def build_codex_prompt(task_id: int, task_info: dict[str, Any]) -> str:
    task_dir = TASKS_ROOT / task_info["task"]
    context_path = task_dir / "codex_context.txt"
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
            cid = entry["challenge_id"]
            stats_db.insert_entry(cid, "failed", error=reason)


def process_task(task_id: int, task_info: dict[str, Any]) -> int:
    task_name = task_info["task"]

    session = create_session()
    if session is None:
        logging.warning("could not login to CTFd; running without submissions", CTFD_URL)
    elif task_id in solved_ids_cached(session):
        stats_db.insert_entry(challenge_id, "solved", error="solved by a human")
        logging.info("skipping %s (%s): solved while queued", task_name, challenge_id)
        return 0

    prompt = build_codex_prompt(task_id, task_info)
    stats_db.insert_entry(task_id, "running")
    last_output = ""

    for attempt in range(1, MAX_CODEX_ATTEMPTS + 1):
        if STOP_EVENT.is_set():
            return
        try:
            codex_env = prepare_codex_environment()
            output = run_codex(
                task_id,
                task_info,
                prompt=prompt,
                env=codex_env,
            )
        except FileNotFoundError:
            return 1
        last_output = output

        persist_task_logs(task_id, task_info, output)
        candidates = [m.group(0) for m in flag_regex.finditer(output)]
        flag = candidates[-1] if candidates else None
        stats_db.insert_entry(task_id, "done", flag=flag, tokens_used=extract_tokens_used(output))

        if not candidates:
            prompt = (
                prompt
                + "\n\nNo valid flag was found in the previous output. Continue solving and print ONLY the final flag."
            )
            continue

        validated = False
        for candidate in reversed(candidates):
            if submit_flag(session, challenge_id, candidate):
                logging.info(f"successfull flag for {task_name}: {candidate}")
                return 0
            else:
                logging.info(f"incorrect flag for {task_name}: {candidate}")

        prompt = (
            prompt
            + "\n\nThis is incorrect flag."
            " Keep working and print ONLY the correct final flag."
        )

    logging.warning(f"max attempts reached for {task_name}")
    stats_db.insert_entry(task_id, "stopped", tokens_used=extract_tokens_used(last_output), error="max attempts reached")
    return 0


def run_tasks() -> int:
    if not TASKS_ROOT.exists():
        logging.error(f"task directory does not exist: {TASKS_ROOT}")
        return 1

    db_entries = stats_db.read_entries(DB_PATH)
    if not db_entries:
        logging.error("no tasks found in the database")
        return 0

    tasks: dict[int, dict[str, Any]] = {}
    for entry in db_entries:
        challenge_id = entry["challenge_id"]
        task_name = entry["task"]
        
        task_dir = TASKS_ROOT / task_name
        if not task_dir.is_dir():
            logging.warning(f"task directory not found for task '{task_name}'")
            continue
        tasks[challenge_id] = entry

    codex_env = prepare_codex_environment()

    executor = concurrent.futures.ThreadPoolExecutor(max_workers=MAX_CODEX_WORKERS)
    pending = list(tasks.items())
    random.shuffle(pending)
    active = set()

    try:
        task = pending.pop(0)
        fut = executor.submit(process_task, task[0], task[1])
        active.add(fut)

        while active:
            while pending and len(active) < MAX_CODEX_WORKERS:
                task = pending.pop(0)
                fut = executor.submit(process_task, task[0], task[1])
                active.add(fut)

            done, active = concurrent.futures.wait(
                active, return_when=concurrent.futures.FIRST_COMPLETED
            )

            for f in done:
                f.result()

    except KeyboardInterrupt:
        logging.info("killing all processes")
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
    global flag_regex
    flag_regex = build_flag_regex()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s", force=True)
    
    stats_db.delete_status(DB_PATH, "running")
    run_tasks()
