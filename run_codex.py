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
import time
import threading
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from time import time
from dotenv import load_dotenv
from ctfd import *
import stats_db

load_dotenv()


def _parse_integer_env(value: Optional[str], default: int, name: str) -> int:
    if not value:
        return default
    try:
        return int(value)
    except ValueError:
        logging.warning("%s=%r is not an integer; falling back to %s", name, value, default)
        return default


def _terminate_process_tree(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    if hasattr(os, "killpg"):
        try:
            pgid = os.getpgid(proc.pid)
        except OSError:
            pass
        else:
            try:
                os.killpg(pgid, signal.SIGKILL)
            except OSError:
                pass
            return
    try:
        proc.kill()
    except OSError:
        pass


CODEX_TIMEOUT = _parse_integer_env(os.environ.get("CODEX_TIMEOUT"), 0, "CODEX_TIMEOUT") * 60
TASKS_ROOT = Path(os.environ.get("TASKS_ROOT", "tasks"))
FLAG_FORMAT = os.environ.get("FLAG_FORMAT")
FLAG_REGEX = os.environ.get("FLAG_REGEX")
DB_PATH = Path(os.environ.get("DB_PATH", "codex_stats.db"))
THINKING_LOGS_DIR = Path(os.environ.get("THINKING_LOGS_DIR", "thinking_logs"))
MAX_CODEX_WORKERS = os.environ.get("MAX_CODEX_WORKERS")
STATS_LOCK = threading.Lock()
RUNNING_LOCK = threading.Lock()
RUNNING_TASKS: dict[int, Path] = {}
RUNNING_PROCS: dict[int, subprocess.Popen] = {}
RUNNING_PROCS_LOCK = threading.Lock()
SOLVED_LOCK = threading.Lock()
_SOLVED_CACHE: dict[str, object] = {"ts": 0.0, "ids": set()}
SOLVED_CACHE_SECONDS = int(os.environ.get("SOLVED_CACHE_SECONDS", "30"))
OVERRIDES_PATH = Path(os.environ.get("OVERRIDES_PATH", "task_overrides.json"))
DEFAULT_CODEX_COMMAND = ["codex", "exec", "-s", "danger-full-access", "-m", "gpt-5.1-codex-mini", "--skip-git-repo-check"]


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


def persist_task_logs(task_dir: Path, output: str) -> None:
    try:
        logs_root = THINKING_LOGS_DIR / task_dir.name
        logs_root.mkdir(parents=True, exist_ok=True)
        (logs_root / "thinking.log").write_text(extract_thinking(output), encoding="utf-8")
    except OSError as exc:
        logging.warning("failed to write logs under %s: %s", task_dir, exc)


def build_flag_regex() -> re.Pattern[str]:
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
        raise ValueError(f"FLAG_FORMAT {spec!r} is not a valid regex") from exc


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
    """
    Codex needs a writable HOME for session files. Mirror the default ~/.codex into
    the workspace (or supplied path) so the sandbox allows writes.
    """
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


def start_codex_to_file(
    command: list[str],
    task_dir: Path,
    env: Mapping[str, str],
    output_log: Path,
) -> subprocess.Popen:
    output_log.parent.mkdir(parents=True, exist_ok=True)
    fh = output_log.open("ab", buffering=0)

    proc = subprocess.Popen(
        command,
        cwd=task_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env,
    )

    proc._log_fh = fh  # чтобы закрыть потом
    return proc


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
            start_new_session=True,
            env=env,
        )
        if challenge_id is not None:
            with RUNNING_PROCS_LOCK:
                RUNNING_PROCS[challenge_id] = proc
        try:
            proc.wait(timeout=timeout)
            completed_normally = True
        except subprocess.TimeoutExpired:
            _terminate_process_tree(proc)
            proc.wait()
        except KeyboardInterrupt:
            _terminate_process_tree(proc)
            proc.wait()
            raise
        finally:
            if challenge_id is not None:
                with RUNNING_PROCS_LOCK:
                    RUNNING_PROCS.pop(challenge_id, None)

    output = output_log.read_text(encoding="utf-8", errors="ignore")
    if completed_normally:
        tokens = extract_tokens_used(output)
        if tokens is not None:
            print(f"tokens used: {tokens}", flush=True)
    return output


def run_codex(
    task_dir: Path,
    prompt: str,
    env: Mapping[str, str],
    challenge_id: Optional[int] = None,
) -> str:
    command = get_codex_command(prompt)
    if not command:
        raise ValueError("CODEX_COMMAND must not be empty")

    # Находим реальный исполняемый бинарник
    executable = shutil.which(command[0])
    if not executable:
        logging.error("Codex binary %s not found on PATH", command[0])
        raise FileNotFoundError(command[0])
    command[0] = executable

    logging.info("running codex for %s", task_dir.name)

    return run_codex_with_logs(command, task_dir, env, challenge_id=challenge_id)


def local_attachment_names(task_dir: Path) -> list[str]:
    return sorted(
        p.name
        for p in task_dir.iterdir()
        if p.is_file() and p.name != "metadata.json"
    )


def build_codex_prompt(
    task_dir: Path,
    metadata: Mapping[str, Any],
    description: str,
    attachments: Sequence[str],
) -> str:
    context_path = task_dir / "codex_context.txt"
    context = ""
    try:
        if context_path.exists():
            context = context_path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        context = ""
    attachment_line = ", ".join(attachments) if attachments else "none"
    parts = [
        "Solve this Jeopardy CTF challenge inside the current directory.",
        f"Task directory: {task_dir.name}",
        f"Name: {metadata.get('name', '<unknown>')} ({metadata.get('category', 'unknown')})",
        f"Description: {description or '<no description provided>'}",
        f"Attachments present locally or in metadata: {attachment_line}",
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


def append_stats(
    task_dir: Path,
    challenge_id: int,
    flag: Optional[str],
    output: str,
    status: str = "done",
    error: Optional[str] = None,
) -> None:
    entry = {
        "task": task_dir.name,
        "challenge_id": challenge_id,
        "flag": flag,
        "tokens_used": extract_tokens_used(output),
        "status": status,
        "error": error,
        "timestamp": time(),
    }
    with STATS_LOCK:
        try:
            stats_db.insert_entry(DB_PATH, entry)
        except Exception as exc:
            logging.warning("failed to write stats to %s: %s", DB_PATH, exc)


def mark_all_running_failed(reason: str = "interrupted") -> None:
    entries = stats_db.read_entries(DB_PATH)
    for entry in entries:
        if entry.get("status") != "running":
            continue
        cid = entry.get("challenge_id")
        task_name = entry.get("task")
        if not isinstance(cid, int) or not task_name:
            continue
        task_dir = TASKS_ROOT / task_name
        append_stats(task_dir, cid, None, "", status="failed", error=reason)


def run_tasks() -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    try:
        stats_db.delete_status(DB_PATH, "running")
    except Exception:
        logging.debug("could not clear previous running entries")
    stats_db.dedupe_stats(DB_PATH)
    # Keep previous stats; the dashboard and runner use this file as an append-only log.
    if not TASKS_ROOT.exists():
        logging.error("task directory %s does not exist", TASKS_ROOT)
        return 1
    if FLAG_REGEX:
        try:
            flag_regex = re.compile(FLAG_REGEX)
        except re.error as exc:
            raise ValueError(f"FLAG_REGEX {FLAG_REGEX!r} is not a valid regex") from exc
    else:
        flag_regex = build_flag_regex()
    task_dirs = sorted(p for p in TASKS_ROOT.iterdir() if p.is_dir())
    if not task_dirs:
        logging.warning("no tasks found under %s", TASKS_ROOT)
        return 0
    codex_env = prepare_codex_environment()
    errors = 0
    max_workers: Optional[int] = None
    if MAX_CODEX_WORKERS:
        try:
            cap = int(MAX_CODEX_WORKERS)
            if cap > 0:
                max_workers = cap
                logging.info("MAX_CODEX_WORKERS: %s", cap)
            else:
                logging.warning("ignoring invalid MAX_CODEX_WORKERS=%s", MAX_CODEX_WORKERS)
        except ValueError:
            logging.warning("ignoring invalid MAX_CODEX_WORKERS=%r", MAX_CODEX_WORKERS)

    stats: dict[int, dict[str, object]] = {}
    for entry in stats_db.read_entries(DB_PATH):
        cid = entry.get("challenge_id")
        status = str(entry.get("status") or "")
        stats[cid] = entry

    # Also skip tasks already solved on CTFd (useful after restarts or stats resets).
    solved_session = create_session()
    if solved_session is not None:
        solved_ids = fetch_solved_challenge_ids(solved_session)
        for id in solved_ids:
            task = fetch_challenge_detail(solved_session, id)
            entry = {
                "task": task,
                "challenge_id": challenge_id,
                "flag": "",
                "tokens_used": 0,
                "status": "solved",
                "error": "",
                "timestamp": time(),
            }
            stats_db.insert_entry(DB_PATH, entry)
            logging.info(f"CTFd reports solved challenge: {task}")

    task_dirs_to_run: list[Path] = []
    # Seed queued entries for tasks we will run, and skip those already completed.
    for task_dir in task_dirs:
        metadata_path = task_dir / "metadata.json"
        if not metadata_path.exists():
            continue
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        challenge_id = metadata.get("id")
        if not isinstance(challenge_id, int):
            continue
        entry = stats.get(challenge_id)
        # Allow reruns even for failed/stopped; only skip if explicitly solved/hidden/ or completed_ids.
        task_dirs_to_run.append(task_dir)

    seed = os.environ.get("TASK_SHUFFLE_SEED")
    if task_dirs_to_run:
        if seed is not None and seed != "":
            try:
                random.Random(int(seed)).shuffle(task_dirs_to_run)
            except ValueError:
                random.Random(seed).shuffle(task_dirs_to_run)
        else:
            random.shuffle(task_dirs_to_run)

    def process_task(task_dir: Path) -> int:
        metadata_path = task_dir / "metadata.json"
        if not metadata_path.exists():
            logging.warning("skipping %s (missing metadata.json)", task_dir)
            return 0
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            logging.warning("invalid metadata.json in %s", task_dir)
            return 0
        challenge_id = metadata.get("id")
        if challenge_id is None:
            logging.warning("skipping %s (no id in metadata)", task_dir)
            return 0

        session = create_session()
        if session is None:
            logging.warning(
                "could not authenticate with %s; running without submissions", CTFD_URL
            )
        if session is not None:
            try:
                if int(challenge_id) in solved_ids_cached(session):
                    append_stats(task_dir, int(challenge_id), None, "", status="solved", error="solved by a human")
                    logging.info("skipping %s (%s): already solved on CTFd", task_dir.name, challenge_id)
                    return 0
            except Exception:
                pass

        detail: Mapping[str, Any] = {}
        if session:
            try:
                detail = fetch_challenge_detail(session, challenge_id)
            except Exception as exc:
                logging.warning("failed to fetch detail for %s: %s", challenge_id, exc)
                detail = {}
        description = (
            detail.get("description")
            or metadata.get("description")
            or ""
        )
        detail_attachments: list[str] = []
        for item in (detail.get("files") or []):
            if isinstance(item, Mapping):
                name = item.get("name")
                if name:
                    detail_attachments.append(str(name))
            elif isinstance(item, str):
                detail_attachments.append(item.rsplit("/", 1)[-1] or item)
        local_attachments = local_attachment_names(task_dir)
        attachments = detail_attachments or local_attachments
        prompt = build_codex_prompt(task_dir, metadata, description, attachments)
        max_attempts = int(os.environ.get("MAX_CODEX_ATTEMPTS", "3"))
        last_output = ""
        for attempt in range(1, max_attempts + 1):
            if session is not None:
                try:
                    if int(challenge_id) in solved_ids_cached(session):
                        append_stats(task_dir, int(challenge_id), None, "", status="solved", error="solved by a human")
                        logging.info("skipping %s (%s): solved while queued", task_dir.name, challenge_id)
                        return 0
                except Exception:
                    pass
            with RUNNING_LOCK:
                if isinstance(challenge_id, int):
                    RUNNING_TASKS[challenge_id] = task_dir
            append_stats(task_dir, challenge_id, None, "", status="running")
            try:
                output = run_codex(
                    task_dir,
                    prompt=prompt,
                    env=codex_env,
                    challenge_id=int(challenge_id) if isinstance(challenge_id, int) else None,
                )
            except FileNotFoundError:
                return 1
            last_output = output
            persist_task_logs(task_dir, output)

            candidates = [m.group(0) for m in flag_regex.finditer(output)]
            flag = candidates[-1] if candidates else None
            append_stats(task_dir, challenge_id, flag, output, status="done")
            with RUNNING_LOCK:
                RUNNING_TASKS.pop(int(challenge_id), None)

            if not candidates:
                prompt = (
                    prompt
                    + "\n\nNo valid flag was found in the previous output. Continue solving and print ONLY the final flag."
                )
                continue

            if session is None:
                logging.info("skipping submission/validation for %s (dry-run/no-submit)", task_dir.name)
                return 0

            validated = False
            for candidate in reversed(candidates):
                if submit_flag(session, challenge_id, candidate):
                    logging.info("flag validated/submitted successfully for %s", task_dir.name)
                    validated = True
                    break
            if validated:
                return 0

            logging.info(
                "candidate flag(s) incorrect for %s (attempt %s/%s); retrying",
                task_dir.name,
                attempt,
                max_attempts,
            )
            prompt = (
                prompt
                + "\n\nThe previous output contained candidate flags, but CTFd marked them incorrect."
                " Keep working and print ONLY the correct final flag."
            )

        logging.warning("max attempts reached for %s; last run did not validate", task_dir.name)
        if last_output:
            print("no valid flag", flush=True)
        append_stats(task_dir, challenge_id, None, last_output, status="stopped", error="max attempts reached")
        with RUNNING_LOCK:
            RUNNING_TASKS.pop(int(challenge_id), None)
        return 0


def main() -> int:
    return run_tasks()


if __name__ == "__main__":
    raise SystemExit(main())
