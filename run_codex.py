#!/usr/bin/env python3
"""
Run `codex` for each downloaded task, capture flags, and optionally submit them to the
same CTFd instance that `autonomous_ctfd.py` targets.

The runner loads credentials from `.env` (via `dotenv`) and follows `FLAG_FORMAT` for
matching. Flags are always sought in Codex's combined output, but submissions only
happen in normal mode; `--dry-run` or `--no-submit` let you validate the workflow
without contacting the remote server. Use `--timeout` to override the 10 minute
per-task Codex timeout.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import pty
import random
import re
import select
import shlex
import shutil
import subprocess
import sys
import time
import threading
import signal
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from time import time
import requests
from dotenv import load_dotenv

import stats_db

load_dotenv()

CODEX_TIMEOUT = os.environ.get("CODEX_TIMEOUT", 10)
CTFD_URL = os.environ.get("CTFD_URL").rstrip("/")
TEAM_NAME = os.environ.get("AI_TEAM_NAME")
TEAM_EMAIL = os.environ.get("AI_TEAM_EMAIL")
TEAM_PASSWORD = os.environ.get("AI_TEAM_PASSWORD")
TASKS_ROOT = Path(os.environ.get("TASKS_ROOT", "tasks"))
FLAG_FORMAT = os.environ.get("FLAG_FORMAT")
FLAG_REGEX = os.environ.get("FLAG_REGEX")
DB_PATH = Path(os.environ.get("DB_PATH", "codex_stats.db"))
THINKING_LOGS_DIR = Path(os.environ.get("THINKING_LOGS_DIR", "thinking_logs"))
MAX_CODEX_WORKERS = os.environ.get("MAX_CODEX_WORKERS")
STATS_LOCK = threading.Lock()
RUNNING_LOCK = threading.Lock()
RUNNING_TASKS: dict[int, Path] = {}
SOLVED_LOCK = threading.Lock()
_SOLVED_CACHE: dict[str, object] = {"ts": 0.0, "ids": set()}
SOLVED_CACHE_SECONDS = int(os.environ.get("SOLVED_CACHE_SECONDS", "30"))
OVERRIDES_PATH = Path(os.environ.get("OVERRIDES_PATH", "task_overrides.json"))
STOP_FLAGS_DIR = Path(os.environ.get("STOP_FLAGS_DIR", "thinking_logs"))
DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko)"
        " Chrome/120 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}
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


def extract_thinking(output: str, limit: int = 500) -> str:
    clean = strip_ansi(output)
    lower = clean.lower()
    idx = lower.find("thinking")
    if idx == -1:
        return clean[:limit]
    snippet = clean[idx:].splitlines()
    if snippet:
        snippet = snippet[1:]  # drop the 'thinking' label line
    joined = "\n".join(snippet).strip()
    if not joined:
        return clean[:limit]
    return joined[:limit]


def extract_thinking_full(output: str) -> str:
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
        (logs_root / "codex_output.log").write_text(strip_ansi(output), encoding="utf-8")
        (logs_root / "thinking.log").write_text(extract_thinking_full(output), encoding="utf-8")
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


def fetch_csrf_token(session: requests.Session, path: str) -> str:
    url = urljoin(CTFD_URL, path)
    resp = session.get(url, headers=DEFAULT_HEADERS)
    resp.raise_for_status()
    html = resp.text
    patterns = [
        r'name="nonce"[^>]*value="([^"]+)"',
        r'name="csrf_token"[^>]*value="([^"]+)"',
        r"'csrfNonce':\s*\"([0-9a-f]+)\"",
    ]
    for pattern in patterns:
        match = re.search(pattern, html)
        if match:
            return match.group(1)
    raise RuntimeError(f"CSRF token not found on {url}")


def is_logged_in(session: requests.Session) -> bool:
    resp = session.get(
        urljoin(CTFD_URL, "/api/v1/users/me"),
        headers={"Accept": "application/json", **DEFAULT_HEADERS},
        allow_redirects=False,
    )
    if resp.status_code != 200:
        return False
    try:
        payload = resp.json()
    except ValueError:
        return False
    return bool(payload.get("data"))


def login(session: requests.Session) -> bool:
    if not TEAM_EMAIL or not TEAM_PASSWORD:
        logging.error("AI_TEAM_EMAIL/AI_TEAM_PASSWORD must be set for submissions")
        return False
    try:
        token = fetch_csrf_token(session, "/login")
    except Exception as exc:
        logging.warning("login CSRF fetch failed: %s", exc)
        return False
    payload = {
        "name": TEAM_NAME,
        "email": TEAM_EMAIL,
        "password": TEAM_PASSWORD,
        "nonce": token,
    }
    resp = session.post(urljoin(CTFD_URL, "/login"), data=payload, headers=DEFAULT_HEADERS)
    body = resp.text.lower()
    if resp.status_code == 403 or "cf-turnstile" in body:
        logging.error("login blocked by Turnstile/firewall")
        return False
    if resp.status_code >= 400 or "invalid username or password" in body:
        logging.error("login failed (status %s)", resp.status_code)
        return False
    return is_logged_in(session)


def create_session() -> Optional[requests.Session]:
    session = requests.Session()
    session.headers.update(DEFAULT_HEADERS)
    if not login(session):
        return None
    return session


def fetch_challenge_detail(session: requests.Session, challenge_id: int) -> Mapping[str, Any]:
    resp = session.get(
        urljoin(CTFD_URL, f"/api/v1/challenges/{challenge_id}"),
        headers={"Accept": "application/json", **DEFAULT_HEADERS},
    )
    resp.raise_for_status()
    payload = resp.json()
    return payload.get("data") if isinstance(payload, dict) else {}


def fetch_solved_challenge_ids(session: requests.Session) -> set[int]:
    solved: set[int] = set()
    for path in ("/api/v1/teams/me/solves", "/api/v1/users/me/solves"):
        try:
            resp = session.get(
                urljoin(CTFD_URL, path),
                headers={"Accept": "application/json", **DEFAULT_HEADERS},
            )
        except requests.RequestException:
            continue
        if resp.status_code != 200:
            continue
        try:
            payload = resp.json()
        except ValueError:
            continue
        entries = payload.get("data") if isinstance(payload, dict) else []
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, Mapping):
                continue
            chall = entry.get("challenge") if isinstance(entry.get("challenge"), Mapping) else entry
            if not isinstance(chall, Mapping):
                continue
            cid = chall.get("id")
            try:
                solved.add(int(cid))
            except (TypeError, ValueError):
                continue
        if solved:
            break
    return solved


def solved_ids_cached(session: requests.Session) -> set[int]:
    now = time()
    with SOLVED_LOCK:
        cached_ts = float(_SOLVED_CACHE.get("ts") or 0.0)
        cached_ids = _SOLVED_CACHE.get("ids")
        if (now - cached_ts) <= SOLVED_CACHE_SECONDS and isinstance(cached_ids, set):
            return set(cached_ids)
    solved = fetch_solved_challenge_ids(session)
    with SOLVED_LOCK:
        _SOLVED_CACHE["ts"] = now
        _SOLVED_CACHE["ids"] = solved
    return solved


def submit_flag(session: requests.Session, challenge_id: int, flag: str) -> bool:
    endpoint = urljoin(CTFD_URL, "/api/v1/challenges/attempt")
    payload = {"submission": flag, "challenge_id": challenge_id}
    csrf_token = session.cookies.get("csrf_token")
    if not csrf_token:
        try:
            csrf_token = fetch_csrf_token(session, "/challenges")
        except Exception as exc:
            logging.warning("could not obtain CSRF token for submission: %s", exc)
    headers = {"X-Requested-With": "XMLHttpRequest", **DEFAULT_HEADERS}
    if csrf_token:
        headers["CSRF-Token"] = csrf_token
    headers["Referer"] = urljoin(CTFD_URL, "/challenges")
    resp = session.post(
        endpoint,
        json=payload,
        headers=headers,
    )
    if resp.status_code not in (200, 201):
        logging.warning("flag submission returned HTTP %s", resp.status_code)
        print(f"submission failed: HTTP {resp.status_code}", flush=True)
        return False
    try:
        payload = resp.json()
    except ValueError:
        print("submission failed: invalid JSON response", flush=True)
        return False
    success, data = payload.get("success"), payload.get("data")
    if success:
        if data.get("status") == "correct":
            logging.info("server accepted flag for challenge %s", challenge_id)
            return True
        else:
            print(f"submission failed: {data.get('message')}", flush=True)
            return False
    else:
        print(f"submission failed: {payload}", flush=True)
        return False


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


def _collect_pty_output(
    proc: subprocess.Popen,
    master_fd: int,
    timeout: int,
    on_chunk=None,
    stop_flag: Optional[Path] = None,
) -> tuple[bytearray, bool, bool]:
    output = bytearray()
    deadline = time() + timeout * 60
    timed_out = False
    stop_requested = False
    while True:
        now = time()
        poll = proc.poll()
        if poll is None:
            remaining = deadline - now
            if remaining <= 0:
                proc.kill()
                timed_out = True
                remaining = 0.1
        else:
            remaining = 0.1
        if stop_flag and stop_flag.exists() and poll is None:
            try:
                proc.terminate()
            except Exception:
                pass
            stop_requested = True
        try:
            ready, _, _ = select.select([master_fd], [], [], max(0.0, remaining))
        except InterruptedError:
            continue
        if ready:
            try:
                chunk = os.read(master_fd, 4096)
            except OSError:
                break
            if chunk:
                output.extend(chunk)
                if on_chunk is not None:
                    try:
                        on_chunk(chunk)
                    except Exception:
                        pass
                continue
            if poll is not None:
                break
        if poll is not None and not ready:
            break
        if timed_out and poll is None:
            continue
    proc.wait()
    return output, timed_out, stop_requested


def run_codex_with_pty(
    command: list[str],
    task_dir: Path,
    timeout: int,
    master_fd: int,
    slave_fd: int,
    env: Mapping[str, str],
) -> str:
    logs_root = THINKING_LOGS_DIR / task_dir.name
    output_log_path = logs_root / "codex_output.raw.log"
    stripped_log_path = logs_root / "codex_output.log"
    thinking_log_path = logs_root / "thinking.log"
    stop_flag_path = STOP_FLAGS_DIR / task_dir.name / "stop.flag"
    try:
        proc = subprocess.Popen(
            command,
            cwd=task_dir,
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            text=False,
            bufsize=0,
            env=env,
        )
    except OSError as exc:
        os.close(master_fd)
        os.close(slave_fd)
        logging.error("failed to start codex: %s", exc)
        raise
    else:
        os.close(slave_fd)
    try:
        logs_root.mkdir(parents=True, exist_ok=True)
        stop_flag_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            stop_flag_path.unlink()
        except FileNotFoundError:
            pass
        line_buffer = ""
        thinking_started = False
        max_thinking_line = int(os.environ.get("MAX_THINKING_LINE_CHARS", "2000"))
        max_thinking_nonprintable = float(os.environ.get("MAX_THINKING_NONPRINTABLE_RATIO", "0.2"))
        with (
            output_log_path.open("wb") as raw_fh,
            stripped_log_path.open("w", encoding="utf-8") as stripped_fh,
            thinking_log_path.open("w", encoding="utf-8") as thinking_fh,
        ):

            def tee(chunk: bytes) -> None:
                nonlocal line_buffer, thinking_started
                raw_fh.write(chunk)
                raw_fh.flush()
                sys.stdout.buffer.write(chunk)
                sys.stdout.buffer.flush()

                text = chunk.decode("utf-8", errors="ignore")
                clean = strip_ansi(text)
                if clean:
                    stripped_fh.write(clean)
                    stripped_fh.flush()

                    line_buffer += clean
                    lines = line_buffer.split("\n")
                    line_buffer = lines.pop()  # keep last partial line
                    for line in lines:
                        if not thinking_started and line.strip().lower() == "thinking":
                            thinking_started = True
                            continue
                        if thinking_started:
                            nonprintable = sum(1 for ch in line if (ord(ch) < 9 or (13 < ord(ch) < 32)))
                            ratio = (nonprintable / max(1, len(line)))
                            if len(line) > max_thinking_line or ratio > max_thinking_nonprintable:
                                thinking_fh.write(
                                    f"[omitted noisy line: {len(line)} chars, nonprintable {ratio:.0%}]\n"
                                )
                            else:
                                thinking_fh.write(line + "\n")
                    if thinking_started:
                        thinking_fh.flush()

            output_bytes, timed_out, stop_requested = _collect_pty_output(
                proc, master_fd, timeout, on_chunk=tee, stop_flag=stop_flag_path
            )
    finally:
        os.close(master_fd)
    output = output_bytes.decode("utf-8", errors="ignore")
    if timed_out:
        logging.warning("codex timed out for %s", task_dir)
    elif proc.returncode != 0:
        logging.warning("codex exited with code %s for %s", proc.returncode, task_dir.name)
    if stop_flag_path.exists():
        stop_flag_path.unlink()
    return output


def run_codex(
    task_dir: Path,
    prompt: str,
    env: Mapping[str, str],
    timeout: int = CODEX_TIMEOUT,
) -> str:
    command = get_codex_command(prompt)
    if not command:
        raise ValueError("CODEX_COMMAND must not be empty")
    executable = shutil.which(command[0])
    if not executable:
        logging.error("codex binary %s not found on PATH", command[0])
        raise FileNotFoundError(command[0])
    command[0] = executable
    display_command = [
        "<prompt>" if part == prompt else part for part in command
    ]
    logging.info(
        "running codex for %s",
        task_dir.name,
    )
    master_fd, slave_fd = pty.openpty()
    return run_codex_with_pty(command, task_dir, timeout, master_fd, slave_fd, env)


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
    ]
    if context:
        parts.extend(
            [
                "",
                "Previous attempts summary (continue from here, do not repeat work):",
                context,
            ]
        )
    parts.extend(
        [
            "If the flag is explicitly encoded in the description, decode/unpack it.",
            "Output the recovered flag plainly so the runner can extract it.",
            "Do not install new tools or use sudo.",
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


def parse_arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Codex on each downloaded CTF task")
    parser.add_argument(
        "--tasks-root",
        type=Path,
        default=None,
        help="directory containing downloaded tasks (falls back to TASKS_ROOT env)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="skip all CTFd requests and only run Codex locally",
    )
    parser.add_argument(
        "--no-submit",
        action="store_true",
        help="run Codex but do not submit any flags (requires login for metadata)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=600.0,
        help="seconds to wait for each Codex invocation",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=max(1, os.cpu_count() or 4),
        help="number of Codex tasks to run in parallel",
    )
    return parser.parse_args(argv)


def run_tasks(
    tasks_root: Path,
    dry_run: bool,
    no_submit: bool,
    timeout: int,
    workers: int,
) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    if dry_run:
        logging.info("running in dry-run mode; no network requests will be made")
    try:
        stats_db.delete_status(DB_PATH, "running")
    except Exception:
        logging.debug("could not clear previous running entries")
    stats_db.dedupe_stats(DB_PATH)
    # Keep previous stats; the dashboard and runner use this file as an append-only log.
    if not tasks_root.exists():
        logging.error("task directory %s does not exist", tasks_root)
        return 1
    flag_regex = build_flag_regex() if not FLAG_REGEX else FLAG_REGEX
    task_dirs = sorted(p for p in tasks_root.iterdir() if p.is_dir())
    if not task_dirs:
        logging.warning("no tasks found under %s", tasks_root)
        return 0
    skip_submission = no_submit or dry_run
    codex_env = prepare_codex_environment()
    errors = 0
    if MAX_CODEX_WORKERS:
        try:
            cap = max(1, int(MAX_CODEX_WORKERS))
            if workers > cap:
                logging.info("MAX_CODEX_WORKERS: %s", cap)
            workers = min(workers, cap)
        except ValueError:
            logging.warning("ignoring invalid MAX_CODEX_WORKERS=%r", MAX_CODEX_WORKERS)

    completed_ids: set[int] = set()
    latest_stats: dict[int, dict[str, object]] = {}
    for entry in stats_db.read_entries(DB_PATH):
        cid = entry.get("challenge_id")
        status = str(entry.get("status") or "")
        if not isinstance(cid, int):
            continue
        prev = latest_stats.get(cid)
        ts = float(entry.get("timestamp") or 0.0)
        if not prev or float(prev.get("timestamp") or 0.0) <= ts:
            latest_stats[cid] = entry
        if status == "done" and entry.get("flag"):
            completed_ids.add(cid)

    # Also skip tasks already solved on CTFd (useful after restarts or stats resets).
    if not dry_run and TEAM_EMAIL and TEAM_PASSWORD:
        solved_session = create_session()
        if solved_session is not None:
            solved_ids = fetch_solved_challenge_ids(solved_session)
            if solved_ids:
                logging.info("CTFd reports %d solved challenge(s); will skip them", len(solved_ids))
                completed_ids.update(solved_ids)

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
        if challenge_id in completed_ids:
            logging.info("skipping %s (%s): already recorded in %s", task_dir.name, challenge_id, DB_PATH.name)
            continue
        latest_entry = latest_stats.get(challenge_id)
        # Allow reruns even for failed/stopped; only skip if explicitly solved/hidden/ or completed_ids.
        task_dirs_to_run.append(task_dir)
        append_stats(task_dir, challenge_id, None, "", status="queued")

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

        session: Optional[requests.Session] = None
        if not dry_run and not skip_submission:
            session = create_session()
            if session is None:
                logging.warning(
                    "could not authenticate with %s; running without submissions", CTFD_URL
                )
        if session is not None:
            try:
                if int(challenge_id) in solved_ids_cached(session):
                    append_stats(task_dir, int(challenge_id), None, "", status="solved", error="already solved by a human!")
                    logging.info("skipping %s (%s): already solved on CTFd", task_dir.name, challenge_id)
                    return 0
            except Exception:
                pass

        detail: Mapping[str, Any] = {}
        if session and not dry_run:
            try:
                detail = fetch_challenge_detail(session, challenge_id)
            except requests.RequestException as exc:
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
                        append_stats(task_dir, int(challenge_id), None, "", status="solved", error="already solved by a human!")
                        logging.info("skipping %s (%s): solved while queued", task_dir.name, challenge_id)
                        return 0
                except Exception:
                    pass
            with RUNNING_LOCK:
                if isinstance(challenge_id, int):
                    RUNNING_TASKS[challenge_id] = task_dir
            append_stats(task_dir, challenge_id, None, "", status="running")
            try:
                output = run_codex(task_dir, prompt=prompt, env=codex_env, timeout=timeout)
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

            if skip_submission or session is None:
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

    try:
        with ThreadPoolExecutor(max_workers=max(1, workers)) as executor:
            futures = {executor.submit(process_task, td): td for td in task_dirs_to_run}
            for future in as_completed(futures):
                try:
                    result = future.result()
                except Exception as exc:  # pragma: no cover - defensive
                    logging.error("task %s crashed: %s", futures[future], exc)
                    td = futures[future]
                    metadata_path = td / "metadata.json"
                    try:
                        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
                        cid = metadata.get("id")
                    except Exception:
                        cid = None
                    if cid is not None:
                        append_stats(td, cid, None, "", status="failed", error=str(exc))
                    errors += 1
                    continue
                errors += int(bool(result))
    except KeyboardInterrupt:
        with RUNNING_LOCK:
            running_now = list(RUNNING_TASKS.items())
        for cid, td in running_now:
            append_stats(td, cid, None, "", status="failed", error="interrupted")
        logging.warning("interrupted; marked %d running task(s) as failed", len(running_now))
        exit(0)
    finally:
        try:
            stats_db.delete_status(DB_PATH, "running")
        except Exception as exc:
            logging.warning("failed to clean running entries: %s", exc)
    return 1 if errors else 0


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_arguments(argv)
    tasks_root = args.tasks_root or TASKS_ROOT
    return run_tasks(
        tasks_root=tasks_root,
        dry_run=args.dry_run,
        no_submit=args.no_submit,
        timeout=args.timeout,
        workers=args.workers,
    )


if __name__ == "__main__":
    raise SystemExit(main())
