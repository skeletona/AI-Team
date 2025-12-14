#!/usr/bin/env python3
"""
Simple stats dashboard for Codex task runs.

Reads entries from STATS_PATH (default: codex_stats.db) and serves a
small HTML page showing recent runs, Codex thinking snippets, attempted flags,
and token usage totals, using Flask.
"""

from __future__ import annotations

import json
import hashlib
import os
import re
import shlex
import subprocess
import time
from datetime import datetime
from html import escape
from pathlib import Path
from typing import List, Mapping, Optional
from urllib.parse import urljoin

from flask import Flask, Response, jsonify, redirect, render_template, render_template_string, url_for, request
from flask_sock import Sock
import requests
from dotenv import load_dotenv

import stats_db

STATS_PATH = Path(os.environ.get("STATS_PATH", "codex_stats.db"))
STATS_TEMPLATE_ENV = os.environ.get("STATS_TEMPLATE")
STATS_TEMPLATE = Path(STATS_TEMPLATE_ENV) if STATS_TEMPLATE_ENV else None
PORT = int(os.environ.get("STATS_PORT", "8000"))
TASKS_ROOT = Path(os.environ.get("TASKS_ROOT", "tasks"))
THINKING_LOGS_DIR = Path(os.environ.get("THINKING_LOGS_DIR", "thinking_logs"))
STALE_RUNNING_SECONDS = int(os.environ.get("STALE_RUNNING_SECONDS", "900"))
RUNNING_LOG_STALE_SECONDS = int(os.environ.get("RUNNING_LOG_STALE_SECONDS", "45"))
SOLVES_CACHE_SECONDS = int(os.environ.get("SOLVES_CACHE_SECONDS", "30"))
CHALLENGES_CACHE_SECONDS = int(os.environ.get("CHALLENGES_CACHE_SECONDS", "60"))
TOKEN_LIMIT_5H = int(os.environ.get("TOKEN_LIMIT_5H", "250000"))
TOKEN_LIMIT_WEEK = int(os.environ.get("TOKEN_LIMIT_WEEK", "1000000"))
CONTEXT_WINDOW_TOKENS = int(os.environ.get("CONTEXT_WINDOW_TOKENS", "272000"))
CONTEXT_WINDOW_USED_FALLBACK = os.environ.get("CONTEXT_WINDOW_USED")
CODEX_BUDGET_COMMAND = os.environ.get("CODEX_BUDGET_COMMAND", "").strip()

load_dotenv()

CTFD_URL = os.environ.get("CTFD_URL", "https://play.nitectf25.live").rstrip("/")
TEAM_NAME = os.environ.get("TEAM_NAME", os.environ.get("AI_TEAM_NAME", "AI-Team"))
TEAM_EMAIL = os.environ.get("AI_TEAM_EMAIL", os.environ.get("EMAIL", os.environ.get("TEAM_EMAIL")))
TEAM_PASSWORD = os.environ.get("AI_TEAM_PASSWORD", os.environ.get("TEAM_PASSWORD"))
DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko)"
        " Chrome/120 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}

_BUDGET_CACHE: dict[str, object] = {"ts": 0.0, "lines": []}
_BUDGET_CACHE_TTL_SECONDS = 15.0
_SOLVES_CACHE: dict[str, object] = {"ts": 0.0, "ids": set()}
_CHALLENGES_CACHE: dict[str, object] = {"ts": 0.0, "by_id": {}}

ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text or "")


def fetch_csrf_token(session: requests.Session, path: str) -> Optional[str]:
    try:
        resp = session.get(urljoin(CTFD_URL, path), headers=DEFAULT_HEADERS, timeout=10)
        resp.raise_for_status()
    except Exception:
        return None
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
    return None


def is_logged_in(session: requests.Session) -> bool:
    try:
        resp = session.get(
            urljoin(CTFD_URL, "/api/v1/users/me"),
            headers={"Accept": "application/json", **DEFAULT_HEADERS},
            allow_redirects=False,
            timeout=10,
        )
    except Exception:
        return False
    if resp.status_code != 200:
        return False
    try:
        payload = resp.json()
    except ValueError:
        return False
    return bool(payload.get("data"))

def login_ctfd(session: requests.Session) -> bool:
    if not TEAM_EMAIL or not TEAM_PASSWORD:
        return False
    nonce = fetch_csrf_token(session, "/login")
    if not nonce:
        return False
    payload = {"name": TEAM_NAME, "email": TEAM_EMAIL, "password": TEAM_PASSWORD, "nonce": nonce}
    try:
        resp = session.post(urljoin(CTFD_URL, "/login"), data=payload, headers=DEFAULT_HEADERS, timeout=15)
    except Exception:
        return False
    body = (resp.text or "").lower()
    if resp.status_code == 403 or "cf-turnstile" in body:
        return False
    return is_logged_in(session)

def fetch_solved_ids_cached(now_ts: float) -> set[int]:
    try:
        cached_ts = float(_SOLVES_CACHE.get("ts") or 0.0)
        cached = _SOLVES_CACHE.get("ids")
        if (now_ts - cached_ts) <= SOLVES_CACHE_SECONDS and isinstance(cached, set):
            return set(cached)
    except Exception:
        pass

    session = requests.Session()
    session.headers.update(DEFAULT_HEADERS)
    if not login_ctfd(session):
        return set()
    solved: set[int] = set()
    for path in ("/api/v1/teams/me/solves", "/api/v1/users/me/solves"):
        try:
            resp = session.get(
                urljoin(CTFD_URL, path),
                headers={"Accept": "application/json", **DEFAULT_HEADERS},
                timeout=15,
            )
        except requests.RequestException:
            continue
        if resp.status_code != 200:
            continue
        try:
            payload = resp.json()
        except ValueError:
            continue
        data = payload.get("data") if isinstance(payload, dict) else []
        if not isinstance(data, list):
            continue
        for entry in data:
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
    _SOLVES_CACHE["ts"] = now_ts
    _SOLVES_CACHE["ids"] = solved
    return solved

def fetch_challenges_cached(now_ts: float) -> dict[int, Mapping[str, object]]:
    try:
        cached_ts = float(_CHALLENGES_CACHE.get("ts") or 0.0)
        cached = _CHALLENGES_CACHE.get("by_id")
        if (now_ts - cached_ts) <= CHALLENGES_CACHE_SECONDS and isinstance(cached, dict):
            return {k: v for k, v in cached.items() if isinstance(k, int)}
    except Exception:
        pass
    try:
        resp = requests.get(
            urljoin(CTFD_URL, "/api/v1/challenges"),
            headers={"Accept": "application/json", **DEFAULT_HEADERS},
            timeout=15,
        )
    except requests.RequestException:
        return {}
    if resp.status_code != 200:
        return {}
    try:
        payload = resp.json()
    except ValueError:
        return {}
    entries = payload.get("data") if isinstance(payload, dict) else []
    by_id: dict[int, Mapping[str, object]] = {}
    if isinstance(entries, list):
        for entry in entries:
            if not isinstance(entry, Mapping):
                continue
            cid = entry.get("id")
            try:
                cid_int = int(cid)
            except (TypeError, ValueError):
                continue
            by_id[cid_int] = entry
    _CHALLENGES_CACHE["ts"] = now_ts
    _CHALLENGES_CACHE["by_id"] = by_id
    return by_id

def fetch_challenge_name(session: requests.Session, challenge_id: int) -> Optional[str]:
    try:
        resp = session.get(
            urljoin(CTFD_URL, f"/api/v1/challenges/{challenge_id}"),
            headers={"Accept": "application/json", **DEFAULT_HEADERS},
            timeout=15,
        )
    except requests.RequestException:
        return None
    if resp.status_code != 200:
        return None
    try:
        payload = resp.json()
    except ValueError:
        return None
    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data, Mapping):
        return None
    name = data.get("name")
    return str(name) if isinstance(name, str) and name else None

def _format_tokens(value: int) -> str:
    if value >= 1_000_000:
        return f"{value / 1_000_000:.1f}M"
    if value >= 10_000:
        return f"{value / 1_000:.1f}K"
    if value >= 1_000:
        return f"{value / 1_000:.0f}K"
    return str(value)


def _percent_left(used: int, limit: int) -> int:
    if limit <= 0:
        return 100
    ratio = min(max(used / limit, 0.0), 1.0)
    return int(round((1.0 - ratio) * 100))

def _read_budgets_from_codex(now_ts: float) -> Optional[List[str]]:
    if not CODEX_BUDGET_COMMAND:
        return None
    try:
        if (now_ts - float(_BUDGET_CACHE.get("ts") or 0.0)) <= _BUDGET_CACHE_TTL_SECONDS:
            cached = _BUDGET_CACHE.get("lines")
            if isinstance(cached, list) and all(isinstance(x, str) for x in cached):
                return list(cached)
    except Exception:
        pass
    try:
        cmd = shlex.split(CODEX_BUDGET_COMMAND)
    except ValueError:
        return None
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=2.0,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    raw_lines = [ln.rstrip("\n") for ln in (proc.stdout or "").splitlines()]
    wanted: List[str] = []
    prefixes = ("Context window:", "5h limit:", "Weekly limit:")
    for line in raw_lines:
        stripped = line.strip()
        if any(stripped.startswith(prefix) for prefix in prefixes):
            wanted.append(stripped)
    if not wanted:
        return None
    _BUDGET_CACHE["ts"] = now_ts
    _BUDGET_CACHE["lines"] = wanted
    return wanted

app = Flask(__name__, template_folder="templates", static_folder="static")
sock = Sock(app)

def format_thinking_html(text: str) -> str:
    text = strip_ansi(text or "")
    max_lines = int(os.environ.get("MAX_THINKING_RENDER_LINES", "800"))
    max_line_chars = int(os.environ.get("MAX_THINKING_RENDER_LINE_CHARS", "2000"))
    lines = text.splitlines()
    if len(lines) > max_lines:
        lines = ["[truncated: showing last lines]"] + lines[-max_lines:]
    out: List[str] = []
    term_out_buffer: List[str] = []

    def flush_term_out() -> None:
        if not term_out_buffer:
            return
        out.append(f'<div class="term-out">{"<br>".join(term_out_buffer)}</div>')
        term_out_buffer.clear()

    for raw in lines:
        line = raw.rstrip("\n")
        if len(line) > max_line_chars:
            line = line[:max_line_chars] + f" … [truncated {len(raw) - max_line_chars} chars]"
        stripped = line.strip()
        klass = "term-line"
        content = escape(line)
        if stripped.startswith("**") and stripped.endswith("**") and len(stripped) > 4:
            klass = "term-heading"
            content = escape(stripped.strip("* ").strip())
        elif stripped.lower() == "thinking":
            klass = "term-muted"
        elif stripped == "exec":
            klass = "term-label"
        elif "tokens used" in stripped.lower():
            klass = "term-label"
        elif stripped.startswith("/usr/bin/") or stripped.startswith("$ ") or stripped.startswith("bash -"):
            klass = "term-cmd"
        elif "succeeded" in stripped.lower():
            klass = "term-ok"
        elif "failed" in stripped.lower() or "error" in stripped.lower():
            klass = "term-err"
        elif "flag recovered" in stripped.lower():
            klass = "term-flag"
        else:
            klass = "term-out"
        if klass == "term-out":
            term_out_buffer.append(content or "&nbsp;")
            continue
        flush_term_out()
        out.append(f'<div class="{klass}">{content or "&nbsp;"}</div>')
    flush_term_out()
    return "\n".join(out) if out else '<div class="term-muted">No thinking captured.</div>'

def load_task_thinking(task_name: str) -> Optional[str]:
    if not task_name:
        return None
    preferred = THINKING_LOGS_DIR / task_name / "thinking.log"
    legacy = TASKS_ROOT / task_name / "thinking.log"
    path = preferred if preferred.exists() else legacy
    try:
        if not path.exists():
            return None
        content = strip_ansi(path.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return None
    # Avoid rendering extremely large logs in the browser.
    if len(content) > 200_000:
        return content[:200_000] + "\n\n[truncated]"
    return content

def load_task_live_output(task_name: str, max_bytes: int = 200_000) -> Optional[str]:
    if not task_name:
        return None
    preferred = THINKING_LOGS_DIR / task_name / "codex_output.log"
    legacy = TASKS_ROOT / task_name / "codex_output.log"
    path = preferred if preferred.exists() else legacy
    try:
        if not path.exists():
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if not data:
        return None
    if len(data) > max_bytes:
        data = data[-max_bytes:]
        prefix = b"[showing last chunk]\n\n"
        data = prefix + data
    return strip_ansi(data.decode("utf-8", errors="replace"))

def extract_thinking_from_stream(text: str) -> str:
    if not text:
        return ""
    text = strip_ansi(text)
    lower = text.lower()
    idx = lower.find("thinking")
    if idx == -1:
        return text
    snippet = text[idx:].splitlines()
    if snippet:
        snippet = snippet[1:]
    return "\n".join(snippet).rstrip()

def load_entries() -> List[Mapping[str, object]]:
    try:
        return stats_db.read_entries(STATS_PATH)
    except Exception:
        return []

def mark_stale_running(entries: List[Mapping[str, object]], now_ts: float) -> List[Mapping[str, object]]:
    latest_by_id: dict[int, Mapping[str, object]] = {}
    for e in entries:
        cid = e.get("challenge_id")
        if not isinstance(cid, int):
            continue
        prev = latest_by_id.get(cid)
        if not prev or float(e.get("timestamp") or 0) >= float(prev.get("timestamp") or 0):
            latest_by_id[cid] = e
    out = list(entries)
    for cid, e in latest_by_id.items():
        if str(e.get("status") or "done") != "running":
            continue
        ts = float(e.get("timestamp") or 0)
        if now_ts - ts <= STALE_RUNNING_SECONDS:
            continue
        out.append(
            {
                "task": e.get("task"),
                "challenge_id": cid,
                "flag": e.get("flag"),
                "tokens_used": e.get("tokens_used"),
                "thinking": e.get("thinking"),
                "status": "stalled",
                "error": "runner restarted",
                "timestamp": now_ts,
            }
        )
    return out

def mark_attempted_without_success(entries: List[Mapping[str, object]], now_ts: float) -> List[Mapping[str, object]]:
    # If we have logs for a task but no successful 'done' flag, mark it failed-ish
    # so the dashboard doesn't keep it queued forever after restarts.
    latest_by_id: dict[int, Mapping[str, object]] = {}
    has_success: set[int] = set()
    for e in entries:
        cid = e.get("challenge_id")
        if not isinstance(cid, int):
            continue
        if str(e.get("status") or "") == "done" and e.get("flag"):
            has_success.add(cid)
        prev = latest_by_id.get(cid)
        if not prev or float(e.get("timestamp") or 0) >= float(prev.get("timestamp") or 0):
            latest_by_id[cid] = e

    out = list(entries)
    for cid, e in latest_by_id.items():
        if cid in has_success:
            continue
        status = str(e.get("status") or "done")
        if status != "queued":
            continue
        task_name = str(e.get("task") or "")
        if not task_name:
            continue
        log_path = THINKING_LOGS_DIR / task_name / "thinking.log"
        if not log_path.exists():
            continue
        try:
            last_update = log_path.stat().st_mtime
        except OSError:
            last_update = None
        # If logs are actively updating, leave it queued/running; don't force-fail.
        if last_update is not None and (now_ts - float(last_update)) <= RUNNING_LOG_STALE_SECONDS:
            continue
        out.append(
            {
                "task": task_name,
                "challenge_id": cid,
                "flag": None,
                "tokens_used": e.get("tokens_used"),
                "thinking": e.get("thinking"),
                "status": "failed",
                "error": "previous attempt exists (logs found)",
                "timestamp": now_ts,
            }
        )
    return out

def _log_last_update_ts(task_name: str) -> Optional[float]:
    candidates = [
        THINKING_LOGS_DIR / task_name / "codex_output.raw.log",
        THINKING_LOGS_DIR / task_name / "codex_output.log",
        THINKING_LOGS_DIR / task_name / "thinking.log",
        TASKS_ROOT / task_name / "codex_output.log",
        TASKS_ROOT / task_name / "thinking.log",
    ]
    for path in candidates:
        try:
            if path.exists():
                return path.stat().st_mtime
        except OSError:
            continue
    return None


def find_task_dir_by_id(challenge_id: int) -> Optional[Path]:
    for entry in TASKS_ROOT.iterdir():
        if not entry.is_dir():
            continue
        meta = entry / "metadata.json"
        if not meta.exists():
            continue
        try:
            data = json.loads(meta.read_text(encoding="utf-8"))
        except Exception:
            continue
        try:
            mid = int(data.get("id"))
        except Exception:
            continue
        if mid == challenge_id:
            return entry
    return None


def build_view_model(
    entries: list[Mapping[str, object]],
    task_id: int | None = None,
) -> Mapping[str, object]:
    now = datetime.now().timestamp()

    # --- Normalize / mark states ---
    entries = mark_stale_running(entries, now)
    entries = mark_attempted_without_success(entries, now)

    filtered = (
        entries
        if task_id is None
        else [e for e in entries if e.get("challenge_id") == task_id]
    )

    total_tokens = sum(int(e.get("tokens_used") or 0) for e in filtered)
    flags_found = [e for e in filtered if e.get("flag")]

    title = "Codex Task Stats" if task_id is None else f"Codex Task Stats – {task_id}"
    summary = {
        "runs_label": "Total runs" if task_id is None else "Runs",
        "runs": len(filtered),
        "flags": len(flags_found),
        "tokens": total_tokens,
    }

    # --- Budgets (index page only, no network) ---
    budgets: Mapping[str, object] = {}
    if task_id is None:
        window_5h = [e for e in entries if now - float(e.get("timestamp") or 0) <= 5 * 3600]
        window_week = [e for e in entries if now - float(e.get("timestamp") or 0) <= 7 * 86400]

        tokens_5h = sum(int(e.get("tokens_used") or 0) for e in window_5h)
        tokens_week = sum(int(e.get("tokens_used") or 0) for e in window_week)

        budgets = {
            "tokens_5h": tokens_5h,
            "limit_5h": TOKEN_LIMIT_5H,
            "tokens_week": tokens_week,
            "limit_week": TOKEN_LIMIT_WEEK,
        }

    # --- Latest status ---
    latest_status = "done"
    source = entries if task_id is None else filtered
    for e in reversed(source):
        status = str(e.get("status") or "done")
        if status == "running":
            latest_status = "running"
            break
        latest_status = status
        break

    # --- Buckets for index page ---
    queue: list[Mapping[str, object]] = []
    running: list[Mapping[str, object]] = []
    solved: list[Mapping[str, object]] = []
    failed: list[Mapping[str, object]] = []

    if task_id is None:
        # latest entry per challenge_id
        latest_by_id: dict[int, Mapping[str, object]] = {}
        for e in entries:
            cid = e.get("challenge_id")
            if not isinstance(cid, int):
                continue
            prev = latest_by_id.get(cid)
            if not prev or float(e.get("timestamp") or 0) >= float(prev.get("timestamp") or 0):
                latest_by_id[cid] = e

        for cid, e in sorted(latest_by_id.items(), key=lambda kv: str(kv[1].get("task") or "")):
            status = str(e.get("status") or "done")
            ts = float(e.get("timestamp") or 0)
            has_flag = bool(e.get("flag"))

            item: dict[str, object] = {
                "task": str(e.get("task") or ""),
                "challenge_id": cid,
                "status": status,
                "timestamp": datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S"),
                "detail_href": f"/task/{cid}",
                "error": str(e.get("error") or ""),
            }

            if status == "hidden":
                continue

            # --- SOLVED ---
            if has_flag or status == "solved":
                solved.append({**item, "status": "solved", "error": ""})
                continue

            # --- QUEUED ---
            if status == "queued":
                queue.append(item)
                continue

            # --- RUNNING ---
            if status == "running":
                last_update = _log_last_update_ts(item["task"])
                log_stale = (
                    last_update is not None
                    and (now - last_update) > RUNNING_LOG_STALE_SECONDS
                )
                if log_stale or (now - ts) > STALE_RUNNING_SECONDS:
                    failed.append(
                        {
                            **item,
                            "status": "stalled",
                            "error": item["error"] or "no recent log updates",
                        }
                    )
                else:
                    running.append(item)
                continue

            # --- FAILED / DONE WITHOUT FLAG ---
            failed.append(
                {
                    **item,
                    "status": status,
                    "error": item["error"] or "no flag",
                }
            )

    # --- Cards (task detail page only) ---
    cards: list[Mapping[str, object]] = []
    if task_id is not None and filtered:
        best = max(
            filtered,
            key=lambda e: float(e.get("timestamp") or 0),
            default=None,
        )

        if best:
            task_name = str(best.get("task") or "")
            status = str(best.get("status") or "done")

            thinking_text = load_task_thinking(task_name) or str(best.get("thinking") or "")
            if status == "running" and not thinking_text.strip():
                live = load_task_live_output(task_name)
                if live:
                    thinking_text = extract_thinking_from_stream(live)

            ts = datetime.fromtimestamp(best.get("timestamp", 0)).strftime("%Y-%m-%d %H:%M:%S")

            cards.append(
                {
                    "id": "task-0",
                    "task": task_name,
                    "challenge_id": best.get("challenge_id"),
                    "timestamp": ts,
                    "flag": best.get("flag") or "",
                    "tokens": best.get("tokens_used") or "",
                    "status": status,
                    "thinking": thinking_text,
                    "thinking_html": format_thinking_html(thinking_text),
                    "detail_href": f"/task/{best.get('challenge_id')}",
                }
            )

    # --- Empty text ---
    task_name = ""
    if task_id is not None and filtered:
        task_name = str(filtered[-1].get("task") or "")

    empty_text = (
        "No runs yet."
        if task_id is None
        else "No runs for this task yet."
    )

    return {
        "title": title,
        "task_id": task_id,
        "task_name": task_name,
        "summary": summary,
        "budgets": budgets,
        "latest_status": latest_status,
        "queue": queue,
        "running": running,
        "solved": solved,
        "failed": failed,
        "cards": cards,
        "empty_text": empty_text,
    }


@app.route("/", methods=["GET"])
@app.route("/index.html", methods=["GET"])
def index() -> Response:
    entries = load_entries()
    context = build_view_model(entries)
    html = render_template("stats.html", **context)
    return Response(html, mimetype="text/html")


@app.route("/task/<int:task_id>", methods=["GET"])
def task_detail(task_id: int) -> Response:
    entries = load_entries()
    context = build_view_model(entries, task_id=task_id)
    html = render_template("detail.html", **context)
    return Response(html, mimetype="text/html")


@app.route("/api/task/<int:task_id>/thinking", methods=["GET"])
def task_thinking_api(task_id: int) -> Response:
    entries = load_entries()
    relevant = [e for e in entries if e.get("challenge_id") == task_id]
    latest = relevant[-1] if relevant else {}
    task_name = str(latest.get("task") or "")
    status = str(latest.get("status") or "done")
    thinking_text = load_task_thinking(task_name) or str(latest.get("thinking") or "")
    if status == "running" and not thinking_text.strip():
        live = load_task_live_output(task_name)
        if live:
            thinking_text = extract_thinking_from_stream(live)
    return jsonify(
        {
            "task_id": task_id,
            "task": task_name,
            "status": status,
            "html": format_thinking_html(thinking_text),
        }
    )

def _thinking_payload(task_id: int) -> dict[str, object]:
    entries = load_entries()
    relevant = [e for e in entries if e.get("challenge_id") == task_id]
    latest = relevant[-1] if relevant else {}
    task_name = str(latest.get("task") or "")
    status = str(latest.get("status") or "done")
    thinking_text = load_task_thinking(task_name) or str(latest.get("thinking") or "")
    if status == "running" and not thinking_text.strip():
        live = load_task_live_output(task_name)
        if live:
            thinking_text = extract_thinking_from_stream(live)
    return {
        "task_id": task_id,
        "task": task_name,
        "status": status,
        "html": format_thinking_html(thinking_text),
    }


@sock.route("/ws/task/<int:task_id>/thinking")
def task_thinking_ws(ws, task_id: int) -> None:
    last_hash = ""
    while True:
        payload = _thinking_payload(task_id)
        html = str(payload.get("html") or "")
        status = str(payload.get("status") or "done")
        digest = hashlib.sha256(html.encode("utf-8", errors="ignore")).hexdigest()
        if digest != last_hash:
            last_hash = digest
            ws.send(json.dumps(payload))
        if status != "running":
            break
        time.sleep(5)


@app.route("/api/task/<int:task_id>/message", methods=["POST"])
def task_message(task_id: int) -> Response:
    data = request.get_json(silent=True) or {}
    message = str(data.get("message") or "").strip()
    if not message:
        return jsonify({"error": "missing message"}), 400

    task_dir = find_task_dir_by_id(task_id)
    if not task_dir:
        return jsonify({"error": "task not found"}), 404

    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    context_path = task_dir / "codex_context.txt"
    note = f"[Operator note {ts}]\n{message}\n\n"
    try:
        existing = context_path.read_text(encoding="utf-8")
    except Exception:
        existing = ""
    try:
        context_path.write_text((existing + "\n" + note).strip() + "\n", encoding="utf-8")
    except Exception as exc:
        return jsonify({"error": f"failed to write context: {exc}"}), 500

    stop_flag = THINKING_LOGS_DIR / task_dir.name / "stop.flag"
    stop_flag.parent.mkdir(parents=True, exist_ok=True)
    stop_flag.write_text(message, encoding="utf-8")

    return jsonify({"status": "ok"})


@app.route("/task/<task_name>", methods=["GET"])
def task_name_redirect(task_name: str) -> Response:
    entries = load_entries()
    for e in reversed(entries):
        if e.get("task") == task_name and isinstance(e.get("challenge_id"), int):
            return redirect(url_for("task_detail", task_id=e["challenge_id"]))
    return redirect(url_for("index"))


if __name__ == "__main__":
    print(f"Serving Codex stats on http://localhost:{PORT} (source: {STATS_PATH})")
    # Use a WS-capable server so flask-sock endpoints work.
    try:
        from gevent import pywsgi  # type: ignore
        from geventwebsocket.handler import WebSocketHandler  # type: ignore
    except Exception:
        app.run(host="0.0.0.0", port=PORT, debug=False)
    else:
        server = pywsgi.WSGIServer(("0.0.0.0", PORT), app, handler_class=WebSocketHandler)
        server.serve_forever()
