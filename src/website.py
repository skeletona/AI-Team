#!/usr/bin/env python3
"""
Simple stats dashboard for Codex task runs.

Reads entries from DB_PATH (default: codex_stats.db) and serves a
small HTML page showing recent runs, Codex thinking snippets, attempted flags,
and token usage totals, using Flask.
"""

from __future__ import annotations

import json
import hashlib
import re
from html import escape
from typing import List, Mapping, Optional

from flask import Flask, Response, jsonify, redirect, render_template, render_template_string, url_for, request
from flask_sock import Sock

from src.models import *
from . import db

ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")

app = Flask(__name__, template_folder="web/templates", static_folder="web/static")
sock = Sock(app)

def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text or "")


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


def load_task_thinking(task: Task) -> Optional[str]:
    path = CODEX_DIR / task.name / "thinking.log"
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        logging.error(f"Error reading thinking.log: {path}")
        return None
    if len(content) > 200_000:
        return content[:200_000] + "\n\n[truncated]"
    return content


def load_task_live_output(task_name: str, max_bytes: int = 200_000) -> Optional[str]:
    if not task_name:
        return None
    preferred = CODEX_DIR / task_name / "codex_output.log"
    legacy = TASKS_DIR / task_name / "codex_output.log"
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


def _log_last_update_ts(task_name: str) -> Optional[float]:
    candidates = [CODEX_DIR / task_name / "thinking.log"]
    for path in candidates:
        try:
            if path.exists():
                return path.stat().st_mtime
        except OSError:
            continue
    return None


def task_view_model(task_id: int) -> Mapping[str, object]:
    task = db.get_entry(DB_PATH, task_id)

    return {
        "title": task.name,
        "task_id": task.id,
        "task_name": task.name,
        "runs": 0,
        "tokens": task.tokens,
    }


def stats_view_model() -> Mapping[str, object]:
    entries = db.read_entries(DB_PATH)
    tokens = sum(task.tokens for task in entries)

    # --- Budgets ---
    budgets = {  # TODO
        "tokens_5h": 0,
        "limit_5h": TOKEN_LIMIT_5H,
        "tokens_week": 0,
        "limit_week": TOKEN_LIMIT_WEEK,
    }

    # --- Cards (task detail page only) ---
    cards: dict[str, list[Task]] = {
        "queued": [],
        "running": [],
        "solved": [],
        "failed": [],
    }
    for task in entries:
        cards[task.status].append(task)

    return {
        "title":    "AI-Team Stats",
        "tokens":   tokens,
        "budgets":  budgets,
        "cards":    cards,
        "runs":     0,
        "flags":    0,
    }


@app.route("/", methods=["GET"])
@app.route("/index.html", methods=["GET"])
def index() -> Response:
    context = stats_view_model()
    html = render_template("stats.html", **context)
    return Response(html, mimetype="text/html")


@app.route("/task/<int:task_id>", methods=["GET"])
def task_detail(task_id: int) -> Response:
    context = task_view_model(task_id)
    html = render_template("detail.html", **context)
    return Response(html, mimetype="text/html")


@app.route("/api/task/<int:task_id>/thinking", methods=["GET"])
def task_thinking_api(task_id: int) -> Response:
    entries = db.read_entries(DB_PATH) 
    relevant = [e for e in entries if e.id == task_id]
    latest = relevant[-1] if relevant else {}
    task_name = str(latest.get("task") or "")
    status = str(latest.get("status") or "done")
    thinking_text = load_task_thinking(task_name) or str(latest.get("thinking") or "")
    if status == "running" and not thinking_text.strip():
        live = load_task_live_output(task_name)
        if live:
            thinking_text = live
    return jsonify(
        {
            "task_id": task_id,
            "task": task_name,
            "status": status,
            "html": format_thinking_html(thinking_text),
        }
    )


def _thinking_payload(task_id: int) -> dict[str, object]:
    entries = db.read_entries(DB_PATH)
    relevant = [e for e in entries if e.id == task_id]
    latest = relevant[-1] if relevant else {}
    task_name = str(latest.get("task") or "")
    status = str(latest.get("status") or "done")
    thinking_text = load_task_thinking(task_name) or str(latest.get("thinking") or "")
    if status == "running" and not thinking_text.strip():
        live = load_task_live_output(task_name)
        if live:
            thinking_text = live
    return {
        "task_id": task_id,
        "task": task_name,
        "status": status,
        "html": format_thinking_html(thinking_text),
    }


@sock.route("/task/<int:task_id>/logs")
def task_thinking_ws(ws, task_id: int):
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
        sleep(5)


@app.route("/api/task/<int:task_id>/message", methods=["POST"])
def task_message(task_id: int) -> Response:
    data = request.get_json(silent=True) or {}
    message = str(data.get("message") or "").strip()
    if not message:
        return jsonify({"error": "missing message"}), 400

    task = db.get_entry(DB_PATH, task_id)
    if not task:
        return jsonify({"error": "task not found"}), 404
    task_dir = TASKS_DIR / task

    ts = time().strftime("%Y-%m-%d %H:%M:%S")
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

    stop_flag = CODEX_DIR / task_dir.name / "stop.flag"
    stop_flag.parent.mkdir(parents=True, exist_ok=True)
    stop_flag.write_text(message, encoding="utf-8")

    return jsonify({"status": "ok"})


def main():
    logging.info(f"Running website on http://{HOST}:{PORT} (database: {DB_PATH})")
    app.run(host=HOST, port=PORT, debug=DEBUG_FLASK, use_reloader=False)


if __name__ == "__main__":
    main()
