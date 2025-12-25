#!/usr/bin/env python3

import re
import json
import os
import subprocess
import sys
from ansi2html import Ansi2HTMLConverter

from flask import Flask, Response, jsonify, redirect, render_template, render_template_string, url_for, request, abort
from flask_sock import Sock

from python.models import *
from . import db

ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
PERCENT_5H = 0
PERCENT_WEEK = 0
TOKENS_SINCE = 0

app = Flask(__name__, template_folder="web/templates", static_folder="web/static")
sock = Sock(app)


def strip_ansi(text: str) -> str:
    return re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)


conv = Ansi2HTMLConverter(
    inline=True,   # стили прямо в span'ах
    dark_bg=True   # под терминал
)

def ansi_to_html(text: str) -> str:
    return conv.convert(text, full=False)


def _load_process_registry() -> dict:
    if not JSON_FILE.exists():
        return {}
    try:
        return json.loads(JSON_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _write_process_registry(data: dict) -> None:
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    with JSON_FILE.open("w", encoding="utf-8") as json_file:
        json.dump(data, json_file, indent=2)


def _process_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def ensure_codex_running(task_name: str | None = None) -> None:
    data = _load_process_registry()
    proc = data.get("codex")
    if proc and _process_alive(proc.get("pid", -1)):
        return
    if proc:
        data.pop("codex", None)

    task_args = ["--task", task_name] if task_name else []
    command = [sys.executable, str(ROOT / "main.py"), "run", "codex", *task_args]
    subprocess.Popen(
        command,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )


def _attempt_from_log_path(path: Path) -> int | None:
    match = re.search(r"\.(\d+)$", path.name)
    if not match:
        return None
    return int(match.group(1))


def _list_attempts(task: Task) -> list[int]:
    task_dir = CODEX_DIR / task.name
    attempts: set[int] = set()
    if task_dir.exists():
        for log_path in task_dir.glob(f"{CODEX_FILE}.*"):
            attempt = _attempt_from_log_path(log_path)
            if attempt is not None:
                attempts.add(attempt)
    current_attempt = _attempt_from_log_path(task.log)
    if current_attempt is not None:
        attempts.add(current_attempt)
    return sorted(attempts)


def _next_attempt(task: Task) -> int:
    attempts = _list_attempts(task)
    if not attempts:
        return 1
    return max(attempts) + 1


def _ensure_attempt_log(task: Task) -> None:
    attempt = _next_attempt(task)
    log_path = CODEX_DIR / task.name / f"{CODEX_FILE}.{attempt}"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    if not log_path.exists():
        log_path.write_text("[attempt queued via dashboard]\n", encoding="utf-8")


def load_log(log_path: Path) -> str | None:
    if log_path.exists():
        content = ansi_to_html(log_path.read_text(encoding="utf-8", errors="replace"))
    else:
        warning(f"no log file: {log_path}")
        return 
    return content


def task_view_model(task: Task, selected_attempt: int | None = None) -> dict:
    if not task:
        error("task_view_model but task does not exist")
        return {}

    attempts = _list_attempts(task)
    latest_attempt = max(attempts) if attempts else None
    if selected_attempt is None or selected_attempt not in attempts:
        selected_attempt = latest_attempt

    log_path = task.log
    if selected_attempt is not None:
        log_path = CODEX_DIR / task.name / f"{CODEX_FILE}.{selected_attempt}"
    text = load_log(log_path)

    if not text:
        text = "No codex logs"

    enable_live = (
        selected_attempt is not None
        and selected_attempt == latest_attempt
        and task.status == "running"
    )

    return {
        "title": task.name,
        "task_id": task.id,
        "task_name": task.name,
        "runs": 0,
        "tokens": task.tokens,
        "text": text,
        "latest_status": task.status,
        "attempts": attempts,
        "selected_attempt": selected_attempt,
        "latest_attempt": latest_attempt,
        "enable_live": enable_live,
    }


def stats_view_model() -> dict:
    entries = db.read_entries(DB_PATH)
    tokens = sum(task.tokens for task in entries if task.timestamp >= TOKENS_SINCE)

    # --- Budgets ---
    limit_5h    = 20000000
    limit_week  = 100000000

    tokens_5h   = int(PERCENT_5H * limit_5h / 100 - tokens)
    tokens_week = int(PERCENT_WEEK * limit_week / 100 - tokens)

    budgets = {
        "tokens_5h": tokens_5h,
        "limit_5h": limit_5h,
        "tokens_week": tokens_week,
        "limit_week": limit_week,
    }

    # --- Cards (task detail page only) ---
    cards: dict[str, list[Task]] = {
        "queued": [],
        "running": [],
        "solved": [],
        "failed": [],
        "block": [],
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


@app.route("/task/<string:task_id>", methods=["GET"])
def task_detail(task_id: str) -> Response:
    task = db.get_entry(DB_PATH, task_id)
    if not task:
        abort(404)

    selected_attempt = request.args.get("attempt", type=int)
    context = task_view_model(task, selected_attempt)
    html = render_template("detail.html", **context)
    return Response(html, mimetype="text/html")


@app.route("/task/<string:task_id>/log", methods=["GET"])
def task_log(task_id: str) -> Response:
    task = db.get_entry(DB_PATH, task_id)
    if not task:
        abort(404)

    selected_attempt = request.args.get("attempt", type=int)
    context = task_view_model(task, selected_attempt)
    payload = {
        "text": context.get("text"),
        "selected_attempt": context.get("selected_attempt"),
        "latest_attempt": context.get("latest_attempt"),
        "enable_live": context.get("enable_live"),
    }
    return jsonify(payload)


@sock.route("/task/<string:task_id>/update")
def load_codex_ws(ws, task_id: str):
    message = ws.receive()
    if not message or not message.startswith("start_log_stream:"):
        print(f"WS received unexpected message or no message: {message}", flush=True)
        ws.close()
        return

    task = db.get_entry(DB_PATH, task_id)
    if not task.log.exists() or task is None or task.status != "running":
        ws.close()
        return

    with open(task.log, "r", encoding="utf-8") as f:
        f.seek(0, 2)
        while True:
            task = db.get_entry(DB_PATH, task_id)
            line = f.readline()
            if task.status != "running":
                break
            if not line:
                sleep(1)
            else:
                ws.send(ansi_to_html(line))


@app.route("/api/task/<int:task_id>/message", methods=["POST"])
def task_message(task_id: str) -> Response:
    data = request.get_json(silent=True) or {}
    message = str(data.get("message") or "").strip()
    if not message:
        return jsonify({"error": "missing message"}), 400

    task = db.get_entry(DB_PATH, task_id)
    if not task:
        return jsonify({"error": "task not found"}), 404
    task_dir = TASKS_DIR / task

    ts = now().strftime("%Y-%m-%d %H:%M:%S")
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


@app.route("/api/task/<int:task_id>/status", methods=["POST"])
def task_status(task_id: int) -> Response:
    data = request.get_json(silent=True) or {}
    status = str(data.get("status") or "").strip().lower()
    if status not in ("queued", "running", "solved", "failed", "block"):
        return jsonify({"error": "invalid status"}), 400

    task = db.get_entry(DB_PATH, str(task_id))
    if not task:
        return jsonify({"error": "task not found"}), 404

    if task.status == status:
        return jsonify({"status": "ok"})

    if task.status == "running" and status != "running":
        stop_flag = CODEX_DIR / task.name / "stop.flag"
        stop_flag.parent.mkdir(parents=True, exist_ok=True)
        stop_flag.write_text("stopped via dashboard", encoding="utf-8")

    db.update_task_status(DB_PATH, task.id, status, error="")
    if status == "running":
        _ensure_attempt_log(task)
        ensure_codex_running(task.name)
    return jsonify({"status": "ok"})


def get_percent() -> tuple[float]:
    proc = subprocess.Popen(
        ["codex", "exec", "--skip-git-repo-check", "say hi"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env={"RUST_LOG": "debug"},
        text=True,
        bufsize=1,
    )

    assert proc.stdout is not None
    for line in proc.stdout:
        if "RateLimitWindow" in line:
            primary = float(line.split('used_percent:')[1].split(',')[0].strip())
            secondary = float(line.split('used_percent:')[2].split(',')[0].strip())
            info(f"Tokens used in 5h:{100 - primary}%, week: {100 - secondary}%")
            return (100 - primary, 100 - secondary)


def main():
    global PERCENT_5H, PERCENT_WEEK, TOKENS_SINCE
    info(f"Running website on http://{HOST}:{PORT} (database: {DB_PATH})")
    PERCENT_5H, PERCENT_WEEK = get_percent()
    TOKENS_SINCE = now()
    app.run(host=HOST, port=PORT, debug=DEBUG_FLASK)
    info("ended")

if __name__ == "__main__":
    main()
