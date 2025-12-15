from dataclasses import dataclass
from dotenv import load_dotenv
from pathlib import Path
from time import time, sleep
import logging
import os

@dataclass
class Task:
    id:         int
    timestamp:  int
    name:       str
    status:     str
    tokens:     int = 0
    flag:       str = ""
    error:      str = ""


load_dotenv()

CTFD_URL = os.environ["CTFD_URL"].rstrip("/")
TEAM_EMAIL = os.environ.get("AI_TEAM_EMAIL")
TEAM_PASSWORD = os.environ.get("AI_TEAM_PASSWORD")
TEAM_NAME = os.environ.get("AI_TEAM_NAME")

DB_PATH = Path(os.environ.get("DB_PATH", "tasks.db"))
TASKS_DIR = Path(os.environ.get("TASKS_ROOT", "tasks"))
LOGS_DIR = Path(os.environ.get("THINKING_LOGS_DIR", "logs"))

MAX_ATTACHMENT_BYTES = int(os.environ.get("MAX_ATTACHMENT_BYTES", 10 * 1024 * 1024))
TARGET_POINTS = int(os.environ.get("TARGET_POINTS"))
MAX_CODEX_ATTEMPTS = int(os.environ.get("MAX_CODEX_ATTEMPTS", "3"))
CODEX_TIMEOUT = int(os.environ.get("CODEX_TIMEOUT")) * 60
HOST = os.environ.get("STATS_HOST", "127.0.0.1")
PORT = int(os.environ.get("STATS_PORT", "8000"))
MAX_CODEX_WORKERS = int(os.environ.get("MAX_CODEX_WORKERS"))

FLAG_FORMAT = os.environ.get("FLAG_FORMAT")
FLAG_REGEX = os.environ.get("FLAG_REGEX")

_SOLVED_CACHE: dict[str, object] = {"ts": 0.0, "ids": set()}
SOLVED_CACHE_SECONDS = int(os.environ.get("SOLVED_CACHE_SECONDS", "30"))
DEFAULT_CODEX_COMMAND = ["codex", "exec", "-s", "danger-full-access", "-m", "gpt-5.1-codex-mini", "--skip-git-repo-check"]
STATS_TEMPLATE_ENV = os.environ.get("STATS_TEMPLATE")
STATS_TEMPLATE = Path(STATS_TEMPLATE_ENV) if STATS_TEMPLATE_ENV else None
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
EXPECTED_COLUMNS = ["id", "timestamp", "name", "status", "flag", "tokens", "error"]

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
_CHALLENGES_CACHE: dict[str, object] = {"ts": 0.0, "by_id": {}}

