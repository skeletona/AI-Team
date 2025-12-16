#!/usr/bin/env python3

from dataclasses import dataclass, asdict
from dotenv import load_dotenv
from pathlib import Path
from time import time, sleep
from logging import info, error, warning, basicConfig, INFO
from signal import signal, SIGTERM, SIGKILL
import json
import os


def now() -> int:
    return int(time())


@dataclass
class Task:
    id:         int
    timestamp:  int
    name:       str
    status:     str
    points:     int
    solves:     int
    category:   str
    tokens:     int = 0
    flag:       str = ""
    error:      str = ""

@dataclass
class Process:
    name:       str
    pid:        int
    log:        Path


load_dotenv()
basicConfig(level=INFO, format="%(levelname)s: %(message)s", force=True)


CTFD_URL        = os.environ["CTFD_URL"].rstrip("/")
TEAM_EMAIL      = os.environ.get("AI_TEAM_EMAIL")
TEAM_PASSWORD   = os.environ.get("AI_TEAM_PASSWORD")
TEAM_NAME       = os.environ.get("AI_TEAM_NAME")
FLAG_FORMAT = os.environ.get("FLAG_FORMAT")

MAX_ATTACHMENT_SIZE = int(os.environ.get("MAX_ATTACHMENT_SIZE", 10))
MAX_CODEX_ATTEMPTS  = int(os.environ.get("MAX_CODEX_ATTEMPTS", "3"))
MAX_CODEX_WORKERS   = int(os.environ.get("MAX_CODEX_WORKERS"))
CODEX_TIMEOUT       = int(os.environ.get("CODEX_TIMEOUT") or 60) * 60
TARGET_POINTS       = int(os.environ.get("TARGET_POINTS") or 0)
MAX_CODEX_TOKEN     = int(os.environ.get("MAX_CODEX_TOKENS") or 0)
MODEL               = os.environ.get("MODEL")
CODEX_COMMAND   = ["codex", "exec", "-s", "workspace-write", "-m", MODEL, "--skip-git-repo-check"]

DB_PATH     = Path(os.environ.get("DB_PATH", "tasks.db"))
TASKS_DIR   = Path(os.environ.get("TASKS_ROOT", "tasks"))
CODEX_DIR   = Path(os.environ.get("THINKING_LOGS_DIR", "codex"))
LOGS_DIR    = Path(os.environ.get("LOGS_DIR", "logs"))
JSON_FILE   = Path(os.environ.get("JSON_FILE") or LOGS_DIR / "running.json")

FLAG_REGEX = os.environ.get("FLAG_REGEX")
HOST = os.environ.get("FLASK_HOST", "0.0.0.0")
PORT = os.environ.get("FLASK_PORT", 8000)
DEBUG_FLASK = os.environ.get("DEBUG_FLASK", False)

############
# NON-CTFD #
############

CTFD_SKIP_LOGIN    = bool(os.environ.get("CTFD_SKIP_LOGIN", False))
CTFD_TASK_API           = os.environ.get("CTFD_TASK_API", "/api/v1/challenges/")
CTFD_TASKS_API          = os.environ.get("CTFD_TASKS_API", "/api/v1/challenges")
CTFD_TASKS_JSON_LIST    = os.environ.get("CTFD_TASKS_PATH", "data")
CTFD_TASK_DETAIL_LIST   = os.environ.get("CTFD_DETAIL_PATH", "data")
CTFD_FILES_JSON         = os.environ.get("CTFD_FILES_PATH", "files")
CTFD_DOWNLOAD_API       = os.environ.get("CTFD_DOWNLOAD_API", "/files/")
CTFD_SUBMIT_API         = os.environ.get("CTFD_SUBMIT_API", "/api/v1/challenges/attempt")
CTFD_SUBMIT_PATH        = os.environ.get("CTFD_SUBMIT_PATH", "")

raw = os.environ.get("CTFD_HEADERS")
if raw:
    CTFD_HEADERS = json.loads(raw)
else:
    CTFD_HEADERS = {
        "User-Agent": (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko)"
            " Chrome/120 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9"
    }

raw = os.environ.get("CTFD_JSON_FORMAT")
if raw:
    CTFD_JSON_FORMAT = json.loads(raw)
else:
    CTFD_JSON_FORMAT = {
        "id": "id",
        "name": "name",
        "points": "value",
        "solves": "solves",
        "category": "category"
    }
