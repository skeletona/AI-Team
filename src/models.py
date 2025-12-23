#!/usr/bin/env python3

from dataclasses import dataclass, asdict, replace
from dotenv import load_dotenv
from pathlib import Path
from time import time, sleep
from logging import debug, info, warning, error, basicConfig, exception, INFO, DEBUG
from signal import signal, SIGTERM, SIGKILL
import subprocess
import json
import os


def now() -> int:
    return int(time())


@dataclass
class Task:
    id:         int
    name:       str
    status:     str
    points:     int
    solves:     int
    category:   str
    timestamp:  int
    tokens:     int
    log:        Path = 0
    flag:       str  = ""
    error:      str  = ""

@dataclass
class Process:
    name:       str
    pid:        int
    log:        Path


load_dotenv()

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
CODEX_COMMAND = ["docker", "exec", "-it", "AI-Team", "codex", "exec", "--dangerously-bypass-approvals-and-sandbox", "-m", MODEL, "-c", "model_reasoning_effort=low", "--skip-git-repo-check"]

ROOT        = Path(__file__).resolve().parent.parent
DB_PATH     = ROOT / os.environ.get("DB_PATH", "tasks.db")
TASKS_DIR   = ROOT / os.environ.get("TASKS_DIR", "tasks")
CODEX_DIR   = ROOT / os.environ.get("THINKING_LOGS_DIR", "codex")
LOGS_DIR    = ROOT / os.environ.get("LOGS_DIR", "logs")
JSON_FILE   = LOGS_DIR / os.environ.get("JSON_FILE", "running.json")
CODEX_FILE  = os.environ.get("CODEX_FILE", "codex.log")

FLAG_REGEX = os.environ.get("FLAG_REGEX")
HOST = os.environ.get("FLASK_HOST", "0.0.0.0")
PORT = os.environ.get("FLASK_PORT", 8000)
DEBUG_FLASK = os.environ.get("DEBUG_FLASK", False)
ENABLE_DEBUG = os.environ.get("DEBUG", False)

basicConfig(level=DEBUG if ENABLE_DEBUG else INFO, format="%(levelname)s: %(message)s", force=True)

############
# NON-CTFD #
############

CTFD_OWL                = os.environ.get("CTFD_OWL", False)
CTFD_TASK_API           = os.environ.get("CTFD_TASK_API", "/api/v1/challenges/")
CTFD_TASKS_API          = os.environ.get("CTFD_TASKS_API", "/api/v1/challenges")
CTFD_TASKS_JSON_LIST    = os.environ.get("CTFD_TASKS_PATH", "data")
CTFD_TASK_DETAIL_LIST   = os.environ.get("CTFD_DETAIL_PATH", "data")
CTFD_FILES_JSON         = os.environ.get("CTFD_FILES_PATH", "files")
CTFD_DOWNLOAD_API       = os.environ.get("CTFD_DOWNLOAD_API", "/files/")
CTFD_SUBMIT_API         = os.environ.get("CTFD_SUBMIT_API", "/api/v1/challenges/attempt")
CTFD_SUBMIT_PATH        = os.environ.get("CTFD_SUBMIT_PATH", "")
CTFD_SKIP_LOGIN    = bool(os.environ.get("CTFD_SKIP_LOGIN", False))


raw = os.environ.get("CODEX_PROMPT")
if raw:
    CODEX_PROMPT = json.loads(raw)
else:
    CODEX_PROMPT = [
        "Solve this Jeopardy CTF challenge inside the current directory.",
        "You do not need to know what is in /tasks or /codex.",
        f"Flag format (regex): {FLAG_FORMAT}",
        "You are in Docker container. You have sudo without password.",
    ]

raw = os.environ.get("CODEX_OWL_PROMPT")
if raw:
    CODEX_OWL_PROMPT = json.loads(raw)
else:
    CODEX_OWL_PROMPT = [
        f"Instance is available. Run \"instance [id] [command]\" (instance is in your PATH)",
        "Possible commands: start, stop, info, renew",
        "Do not stop instance before exiting."
    ]

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
        "Accept-Language": "en-US,en;q=0.9",
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

