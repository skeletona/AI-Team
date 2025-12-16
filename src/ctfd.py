from logging import basicConfig, debug, error, info, warning
from pathlib import Path
from time import time
import re
import threading
from typing import Any, Mapping, Optional
from urllib.parse import unquote, urljoin

import requests

from src.db import create_entry, read_entries
from src.models import *


def login(session: requests.Session) -> bool:
    if not TEAM_EMAIL or not TEAM_PASSWORD:
        error("AI_TEAM_EMAIL/AI_TEAM_PASSWORD must be set for submissions")
        return False
    try:
        token = fetch_csrf_token(session, "/login")
    except Exception as exc:
        warning("login CSRF fetch failed: %s", exc)
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
        error("login blocked by Turnstile/firewall")
        return False
    if resp.status_code >= 400 or "invalid username or password" in body:
        error("login failed (status %s)", resp.status_code)
        return False
    return is_logged_in(session)


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


def create_session() -> Optional[requests.Session]:
    session = requests.Session()
    session.headers.update(DEFAULT_HEADERS)
    if not login(session):
        return None
    return session



def submit_flag(session: requests.Session, challenge_id: int, flag: str) -> bool:
    endpoint = urljoin(CTFD_URL, "/api/v1/challenges/attempt")
    payload = {"submission": flag, "challenge_id": challenge_id}
    csrf_token = session.cookies.get("csrf_token")
    if not csrf_token:
        try:
            csrf_token = fetch_csrf_token(session, "/challenges")
        except Exception as exc:
            warning("could not obtain CSRF token for submission: %s", exc)
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
        warning("flag submission returned HTTP %s", resp.status_code)
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
            info("server accepted flag for challenge %s", challenge_id)
            return True
        else:
            print(f"submission failed: {data.get('message')}", flush=True)
            return False
    else:
        print(f"submission failed: {payload}", flush=True)
        return False


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


def fetch_tasks(session: requests.Session) -> list[Task]:
    try:
        resp = session.get(
            urljoin(CTFD_URL, "/api/v1/challenges"),
            headers={"Accept": "application/json", **DEFAULT_HEADERS},
        )
        resp.raise_for_status()
        payload = resp.json()
        tasks = payload.get("data", [])

        tasks: list[Task] = [
            Task(
                id=task["id"],
                timestamp=now(),
                name=task["name"],
                status="queued",
                points=task["value"],
                solves=task["solves"],
                category=task["category"],
            )
            for task in tasks
        ]

        info(f"Fetched tasks: {len(tasks)}")
        return tasks

    except (requests.RequestException, ValueError) as e:
        error(f"Failed to fetch challenges: {e}")
        return []


def fetch_challenge_detail(session: requests.Session, challenge_id: int) -> str | None:
    resp = session.get(
        urljoin(CTFD_URL, f"/api/v1/challenges/{challenge_id}"),
        headers={"Accept": "application/json", **DEFAULT_HEADERS},
    )
    resp.raise_for_status()
    payload = resp.json()
    return payload.get("data") if isinstance(payload, dict) else {}


def download_task_files(
    task: Task, session: requests.Session
) -> int:
    task_dir = TASKS_DIR / task.name
    task_dir.mkdir(exist_ok=True)

    try:
        task_details = fetch_challenge_detail(session, task.id)
        file_urls: list = task_details.get('files')
    except requests.exceptions.RequestException as e:
        error(f"Failed to fetch challenge details for {task.name}: {e}")
        return

    if not file_urls:
        info(f"Task '{task.name}' has no files to download.")
        return

    info(f"Downloading {len(file_urls)} files for challenge '{task.name}'...")
    for url in file_urls:
        full_url = urljoin(CTFD_URL, url)
        try:
            response = session.get(full_url, allow_redirects=True, stream=True)
            response.raise_for_status()

            if "content-disposition" in response.headers:
                header = response.headers["content-disposition"]
                filename = header.split("filename=")[1].strip('"')
            else:
                filename = unquote(url.split("/")[-1])

            file_path = task_dir / filename
            size = 0

            with open(file_path, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if not chunk:
                        continue
                    size += len(chunk)
                    if size > MAX_ATTACHMENT_SIZE:
                        error(f"{task.name}: Aborting download '{filename}': size > {MAX_ATTACHMENT_SIZE} MB")
                        return 1
                    f.write(chunk)

            info(f"Downloaded '{filename}' ({size} bytes) to '{file_path}'")

        except requests.exceptions.RequestException as e:
            error(f"Failed to download {full_url}: {e}")
            return 1
    return 0


def download_new_tasks():
    basicConfig(level="INFO", format="%(asctime)s - %(levelname)s - %(message)s")
    print("Downloading tasks …", flush=True)

    TASKS_DIR.mkdir(parents=True, exist_ok=True)

    existing_tasks = read_entries(DB_PATH)
    existing_ids = {task.id for task in existing_tasks}
    info(f"Existing tasks: {len(existing_tasks)}")

    session = create_session()
    if not session:
        error("Failed to log in. Check your credentials and CTFd URL.")
        return

    tasks = fetch_tasks(session)
    if not tasks:
        info("No tasks found on the platform.")
        return

    new_tasks_count = 0
    for task in tasks:
        if task.id in existing_ids:
            continue
        if task.status == "solved":
            info(f"Already solved, skipping: {task.name}")
            continue

        new_tasks_count += 1
        info(f"Processing new task: {task.name}")

        if download_task_files(task, session):
            continue

        print(task, flush=1)
        create_entry(**asdict(task))
        info(f"Added {task.name}")

    if new_tasks_count > 0:
        info(f"New tasks added: {new_tasks_count}")
    else:
        info("No new tasks to add")


def main():
    basicConfig(level=INFO, format="%(levelname)s: %(message)s", force=True)
    download_new_tasks()
