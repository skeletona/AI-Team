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
        "name": TEAM_EMAIL,
        "password": TEAM_PASSWORD,
        "nonce": token,
    }
    resp = session.post(urljoin(CTFD_URL, "/login"), data=payload)
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
        headers={"Accept": "application/json", **CTFD_HEADERS},
        allow_redirects=False,
    )
    if resp.status_code != 200:
        return False
    try:
        payload = resp.json()
    except ValueError:
        return False
    return bool(payload.get("data"))


def create_session() -> requests.Session | None:
    session = requests.Session()
    session.headers.update(CTFD_HEADERS)
    if CTFD_SKIP_LOGIN:
        info("Skipping login")
        return session
    if not login(session):
        return None
    return session


def submit_flag(session: requests.Session, challenge_id: str, flag: str) -> bool:
    endpoint = urljoin(CTFD_URL + CTFD_SUBMIT_API + challenge_id, CTFD_SUBMIT_PATH)
    payload = {"submission": flag, "challenge_id": challenge_id}
    csrf_token = session.cookies.get("csrf_token")
    if not csrf_token:
        try:
            info("re-fetching csrf token")
            csrf_token = fetch_csrf_token(session, "/challenges")
        except Exception as exc:
            warning("could not obtain CSRF token for submission: %s", exc)
    headers = {"X-Requested-With": "XMLHttpRequest", **CTFD_HEADERS}
    if csrf_token:
        headers["CSRF-Token"] = csrf_token
    headers["Referer"] = urljoin(CTFD_URL, "/challenges")
    resp = session.post(
        endpoint,
        json=payload,       # files=payload
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
    resp = session.get(url)
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
            urljoin(CTFD_URL, CTFD_TASKS_API),
            headers={"Accept": "application/json", **CTFD_HEADERS},
        )
        resp.raise_for_status()
        payload = resp.json()
        tasks: list = payload.get(CTFD_TASKS_JSON_LIST, [])

        tasks: list[Task] = [
            Task(
                id=task[CTFD_JSON_FORMAT["id"]],
                timestamp=now(),
                name=task[CTFD_JSON_FORMAT["name"]],
                status="queued",
                points=task[CTFD_JSON_FORMAT["points"]],
                solves=task[CTFD_JSON_FORMAT["solves"]] if CTFD_JSON_FORMAT["solves"] else 0,
                category=task[CTFD_JSON_FORMAT["category"]] if CTFD_JSON_FORMAT["category"] else "",
            )
            for task in tasks
        ]

        info(f"Fetched tasks: {len(tasks)}")
        return tasks

    except (requests.RequestException, ValueError) as e:
        error(f"Failed to fetch tasks: {e}")
        return []


def fetch_task_details(session: requests.Session, task_id: Any) -> str | None:
    resp = session.get(
        urljoin(CTFD_URL, CTFD_TASK_API + str(task_id)),
        headers={"Accept": "application/json", **CTFD_HEADERS},
    )
    resp.raise_for_status()
    payload = resp.json()
    if CTFD_TASK_DETAIL_LIST:
        return payload.get(CTFD_TASK_DETAIL_LIST) if isinstance(payload, dict) else {}
    else:
        return payload


#def get_download_uuid(session: requests.Session, challenge_id: str, file_id: int) -> str:
#    url = (
#        f"{CTFD_URL}{CTFD_TASK_API}{challenge_id}/download/{file_id}"
#    )
#    r = session.get(url)
#    r.raise_for_status()
#    data = r.json()
#    return data["data"]["uuid"]


def download_task_files(task: Task, session: requests.Session) -> int:
    task_dir = TASKS_DIR / task.name
    task_dir.mkdir(exist_ok=True)

    try:
        task_details = fetch_task_details(session, task.id)
        files = list(task_details.get(CTFD_FILES_JSON))  # file["id"]
    except requests.exceptions.RequestException as e:
        error(f"Failed to fetch challenge details: {task.name}: {e}")
        return

    task_info = asdict(task)
    task_info["description"] = task_details.get("description", "")

    task_json_path = task_dir / "task.json"
    with open(task_json_path, "w") as f:
        json.dump(task_info, f, indent=4, sort_keys=True, ensure_ascii=False)


    if not files:
        return

    info(f"Downloading {len(files)} files for challenge '{task.name}'...")
    for file in files:
        full_url = urljoin(CTFD_URL + CTFD_DOWNLOAD_API, file)  # uuid = get_download_uuid(session, task.id, file)
        try:
            response = session.get(full_url, allow_redirects=True, stream=True)
            response.raise_for_status()

            if "content-disposition" in response.headers:
                header = response.headers["content-disposition"]
                filename = header.split("filename=")[1].strip('"')
            else:
                filename = str(file)

            file_path = task_dir / filename
            size = 0

            with open(file_path, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if not chunk:
                        continue
                    size += len(chunk)
                    if size > MAX_ATTACHMENT_SIZE * 1024 * 1024:
                        error(f"{task.name}: Aborting download '{filename}': size > {MAX_ATTACHMENT_SIZE} MB")
                        return 1
                    f.write(chunk)

            info(f"Downloaded '{filename}' ({size} bytes) to '{file_path}'")

        except requests.exceptions.RequestException as e:
            error(f"Failed to download {full_url}: {e}")
            return 1
    return 0


def download_new_tasks():
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

        if download_task_files(task, session):
            continue

        create_entry(**asdict(task))
        info(f"Added {task.name}")

    if new_tasks_count > 0:
        info(f"New tasks added: {new_tasks_count}")
    else:
        info("No new tasks to add")

def launch_instance(session: requests.Session, task_id: str) -> str | None:
    """Launch an instance for a given task and return the connection URL."""
    endpoint = urljoin(CTFD_URL, f"/plugins/ctfd-owl/container?challenge_id={task_id}")
    resp = session.post(endpoint)
    if resp.status_code != 200:
        warning(f"Failed to launch instance for task {task_id}, status code: {resp.status_code}")
        return None
    try:
        data = resp.json()
        if data.get("success"):
            container_data = data.get("containers_data", [])
            if container_data:
                container = container_data[0]
                ip = data.get("ip")
                port = container.get("port")
                conntype = container.get("conntype", "http")
                if ip and port:
                    return f"{conntype}:{ip}:{port}"
        warning(f"Could not extract connection info from launch response for task {task_id}: {data}")
        return None
    except ValueError:
        warning(f"Failed to parse JSON response when launching instance for task {task_id}")
        return None

def get_instance_url(session: requests.Session, task_id: str) -> str | None:
    """Get the instance URL for a given task."""
    endpoint = urljoin(CTFD_URL, f"/plugins/ctfd-owl/container?challenge_id={task_id}")
    resp = session.get(endpoint)
    if resp.status_code != 200:
        warning(f"Failed to get instance url for task {task_id}, status code: {resp.status_code}")
        return None
    try:
        data = resp.json()
        if data.get("success"):
            container_data = data.get("containers_data", [])
            if container_data:
                container = container_data[0]
                ip = data.get("ip")
                port = container.get("port")
                conntype = container.get("conntype", "http")
                if ip and port:
                    return f"{conntype}:{ip}:{port}"
        return None # It's normal for there to be no instance if it hasn't been launched
    except ValueError:
        warning(f"Failed to parse JSON response when getting instance url for task {task_id}")
        return None

def delete_instance(session: requests.Session, task_id: str) -> bool:
    """Delete an instance for a given task."""
    endpoint = urljoin(CTFD_URL, f"/plugins/ctfd-owl/container?challenge_id={task_id}")
    resp = session.delete(endpoint)
    if resp.status_code != 200:
        warning(f"Failed to delete instance for task {task_id}, status code: {resp.status_code}")
        return False
    return True

def main():
    download_new_tasks()
