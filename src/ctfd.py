#!/usr/bin/env python3

import re
from urllib.parse import unquote, urljoin

import requests

from src import db
from src import *


def login(session: requests.Session) -> bool:
    if not TEAM_EMAIL or not TEAM_PASSWORD:
        error("AI_TEAM_EMAIL/AI_TEAM_PASSWORD must be set for submissions")
        return False
    try:
        token = fetch_csrf_token(session, CTFD_LOGIN_API)
    except Exception as exc:
        warning("login CSRF fetch failed: %s", exc)
        return False
    payload = {
        "name": TEAM_EMAIL,
        "username" : TEAM_EMAIL,
        "password": TEAM_PASSWORD,
        "nonce": token,
    }
    debug(session.headers)
    debug(session.cookies)
    resp = session.post(urljoin(CTFD_URL, CTFD_LOGIN_API), data=payload)
    body = resp.text.lower()
    if resp.status_code == 403 or "cf-turnstile" in body:
        error("login blocked by Cloudflare.")
        return False
    if resp.status_code >= 400 or "invalid username or password" in body:
        error(f"Login failed: {resp.status_code} {resp.headers} {body}")
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
    endpoint = urljoin(CTFD_URL + CTFD_SUBMIT_API, CTFD_SUBMIT_PATH)
    payload = {"submission": flag, "challenge_id": challenge_id}
    csrf_token = session.cookies.get("csrf_token")
    if not csrf_token:
        try:
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
        error(f"submission failed: HTTP {resp.status_code}")
        return False
    try:
        payload = resp.json()
    except ValueError:
        error("submission failed: invalid JSON response")
        return False
    success, data = payload.get("success"), payload.get("data")
    if success:
        if data.get("status") == "correct":
            info("server accepted flag for challenge %s", challenge_id)
            return True
        elif "already solved" in data.get('message'):
            info("already solved")
            return True
        else:
            error(f"submission failed: {data.get('message')}")
            return False
    if "already solved" in data.get('message'):
            info("already solved")
            return True

    error(f"submission failed: {payload}")
    return False


def fetch_csrf_token(session: requests.Session, path: str) -> str:
    if SKIP_FETCH_CSRF:
        return ""

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
                name=task[CTFD_JSON_FORMAT["name"]],
                timestamp=now(),
                status="solved" if task[CTFD_JSON_FORMAT["solved"]] else "queued",
                points=task[CTFD_JSON_FORMAT["points"]],
                tokens=0,
                solves=task[CTFD_JSON_FORMAT["solves"]] if CTFD_JSON_FORMAT["solves"] else 0,
                category=task[CTFD_JSON_FORMAT["category"]] if CTFD_JSON_FORMAT["category"] else "",
            )
            for task in tasks
        ]

        return tasks

    except (requests.RequestException, ValueError) as e:
        error(f"Failed to fetch tasks: {e}")
        return []


def fetch_task_details(session: requests.Session, task_id: str) -> str | None:
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


def download_task_files(task: Task, session: requests.Session) -> int:
    task_dir = TASKS_DIR / task.name

    try:
        task_details = fetch_task_details(session, task.id)
        files = list(task_details.get(CTFD_FILES_JSON))  # file["id"]
    except requests.exceptions.RequestException as e:
        error(f"{task.name}: Failed to fetch challenge details: {e}")
        return -1

    task_info = asdict(task)
    task_info["description"] = task_details.get("description", "")

    task_dir.mkdir(exist_ok=True)
    task_json_path = task_dir / "task.json"
    with open(task_json_path, "w") as f:
        json.dump(task_info, f, indent=4, sort_keys=True, ensure_ascii=False)


    if not files:
        return 0

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

            info(f"\tDownloading {file_path}")
            with open(file_path, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if not chunk:
                        continue
                    size += len(chunk)
                    if size > MAX_ATTACHMENT_SIZE * 1024 * 1024:
                        error(f"\t{task.name}: Aborting download '{filename}': size > {MAX_ATTACHMENT_SIZE} MB")
                        return -1
                    f.write(chunk)


        except requests.exceptions.RequestException as e:
            error(f"\tFailed to download {full_url}: {e}")
            return -1
    return 0


def download_new_tasks():

    TASKS_DIR.mkdir(parents=True, exist_ok=True)

    existing_tasks = db.read_entries(DB_PATH)
    existing_ids = {task.id for task in existing_tasks}
    info(f"Already downloaded tasks: {len(existing_tasks)}")
    info("Downloading tasks")

    session = create_session()
    if not session:
        error("Failed to log in. Check your credentials and CTFd URL.")
        return

    tasks = fetch_tasks(session)
    if not tasks:
        error("No tasks found on the platform.")
        return

    new_tasks_count = 0
    for task in tasks:
        if task.id in existing_ids:
            continue

        if download_task_files(task, session):
            continue

        db.insert_entry(**asdict(task))

        if task.status == "solved":
            info(f"{task.name}: Already solved")
            continue

        new_tasks_count += 1
        info(f"\tAdded {task.name}")


    if new_tasks_count > 0:
        info(f"New tasks added: {new_tasks_count}")
    else:
        info("No new tasks to add")


def start_instance(session: requests.Session, task_id: str) -> bool:
    session.headers.update({"Content-Type": "application/json",
                            "CSRF-Token": fetch_csrf_token(session, "/challenges")
                            })

    endpoint = urljoin(CTFD_URL, f"/plugins/ctfd-owl/container?challenge_id={task_id}")

    resp = session.post(endpoint)
    answ = resp.json()
    debug(f"OWL POST response: {answ}")

    if not answ["success"]:
        debug(f"Failed to POST instance: HTTP {resp.status_code}: {resp.text}")
        if "Frequency limit" in answ["msg"]:
            exception(f"ctfd_owl frequency limit: {answ}")
            return False
        if "You have boot" in answ["msg"]:
            info(f"Stopping previously running OWL instance: {answ["msg"].split()[2:-3]}")
            stop_instance(session)
            return start_instance(session, task_id)
        elif not answ["success"]:
            error(f"Some OWL error: {answ}")

    resp = session.get(endpoint)
    debug(f"GET response: {resp.json()}")
    if not resp.json()["success"]:
        debug(f"Failed to GET instance: HTTP {resp.status_code}: {resp.text}")
        return False
    if resp.json() == {"success": True} or not resp.json()["success"]:
        return False
    return True


def stop_instance(session: requests.Session) -> bool:
    endpoint = urljoin(CTFD_URL, f"/plugins/ctfd-owl/container")
    resp = session.delete(endpoint)
    if resp.status_code != 200:
        warning(f"Failed to DELETE instance, status code: {resp.status_code}")
        return False
    debug(f"DELETE response: {resp.json()}")
    return True


def main():
    download_new_tasks()


if __name__ == "__main__":
    main()

