from typing import Any, Mapping, Optional, Sequence
from urllib.parse import urljoin
import requests
import re
from time import time
import threading

from src.models import *

SOLVED_LOCK = threading.Lock()
_SOLVED_CACHE = {}
SOLVED_CACHE_SECONDS = 60


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


def get_task_description_from_ctfd_url(
    session: requests.Session, url: str
) -> Optional[tuple[str, str]]:
    logging.info("found CTFd page: %s", url)
    # TODO: This doesn't seem to work
    m = re.match(r".*/challenges#(\w+)-(\d+)", url)
    if m:
        name, chall_id = m.groups()
        logging.info("extracting CTFd challenge %s (%s)", name, chall_id)
        try:
            detail = fetch_challenge_detail(session, int(chall_id))
            if detail:
                return detail["name"], f'{detail["name"]}\n\n{detail["description"]}'
        except Exception as exc:
            logging.warning("failed to fetch challenge detail: %s", exc)
    return None


def extract_tasks_from_ctfd(session: requests.Session, url: str, seen_tasks: set[str]) -> list[dict[str, Any]]:
    tasks = []
    logging.info("found CTFd, enumerating challenges")
    solved_ids = fetch_solved_challenge_ids(session)
    # This is not a great way to get challenges, but it's what we have
    for chall_id in range(1, 100):
        if chall_id in solved_ids:
            continue
        try:
            detail = fetch_challenge_detail(session, chall_id)
            if not detail:
                continue
            if detail["name"] in seen_tasks:
                continue
            logging.info("found task: %s", detail["name"])
            tasks.append(
                {
                    "name": detail["name"],
                    "description": f'{detail["name"]}\n\n{detail["description"]}',
                    "url": url,
                }
            )
            seen_tasks.add(detail["name"])
        except Exception as exc:
            logging.debug("failed to fetch challenge %s: %s", chall_id, exc)
    return tasks
