from typing import Any, Mapping, Optional, Sequence
from dotenv import load_dotenv
from urllib.parse import urljoin
import logging
import requests
import os
import re

load_dotenv()

CTFD_URL = os.environ.get("CTFD_URL").rstrip("/")
TEAM_NAME = os.environ.get("AI_TEAM_NAME")
TEAM_EMAIL = os.environ.get("AI_TEAM_EMAIL")
TEAM_PASSWORD = os.environ.get("AI_TEAM_PASSWORD")
DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko)"
        " Chrome/120 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}


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
