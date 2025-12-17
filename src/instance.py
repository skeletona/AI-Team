#!/usr/bin/env python

import re
import threading
from urllib.parse import urljoin
import requests
from sys import argv, exit


CTFD_URL = "https://ctfd.infosec.moscow"
TEAM_NAME = "AI"
TEAM_EMAIL = "skeletohan@yandex.ru"
TEAM_PASSWORD = "hUF3Qq#hwgF?Fn7"
CTFD_HEADERS = {
        "User-Agent": (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko)"
            " Chrome/120 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Content-Type": "application/x-www-form-urlencoded",
    }

def login(session: requests.Session) -> bool:
    global CTFD_HEADERS
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
        print("login blocked by Turnstile/firewall")
        return False
    if resp.status_code >= 400 or "invalid username or password" in body:
        print("login failed (status %s)", resp.status_code)
        return False

    CTFD_HEADERS["CSRF-Token"] = token
    return is_logged_in(session)


def is_logged_in(session: requests.Session) -> bool:
    resp = session.get(
        urljoin(CTFD_URL, "/api/v1/users/me"),
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
    if not login(session):
        exit(1)
    return session


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


def request_instance(session: requests.Session, task_id: str, command: str) -> dict:
    endpoint = urljoin(CTFD_URL, f"/plugins/ctfd-owl/container?challenge_id={task_id}")
    headers = CTFD_HEADERS
    headers["Content-Type"] = "application/json"
    headers["CSRF-Token"] = fetch_csrf_token(session, "/login")

    if command == "start":
        resp = session.post(endpoint, headers=headers)
        if resp.status_code != 200:
            print(f"Failed to run instance, status code: {resp.status_code}\n{resp.text}")
            return False

        resp = session.get(endpoint, headers=headers)
        if resp.status_code != 200:
            print(f"Failed to get instance link, status code: {resp.status_code}\n{resp.text}")
            return False

    elif command == "info":
        resp = session.get(endpoint, headers=headers)
        if resp.status_code != 200:
            print(f"Failed to get instance link, status code: {resp.status_code}\n{resp.text}")
            return False
    
    elif command == "stop":
        resp = session.delete(endpoint, headers=headers)
        if resp.status_code != 200:
            print(f"Failed to stop instance, status code: {resp.status_code}\n{resp.text}")
            return False

    elif command == "renew":
        resp = session.patch(endpoint, headers=headers)
        if resp.status_code != 200:
            print(f"Failed to renew instance, status code: {resp.status_code}\n{resp.text}")
            return False
    
    if resp.json() == {'success': True}:
        return "instance is not running"
    return resp.json()


def main():
    argv[2] = argv[2].lower()
    if not argv[1] or not argv[2] or argv[2] not in ("start", "info", "stop", "renew"):
        print("Usage: instance {num} [start / info / stop / renew]")
        return

    session = create_session()
    print(request_instance(session, argv[1], argv[2]))


if __name__ == "__main__":
    main()
