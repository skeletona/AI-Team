#!/usr/bin/env python3

from __future__ import annotations

import json
import logging
import os
import re
import secrets
import string
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional, Set
from urllib.parse import urljoin

import requests
from dotenv import load_dotenv

load_dotenv()

CTFD_URL = os.environ.get("CTFD_URL", "https://play.nitectf25.live").rstrip("/")
TEAM_NAME = os.environ.get("AI_TEAM_NAME", os.environ.get("AI_TEAM_NAME", "AI-Team"))
TEAM_EMAIL = os.environ.get("AI_TEAM_EMAIL", os.environ.get("TEAM_EMAIL"))
TEAM_PASSWORD = os.environ.get("AI_TEAM_PASSWORD", os.environ.get("TEAM_PASSWORD"))
DOWNLOAD_ROOT = Path(os.environ.get("DOWNLOAD_ROOT", "tasks"))
MAX_ATTACHMENT_BYTES = int(os.environ.get("MAX_ATTACHMENT_BYTES", 10 * 1024 * 1024))
TARGET_POINTS = int(os.environ.get("TARGET_POINTS", "50"))

DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko)"
        " Chrome/120 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}


def sanitize_component(value: Optional[str], fallback: str) -> str:
    if not value:
        return fallback
    clean = re.sub(r"[^A-Za-z0-9._-]+", "_", value)
    return clean.strip("_") or fallback


def summarize_description(description: str, limit: int = 120) -> str:
    normalized = " ".join(description.replace("\n", " ").split())
    if len(normalized) <= limit:
        return normalized
    return normalized[: limit - 3].rstrip() + "..."


def generate_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


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


def is_logged_in(session: requests.Session) -> bool:
    resp = session.get(
        urljoin(CTFD_URL, "/api/v1/users/me"),
        headers={"Accept": "application/json", **DEFAULT_HEADERS},
        allow_redirects=False,
    )
    if resp.status_code != 200:
        return False
    try:
        data = resp.json()
    except ValueError:
        return False
    return bool(data.get("data"))


def login(session: requests.Session, email: str, password: str) -> bool:
    try:
        token = fetch_csrf_token(session, "/login")
    except Exception as exc:
        logging.warning("could not retrieve login CSRF token: %s", exc)
        return False
    payload = {
        "name": TEAM_NAME,
        "email": email,
        "password": password,
        "nonce": token,
    }
    resp = session.post(urljoin(CTFD_URL, "/login"), data=payload, headers=DEFAULT_HEADERS)
    body = resp.text.lower()
    if resp.status_code == 403 or "cf-turnstile" in body:
        logging.error(
            "turnstile/firewall blocked login; open %s/login, solve it with %s/%s, and rerun",
            CTFD_URL,
            email,
            password,
        )
        return False
    if "invalid username or password" in body or resp.status_code >= 400:
        logging.info("login response indicates invalid credentials (status %s)", resp.status_code)
        return False
    return is_logged_in(session)


def register(session: requests.Session, email: str, password: str) -> bool:
    try:
        token = fetch_csrf_token(session, "/register")
    except Exception as exc:
        logging.warning("could not retrieve registration CSRF token: %s", exc)
        return False
    payload = {
        "name": TEAM_NAME,
        "email": email,
        "password": password,
        "nonce": token,
        "cf-turnstile-response": "",
    }
    resp = session.post(urljoin(CTFD_URL, "/register"), data=payload, headers=DEFAULT_HEADERS)
    body = resp.text.lower()
    if resp.status_code == 403 or "cf-turnstile" in body:
        logging.error(
            "turnstile blocked registration; open %s/register, solve it with %s/%s, and rerun",
            CTFD_URL,
            email,
            password,
        )
        return False
    if resp.status_code >= 400:
        logging.warning("registration returned HTTP %s", resp.status_code)
        return False
    logging.info("registration submitted; remember to confirm any emailed link if required")
    return True


def download_file(session: requests.Session, url: str, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() and destination.stat().st_size:
        logging.info("skipping %s (already present)", destination)
        return
    resp = session.get(url, headers={"Accept": "*/*", **DEFAULT_HEADERS}, stream=True)
    resp.raise_for_status()
    total = 0
    try:
        with destination.open("wb") as fh:
            for chunk in resp.iter_content(8192):
                if not chunk:
                    continue
                total += len(chunk)
                if total > MAX_ATTACHMENT_BYTES:
                    raise RuntimeError("download exceeds %d bytes" % MAX_ATTACHMENT_BYTES)
                fh.write(chunk)
    except Exception:
        try:
            destination.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    logging.info("downloaded %s (%.2f KiB)", destination, destination.stat().st_size / 1024)


def persist_challenge_metadata(challenge: Mapping[str, Any], destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    files = []
    for item in challenge.get("files") or []:
        if isinstance(item, Mapping):
            files.append(
                {
                    "id": item.get("id"),
                    "name": item.get("name"),
                    "url": item.get("url"),
                    "size": item.get("size"),
                }
            )
        elif isinstance(item, str):
            files.append({"url": item})
    metadata = {
        "id": challenge.get("id"),
        "name": challenge.get("name"),
        "value": challenge.get("value"),
        "category": challenge.get("category"),
        "tags": challenge.get("tags"),
        "description": challenge.get("description"),
        "connection_info": challenge.get("connection_info"),
        "files": files,
    }
    metadata_path = destination / "metadata.json"
    metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")



def fetch_challenge_detail(session: requests.Session, challenge_id: int) -> Mapping[str, Any]:
    resp = session.get(
        urljoin(CTFD_URL, f"/api/v1/challenges/{challenge_id}"),
        headers={"Accept": "application/json", **DEFAULT_HEADERS},
    )
    resp.raise_for_status()
    payload = resp.json()
    return payload.get("data") if isinstance(payload, dict) else {}

def fetch_solved_challenge_ids(session: requests.Session) -> Set[int]:
    endpoints = [
        "/api/v1/teams/me/solves",
        "/api/v1/users/me/solves",
    ]
    solved: Set[int] = set()
    for path in endpoints:
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
                cid_int = int(cid)
            except (TypeError, ValueError):
                continue
            solved.add(cid_int)
        if solved:
            break
    return solved


def download_challenges(session: requests.Session, solved_ids: Set[int]) -> None:
    resp = session.get(
        urljoin(CTFD_URL, "/api/v1/challenges"),
        headers={"Accept": "application/json", **DEFAULT_HEADERS},
    )
    resp.raise_for_status()
    payload = resp.json()
    entries = payload.get("data") if isinstance(payload, dict) else []
    if not entries:
        logging.warning("no challenges returned by %s/api/v1/challenges", CTFD_URL)
        return
    for challenge in entries:
        if int(challenge.get("value") or 0) != TARGET_POINTS:
            continue
        challenge_id = int(challenge.get("id") or 0)
        if challenge_id in solved_ids:
            safe = sanitize_component(challenge.get("name"), str(challenge_id))
            print(f"[skipped   ] {safe:<28} pts={TARGET_POINTS:<3} solved", flush=True)
            continue
        detail = fetch_challenge_detail(session, challenge_id)
        if detail:
            challenge = {**challenge, **detail}

        safe_name = sanitize_component(challenge.get("name"), f"challenge-{challenge.get('id')}")
        folder = DOWNLOAD_ROOT / safe_name
        existing_metadata_path = folder / "metadata.json"
        if existing_metadata_path.exists():
            # Never delete "touched" folders: they may contain useful Codex context.
            print(f"[skipped   ] {safe_name:<28} pts={TARGET_POINTS:<3} already-downloaded", flush=True)
            continue

        files = challenge.get("files") or []
        too_large = []
        for attachment in files:
            if not isinstance(attachment, Mapping):
                continue
            if (attachment.get("size") or 0) > MAX_ATTACHMENT_BYTES:
                too_large.append(attachment)
        if too_large:
            logging.info(
                "skipping %s (%s points): attachment(s) exceed %.2f MiB",
                challenge.get("name") or challenge.get("id"),
                challenge.get("value"),
                MAX_ATTACHMENT_BYTES / (1024 * 1024),
            )
            continue
        persist_challenge_metadata(challenge, folder)
        attachment_names: list[str] = []
        for attachment in challenge.get("files") or []:
            if isinstance(attachment, Mapping):
                att_name = attachment.get("name") or str(attachment.get("id"))
                att_size = attachment.get("size", 0) or 0
                att_url = attachment.get("url") or ""
                filename = sanitize_component(att_name, f"file-{attachment.get('id')}")
                if att_size > MAX_ATTACHMENT_BYTES:
                    logging.debug(
                        "skipping %s (size %.2f MiB exceeds %.2f MiB)",
                        att_name,
                        att_size / (1024 * 1024),
                        MAX_ATTACHMENT_BYTES / (1024 * 1024),
                    )
                    continue
            elif isinstance(attachment, str):
                att_url = attachment
                att_name = attachment.rsplit("/", 1)[-1] or "attachment"
                filename = sanitize_component(att_name, "attachment")
            else:
                continue

            attachment_names.append(att_name)
            dest = folder / filename
            file_url = urljoin(CTFD_URL, att_url)
            try:
                download_file(session, file_url, dest)
            except Exception as exc:
                logging.warning("failed to download %s: %s", att_name, exc)
        points = int(challenge.get("value") or 0)
        attachments_count = len(challenge.get("files") or [])
        print(f"[{'downloaded':<10}] {safe_name:<28} pts={points:<3} files={attachments_count}", flush=True)


def create_team_record(session: requests.Session, password: str) -> bool:
    try:
        csrf = fetch_csrf_token(session, "/")
    except RuntimeError as exc:
        logging.warning("could not read CSRF token for team record: %s", exc)
        csrf = ""
    payload = {
        "name": TEAM_NAME,
        "password": password,
        "email": TEAM_EMAIL,
        "affiliation": os.environ.get("TEAM_AFFILIATION", ""),
        "website": os.environ.get("TEAM_WEBSITE", ""),
        "country": os.environ.get("TEAM_COUNTRY", ""),
        "description": os.environ.get("TEAM_DESCRIPTION", ""),
    }
    headers = {
        **DEFAULT_HEADERS,
        "Content-Type": "application/json",
        "X-Requested-With": "XMLHttpRequest",
    }
    if csrf:
        headers["X-CSRFToken"] = csrf
    resp = session.post(
        urljoin(CTFD_URL, "/api/v1/teams"), headers=headers, data=json.dumps(payload)
    )
    if resp.status_code in (200, 201):
        logging.info("created team record for %s", TEAM_NAME)
        return True
    logging.warning("could not create team record (status %s)", resp.status_code)
    return False


def ensure_team_membership(session: requests.Session, password: str) -> None:
    resp = session.get(
        urljoin(CTFD_URL, "/api/v1/teams/me"),
        headers={"Accept": "application/json", **DEFAULT_HEADERS},
    )
    if resp.status_code == 200:
        return
    logging.info("team membership missing (%s); trying to create a record", resp.status_code)
    create_team_record(session, password)


def main() -> int:
    verbose = os.environ.get("VERBOSE", "").strip().lower() in {"1", "true", "yes", "y"}
    logging.basicConfig(level=logging.INFO if verbose else logging.WARNING, format="%(levelname)s: %(message)s")
    if not TEAM_EMAIL:
        logging.error("EMAIL/AI_TEAM_EMAIL must be set via .env or the environment")
        return 1
    password = TEAM_PASSWORD or generate_password()
    if not TEAM_PASSWORD:
        print(f"Generated password for {TEAM_NAME}: {password}")
    session = requests.Session()
    session.headers.update(DEFAULT_HEADERS)

    if not login(session, TEAM_EMAIL, password):
        logging.info("login failed; attempting to register %s", TEAM_NAME)
        if not register(session, TEAM_EMAIL, password):
            return 1
        if not login(session, TEAM_EMAIL, password):
            logging.error("could not log in after registering")
            return 1

    ensure_team_membership(session, password)
    solved_ids = fetch_solved_challenge_ids(session)
    if solved_ids:
        logging.debug("found %d solved challenge(s); will skip them", len(solved_ids))

    try:
        download_challenges(session, solved_ids)
    except requests.HTTPError as exc:
        if exc.response.status_code == 403:
            logging.info("challenge API blocked (HTTP 403); retrying after ensuring team membership")
            ensure_team_membership(session, password)
            solved_ids = fetch_solved_challenge_ids(session)
            download_challenges(session, solved_ids)
        else:
            raise
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
