#!/usr/bin/env python3

from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Mapping, Optional, Set
from urllib.parse import urljoin
from time import time
from stats_db import insert_entry
import requests
from dotenv import load_dotenv

import ctfd

load_dotenv()

DB_PATH = Path(os.environ.get("DB_PATH", "codex_stats.db"))
CTFD_URL = os.environ.get("CTFD_URL", "https://play.nitectf25.live").rstrip("/")
DOWNLOAD_ROOT = Path(os.environ.get("DOWNLOAD_ROOT", "tasks"))
MAX_ATTACHMENT_BYTES = int(os.environ.get("MAX_ATTACHMENT_BYTES", 10 * 1024 * 1024))
TARGET_POINTS = int(os.environ.get("TARGET_POINTS"))
STATS_PATH = Path(os.environ.get("STATS_PATH", "codex_stats.db"))

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
    metadata_path.write_text(json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8")


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
            safe = sanitize_component(challenge.get("name"), str(challenge.get("id")))
            print(f"[  skipped  ] {safe:<28} pts={challenge.get('value'):<3} != TARGET_POINTS", flush=True)
            continue
        challenge_id = int(challenge.get("id") or 0)
        if challenge_id in solved_ids:
            safe = sanitize_component(challenge.get("name"), str(challenge_id))
            print(f"[  skipped  ] {safe:<28} pts={TARGET_POINTS:<3} solved", flush=True)

            insert_entry(challenge_id, "done", safe, flag="")

            continue
        detail = ctfd.fetch_challenge_detail(session, challenge_id)
        if detail:
            challenge = {**challenge, **detail}

        safe_name = sanitize_component(challenge.get("name"), f"challenge-{challenge.get('id')}")
        folder = DOWNLOAD_ROOT / safe_name
        existing_metadata_path = folder / "metadata.json"
        if existing_metadata_path.exists():
            # Never delete "touched" folders: they may contain useful Codex context.
            print(f"[  skipped  ] {safe_name:<28} pts={TARGET_POINTS:<3} already downloaded", flush=True)
            insert_entry(challenge_id, "queued", safe_name)
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
        insert_entry(challenge_id, "queued", safe_name)
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
        print(f"[{'  download ':<10}] {safe_name:<28} pts={points:<3} files={attachments_count}", flush=True)


def create_team_record(session: requests.Session) -> bool:
    try:
        csrf = ctfd.fetch_csrf_token(session, "/")
    except RuntimeError as exc:
        logging.warning("could not read CSRF token for team record: %s", exc)
        csrf = ""
    payload = {
        "name": ctfd.TEAM_NAME,
        "password": ctfd.TEAM_PASSWORD,
        "email": ctfd.TEAM_EMAIL,
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
        logging.info("created team record for %s", ctfd.TEAM_NAME)
        return True
    logging.warning("could not create team record (status %s)", resp.status_code)
    return False


def ensure_team_membership(session: requests.Session) -> None:
    resp = session.get(
        urljoin(CTFD_URL, "/api/v1/teams/me"),
        headers={"Accept": "application/json", **DEFAULT_HEADERS},
    )
    if resp.status_code == 200:
        return
    logging.info("team membership missing (%s); trying to create a record", resp.status_code)
    create_team_record(session)


def main() -> int:
    verbose = os.environ.get("VERBOSE", "").strip().lower() in {"1", "true", "yes", "y"}
    logging.basicConfig(level=logging.INFO if verbose else logging.WARNING, format="%(levelname)s: %(message)s")

    session = ctfd.create_session()
    if not session:
        logging.error("failed to create CTFd session")
        return 1

    ensure_team_membership(session)
    solved_ids = ctfd.fetch_solved_challenge_ids(session)
    if solved_ids:
        logging.debug("found %d solved challenge(s); will skip them", len(solved_ids))

    try:
        download_challenges(session, solved_ids)
    except requests.HTTPError as exc:
        if exc.response.status_code == 403:
            logging.info("challenge API blocked (HTTP 403); retrying after ensuring team membership")
            ensure_team_membership(session)
            solved_ids = ctfd.fetch_solved_challenge_ids(session)
            download_challenges(session, solved_ids)
        else:
            raise
    return 0


def extract_tasks_main():
    raise SystemExit(main())


if __name__ == "__main__":
    extract_tasks_main()
