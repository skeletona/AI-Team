# AI_Team
Fully automated CTF team

## Autonomous downloader

`autonomous_ctfd.py` logs in as `AI-Team` (configurable via env vars) and
downloads every challenge attachment smaller than 10 MiB.

## Configuration
1. Install dependencies with `pip install -r requirements.txt`.
2. Change `.env` next to the script with `AI_TEAM_EMAIL=` (or `EMAIL=`) and
   optionally `AI_TEAM_PASSWORD=`/`TEAM_PASSWORD=`. If you omit the password, the
   script generates a new one and prints it before attempting registration.
3. Run `python autonomous_ctfd.py` (set `CTFD_URL`/`TEAM_NAME` for other hosts).
4. Attachments land under `downloads/`.

If login/registration hits bot protection (HTTP 403/Turnstile) or the site keeps
showing the login form after the POST (Turnstile markup is still present), the
script logs a short directive that you must open `CTFD_URL/login` (or `/register`)
in a browser, solve the challenge with the same credentials (the password is
printed when it is auto-generated), and rerun once the account exists.

When the challenge API returns 403 because the account still isn’t part of any
team, the script calls `POST /api/v1/teams` to create a team entry for the current
user and retries the download automatically.

## How it works
- `extract_tasks.py` logins and downloads tasks from ctfd api
- `run_codex` starts a codex window for every task
- `serve_stats.py` starts a flask webserver on http://localhost:8000 to see statistics of AI-Team
