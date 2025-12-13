#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import signal
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional


def run_checked(cmd: list[str], cwd: Path) -> None:
    proc = subprocess.run(cmd, cwd=cwd, env=os.environ.copy())
    if proc.returncode != 0:
        raise SystemExit(proc.returncode)


def start_background(cmd: list[str], cwd: Path) -> subprocess.Popen:
    return subprocess.Popen(cmd, cwd=cwd, env=os.environ.copy())


def terminate_process(proc: Optional[subprocess.Popen], timeout: float = 3.0) -> None:
    if not proc:
        return
    if proc.poll() is not None:
        return
    try:
        proc.terminate()
        proc.wait(timeout=timeout)
        return
    except Exception:
        pass
    try:
        proc.kill()
    except Exception:
        return


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run extract_tasks.py, then serve_stats.py, then run_codex.py"
    )
    parser.add_argument(
        "--clean-tasks",
        action="store_true",
        help="delete tasks/ before starting (forces re-download)",
    )
    parser.add_argument(
        "--clean-thinking",
        action="store_true",
        help="delete thinking_logs/ before starting",
    )
    parser.add_argument(
        "--clean-stats",
        action="store_true",
        help="delete codex_stats.jsonl before starting",
    )
    parser.add_argument("--skip-download", action="store_true", help="skip extract_tasks.py")
    parser.add_argument("--skip-serve", action="store_true", help="skip serve_stats.py")
    parser.add_argument("--skip-run", action="store_true", help="skip run_codex.py")
    parser.add_argument(
        "--serve-wait",
        type=float,
        default=0.75,
        help="seconds to wait after starting serve_stats.py",
    )
    args = parser.parse_args(argv)

    root = Path(__file__).resolve().parent
    python = sys.executable or "python"

    server_proc: Optional[subprocess.Popen] = None

    def handle_signal(signum: int, _frame) -> None:
        terminate_process(server_proc)
        raise SystemExit(128 + signum)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    try:
        if args.clean_tasks:
            shutil.rmtree(root / "tasks", ignore_errors=True)
        if args.clean_thinking:
            shutil.rmtree(root / "thinking_logs", ignore_errors=True)
        if args.clean_stats:
            try:
                (root / "codex_stats.jsonl").unlink()
            except FileNotFoundError:
                pass

        if not args.skip_download:
            run_checked([python, "extract_tasks.py"], cwd=root)

        # If we have previous logs, summarize them into tasks/<task>/codex_context.txt
        # so Codex can continue rather than starting from zero.
        try:
            run_checked([python, "summarize_logs.py"], cwd=root)
        except SystemExit:
            pass

        if not args.skip_serve:
            server_proc = start_background([python, "serve_stats.py"], cwd=root)
            time.sleep(max(0.0, args.serve_wait))

        if not args.skip_run:
            run_checked([python, "run_codex.py"], cwd=root)
    finally:
        terminate_process(server_proc)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
