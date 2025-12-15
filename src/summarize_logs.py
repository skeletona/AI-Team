#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
from pathlib import Path


def read_text(path: Path, limit: int = 120_000) -> str:
    try:
        data = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    if len(data) <= limit:
        return data
    return data[:limit] + "\n\n[truncated]"


def summarize_thinking(text: str) -> str:
    lines = [ln.rstrip() for ln in (text or "").splitlines()]
    lines = [ln for ln in lines if ln.strip()]
    if not lines:
        return ""

    omitted = 0
    kept = []
    for ln in lines:
        if ln.startswith("[omitted noisy line"):
            omitted += 1
            continue
        kept.append(ln)
    lines = kept

    commands = []
    for ln in lines:
        if ln.startswith("/usr/bin/") or ln.startswith("$ ") or ln.startswith("bash -lc") or ln.startswith("python -"):
            commands.append(ln)
    commands = commands[-30:]

    key = []
    for ln in lines:
        low = ln.lower()
        if "flag" in low or "submission" in low or "correct" in low or "incorrect" in low:
            key.append(ln)
        elif "succeeded" in low or "failed" in low or "error" in low:
            key.append(ln)
    key = key[-40:]

    out = []
    out.append("Summary of previous Codex attempts")
    out.append("")
    out.append(f"- Total lines: {len(lines)}" + (f" (+{omitted} noisy omitted)" if omitted else ""))
    if key:
        out.append("- Key events (tail):")
        out.extend([f"  {ln}" for ln in key[-20:]])
    if commands:
        out.append("- Recent commands (tail):")
        out.extend([f"  {ln}" for ln in commands])
    out.append("")
    out.append("Continue from the last meaningful step above. Avoid repeating already-tried commands unless you change approach.")
    return "\n".join(out).strip() + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Summarize thinking_logs into per-task codex_context.txt")
    parser.add_argument("--tasks-root", default=os.environ.get("TASKS_ROOT", "tasks"))
    parser.add_argument("--logs-root", default=os.environ.get("THINKING_LOGS_DIR", "thinking_logs"))
    args = parser.parse_args(argv)

    tasks_root = Path(args.tasks_root)
    logs_root = Path(args.logs_root)
    if not tasks_root.exists():
        return 0
    for task_dir in sorted(p for p in tasks_root.iterdir() if p.is_dir()):
        log_path = logs_root / task_dir.name / "thinking.log"
        if not log_path.exists():
            continue
        summary = summarize_thinking(read_text(log_path))
        if not summary:
            continue
        context_path = task_dir / "codex_context.txt"
        try:
            context_path.write_text(summary, encoding="utf-8")
        except OSError:
            continue
    return 0


def summarize_logs_main():
    raise SystemExit(main())


if __name__ == "__main__":
    summarize_logs_main()

