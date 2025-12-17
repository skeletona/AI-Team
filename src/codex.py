#!/usr/bin/env python3

from src.models import *
from src import db, ctfd

from random import shuffle
import re
import concurrent.futures


STOP_EVENT = False
RUNNING_CODEX: dict[str: subprocess.Popen] = {}


def build_flag_regex(flag_regex: str | None, flag_format: str | None) -> re.Pattern:
    if flag_regex:
        try:
            flag_regex = re.compile(flag_regex)
        except re.error as exc:
            raise ValueError(f"FLAG_REGEX {flag_regex!r} is not a valid regex") from exc
    else:
        escaped_spec = re.escape(flag_format)
        placeholder = re.escape("{}")
        flag_regex = escaped_spec.replace(placeholder, r"\{[^}]{5,}+\}")
        try:
            flag_regex = re.compile(flag_regex)
        except re.error as exc:
            raise ValueError(f"FLAG_FORMAT {spec!r} is not a valid format. Example: testCTF{{}}") from exc
    
    return flag_regex


FLAG_RE = build_flag_regex(FLAG_REGEX, FLAG_FORMAT)


def strip_ansi(text: str) -> str:
    return re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)


def extract_thinking(output: str) -> str:
    clean = strip_ansi(output)
    lower = clean.lower()
    idx = lower.find("thinking")
    if idx == -1:
        return clean
    snippet = clean[idx:].splitlines()
    if snippet:
        snippet = snippet[1:]  # drop the 'thinking' label line
    return "\n".join(snippet).rstrip()


def run_codex(task: Task, prompt: str) -> str:
    command = CODEX_COMMAND + [prompt]
    completed_normally = False

    task.log.parent.mkdir(parents=True, exist_ok=True)
    
    with task.log.open("w", encoding="utf-8") as fh:
        proc = subprocess.Popen(
            command,
            cwd=TASKS_DIR / task.name,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        RUNNING_CODEX[task.id] = proc

        lines: list[str] = []
        try:
            assert proc.stdout is not None
            for line in proc.stdout:
                if len(line) > 1000:
                    line = line[:1000] + "[truncated]"
                fh.write(line)
                fh.flush()
                lines.append(line)
            proc.wait(timeout=CODEX_TIMEOUT)
        except Exception:
            exception(e)
            proc.kill()
            proc.wait(timeout=5)
        finally:
            RUNNING_CODEX.pop(task.id, None)

    output = "".join(lines)
    return output



def local_attachment_names(task: Task) -> list[str]:
    task_dir = TASKS_DIR / task.name
    return sorted(
        p.name
        for p in task_dir.iterdir()
        if p.is_file() and p.name != "metadata.json"
    )


def build_codex_prompt(task: Task, instance: bool) -> str:
    context_path = TASKS_DIR / task.name / "codex_context.txt"
    if context_path.exists():
        context = context_path.read_text(encoding="utf-8", errors="replace").strip()
    else:
        context = ""

    parts = CODEX_PROMPT
    if instance:
        parts += [f"Instance is available. Run instance {task.id} [command]",
                   "Possible commands: start, stop, info, renew",
                   "Do not stop instance before exiting."
        ]
    if context:
        parts.extend(
            [
                "Previous attempts summary (continue from here, do not repeat work):",
                context,
            ]
        )
    return "\n".join(parts)


def mark_all_running_failed(reason: str = "marked as failed") -> None:
    entries = db.read_entries(DB_PATH)
    for task in entries:
        if entry.status == "running":
            db.change_task(task, "failed", reason)


def process_task(task: Task) -> int:
    """Give MAX_CODEX_ATTEMPTS attempts for one task"""
    session = ctfd.create_session()

    task_dir = TASKS_DIR / task.name
    task_json_path = task_dir / "task.json"
    task_info = {}
    if task_json_path.exists():
        with open(task_json_path, 'r', encoding='utf-8') as f:
            task_info = json.load(f)

    is_docker_task = task_info.get("type") == "dynamic_check_docker"

    if not session:
        warning("could not login to CTFd; running without submissions", CTFD_URL)
        if is_docker_task:
            error("Cannot process docker task without a session.")
            db.change_task(task, "failed", "login failed")
            return 1
    elif task.id in [t.id for t in ctfd.fetch_tasks(session) if t.status == "solved"]:
        db.change_task(task, "solved", "solved by a human")
        info("skipping %s (%s): solved while queued", task.name, task.id)
        return 0

    instance = None
    try:
        if CTFD_OWL:
            instance = ctfd.start_instance(session, task.id)
            if instance:
                info(f"{task.name}: Has a ctfd_owl instance")

        prompt = build_codex_prompt(task, instance)
        start_attempt = int(str(task.log).split(".")[-1])

        for attempt in range(start_attempt + 1, start_attempt + MAX_CODEX_ATTEMPTS + 1):
            if STOP_EVENT:
                return

            info(f"{task.name}: Running codex ({attempt})")
            db.change_task(task, "running", attempt=attempt)

            output = run_codex(task, prompt)

            result = inspect_output(session, task, output)
            if result != 1:
                info(f"successfull flag found for {task.name}: {flag}")
                db.change_task(task, "done", flag=flag)
                break

            prompt = (
                prompt
                + "\n\nThis is incorrect flag."
                " Keep working and print ONLY the correct final flag."
            )
        else:
            warning(f"max attempts reached for {task.name}")
            db.change_task(task, "failed", "max attempts reached")
    except Exception as e:
        exception(e)
    finally:
        if instance:
            ctfd.stop_instance(session)


def inspect_output(session, task, output) -> int:
    """search for things in codex logs"""
    clean = strip_ansi(output)
    
    seen_tokens = False
    tokens = 0
    flags = []

    for line in clean.splitlines():
        if not seen_tokens:
            m = re.search(r"tokens used", line, flags=re.IGNORECASE)
            if m:
                seen_tokens = True
        else:
            try:
                tokens = int(line.replace(",", ""))
                info(f"{task.name}: tokens used: {tokens}")
                db.change_task(task, tokens=tokens)
            except:
                seen_tokens = False

        if "Access blocked" in line:
            error(f"{task.name}: Cannot connect to Codex servers (check your VPN)")
            return -1

        if "You've hit your usage limit" in line:
            error(f"{task.name}: You have reached your codex limit. Ai-Team can not continue.")
            raise KeyboardInterrupt
            return -1

        flag = FLAG_RE.search(line)
        if flag:
            flags.append(flag.group(0))

    for flag in reversed(flags):
        if ctfd.submit_flag(session, task.id, flag):
            return 1
        else:
            info(f"{task.name}: incorrect flag found: {flag}")

    return 0


def run_tasks():
    """Orchestrator of parralel processes"""
    if not TASKS_DIR.exists():
        error(f"task directory does not exist: {TASKS_DIR}")
        return 1

    pending: list[Task] = db.read_entries(DB_PATH)
    if not pending:
        error("no tasks in the database")
        return 1

    shuffle(pending)
    pending: list[Task] = list(pending)
    active: set[concurrent.futures.Future] = set()
    future_to_task: dict[concurrent.futures.Future, Task] = {}

    executor = concurrent.futures.ThreadPoolExecutor(max_workers=MAX_CODEX_WORKERS)
    try:
        while pending:
            while pending and len(active) < MAX_CODEX_WORKERS:
                task = pending.pop(0)
                fut = executor.submit(process_task, task)
                active.add(fut)
                future_to_task[fut] = task

            done, active = concurrent.futures.wait(active, return_when=concurrent.futures.FIRST_COMPLETED)

            for f in done:
                task = future_to_task.pop(f)
                f.result()

    except KeyboardInterrupt:
        info("Stopping signal recieved")
    finally:
        for fut, task in future_to_task.items():
            fut.cancel()
            if fut in active:
                db.change_task(task, "failed", "interrupted")
        db.move_status(DB_PATH, "running", "failed")
        global STOP_EVENT
        STOP_EVENT = True
        for proc in RUNNING_CODEX.values():
            proc.kill()
        executor.shutdown(wait=True)
        info("Exited")


def handle_sigterm(signum, frame):
    info("recieved SIGTERM")
    raise KeyboardInterrupt


def main():
    info(f"FLAG_REGEX: {FLAG_RE.pattern}")
    signal(SIGTERM, handle_sigterm)
    info("Starting Codex worker …")
    run_tasks()


if __name__ == "__main__":
    main()

