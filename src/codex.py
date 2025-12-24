#!/usr/bin/env python3

from src.models import *
from src import db, ctfd

from random import shuffle
import re
import concurrent.futures
from shutil import copy


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
CODEX_TASK_FILTER = os.environ.get("CODEX_TASK")


def strip_ansi(text: str) -> str:
    return re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)


def is_container_running() -> bool:
    try:
        result = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", "AI-Team"],
            capture_output=True,
            text=True
        )
        if result.stdout.strip() != "true":
            subprocess.run(["docker", "compose", "up", "--build", "-d"])
            result = subprocess.run(
                ["docker", "inspect", "-f", "{{.State.Running}}", "AI-Team"],
                capture_output=True,
                text=True
            )
            if result.stdout.strip() != "true":
                error("could not run docker container")
                exit(1)

        result = subprocess.run(
                ["docker", "exec", "-it", "AI-Team", "curl", "--max-time", "10", CTFD_URL],
                capture_output=True,
                text=True
        )
        if result.returncode:
            error("Could not curl CTFd inside docker. Maybe you are using VPN and youre MTU does not match?")
    except Exception as e:
        error(f"Could not run docker container: {e}")
        exit(1)


def run_codex(task: Task, prompt: str) -> str:
    is_container_running()

    command = ["docker", "exec", "-it", "AI-Team"] + CODEX_COMMAND + ["-C", f"/tasks/{task.name}"] + [prompt]
    completed_normally = False
    output = ""
    stop_flag = CODEX_DIR / task.name / "stop.flag"

    task.log.parent.mkdir(parents=True, exist_ok=True)
    with task.log.open("w", encoding="utf-8") as fh:
        proc = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            start_new_session=True,
        )
        RUNNING_CODEX[task.id] = proc

        lines: list[str] = []
        try:
            assert proc.stdout is not None
            for line in proc.stdout:
                if stop_flag.exists():
                    info(f"{task.name}: stop flag detected, terminating")
                    proc.send_signal(signal.SIGTERM)
                    proc.wait(timeout=5)
                    break
                if len(line) > 1000:
                    line = line[:1000] + "    [truncated]"
                fh.write(line)
                if MAX_CODEX_WORKERS == 1 or ENABLE_DEBUG:
                    print(line.rstrip("\r\n"), flush=True)
                fh.flush()
                lines.append(line)
            proc.wait(timeout=CODEX_TIMEOUT)
            if proc.returncode:
                error(f"Codex returned an error code: {proc.returncode}")
        except KeyboardInterrupt:
            info("Shutting down ...")
            proc.send_signal(signal.SIGTERM)
            return -1
        except Exception as e:
            exception(f"Some error running codex: {e}")
            proc.kill()
            proc.wait(timeout=5)
        finally:
            RUNNING_CODEX.pop(task.id, None)

    if not output:
        output = "".join(lines)
    return output


def build_codex_prompt(task: Task, instance: bool) -> str:
    context_path = TASKS_DIR / task.name / "codex_context.txt"
    if context_path.exists():
        context = context_path.read_text(encoding="utf-8", errors="replace").strip()
    else:
        context = ""

    parts = list(CODEX_PROMPT)
    if instance:
        parts += CODEX_OWL_PROMPT
    if context:
        parts.extend([
                "Previous attempts summary (continue from here, do not repeat work):",
                context,
            ]
        )
    return "\n".join(parts)


def mark_all_running_failed(reason: str = "marked as failed") -> None:
    entries = db.read_entries(DB_PATH)
    for task in entries:
        if entry.status == "running":
            task = db.change_task(task, "failed", reason)


def process_task(task: Task) -> int:
    """Give MAX_CODEX_ATTEMPTS attempts for one task"""
    info(f"{task.name}: starting")
    session = ctfd.create_session()
    stop_flag = CODEX_DIR / task.name / "stop.flag"

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
            task = db.change_task(task, "failed", "login failed")
            return 1
    elif task.id in [t.id for t in ctfd.fetch_tasks(session) if t.status == "solved"]:
        task = db.change_task(task, "solved", "solved by a human")
        info(f"{task.name}: Solved while queued, skipping")
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
            if stop_flag.exists():
                info(f"{task.name}: stop flag detected, exiting")
                return

            info(f"{task.name}: Running codex ({attempt})")
            task = db.change_task(task, "running", attempt=attempt, error="")

            output = run_codex(task, prompt)

            result = inspect_output(session, task, output)
            if result != 0 or output == -1:
                debug("stopping codex ...")
                break
            
            prompt = prompt + "\n".join([
                "\n\nThis is incorrect flag."
                " Keep working and print the correct final flag."
            ])
        else:
            warning(f"max attempts reached for {task.name}")
            task = db.change_task(task, "failed", "max attempts reached")
    except Exception as e:
        error(f"Some error: {e}")
        exception(e)
    finally:
        if instance:
            ctfd.stop_instance(session)


def inspect_output(session, task, output) -> int:
    """ search for things in codex logs
        -1 -> error, 0 -> no valid flags, 1 -> valid flag    
    """
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
                task = db.change_task(task, tokens=tokens)
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
    

    if not flags:
        info(f"{task.name}: No flags found")
    for flag in reversed(flags):
        if ctfd.submit_flag(session, task.id, flag):
            task = db.change_task(task, "solved", flag=flag, error="")
            info(f"{task.name}: Successfull flag found: {flag}")
            return 1
        else:
            info(f"{task.name}: Incorrect flag found: {flag}")

    return 0


def run_tasks():
    """Orchestrator of parralel processes"""
    if not TASKS_DIR.exists():
        error(f"task directory does not exist: {TASKS_DIR}")
        return 1

    graceful_exit = False
    active: set[concurrent.futures.Future] = set()
    future_to_task: dict[concurrent.futures.Future, Task] = {}

    executor = concurrent.futures.ThreadPoolExecutor(max_workers=MAX_CODEX_WORKERS)
    try:
        while True:
            entries = db.read_entries(DB_PATH)
            if CODEX_TASK_FILTER:
                matching = [task for task in entries if task.name == CODEX_TASK_FILTER]
                if not matching:
                    error(f"No task found with name: {CODEX_TASK_FILTER}")
                    return 1
                if any(task.status == "block" for task in matching):
                    info(f"{CODEX_TASK_FILTER}: blocked, exiting")
                    return 0
                if any(task.status == "solved" for task in matching):
                    info(f"{CODEX_TASK_FILTER}: already solved, exiting")
                    graceful_exit = True
                    return 0
                if all(task.status not in ("queued", "running") for task in matching):
                    for task in matching:
                        db.update_task_status(DB_PATH, task.id, "queued", error="")
                    info(f"{CODEX_TASK_FILTER}: forced to queued, continuing")
                entries = matching

            pending = [
                task for task in entries
                if task.status in ("queued", "running")
                and task.id not in [t.id for t in future_to_task.values()]
            ]
            if pending:
                shuffle(pending)
            while pending and len(active) < MAX_CODEX_WORKERS:
                task = pending.pop(0)
                fut = executor.submit(process_task, task)
                active.add(fut)
                future_to_task[fut] = task

            if not active:
                sleep(1)
                continue

            done, active = concurrent.futures.wait(
                active,
                timeout=1,
                return_when=concurrent.futures.FIRST_COMPLETED,
            )

            for f in done:
                task = future_to_task.pop(f)
                f.result()
                if CODEX_TASK_FILTER and task.name == CODEX_TASK_FILTER:
                    info(f"{CODEX_TASK_FILTER}: finished, exiting")
                    graceful_exit = True
                    return 0

    except KeyboardInterrupt:
        info("Stopping signal recieved")
    except Exception as e:
        error(f"Error running tasks: {e}")
    finally:
        for fut, task in future_to_task.items():
            fut.cancel()
            if fut in active and not graceful_exit:
                task = db.change_task(task, "failed", "interrupted")
        db.move_status(DB_PATH, "running", "failed")
        global STOP_EVENT
        STOP_EVENT = True
        for proc in RUNNING_CODEX.values():
            proc.kill()
        executor.shutdown(wait=True)
        info("Exited")


def main():
    if not LOGS_DIR.exists():
        debug(f"creating {LOGS_DIR}")
        LOGS_DIR.mkdir()
    if not CODEX_DIR.exists():
        debug(f"creating {CODEX_DIR}")
        CODEX_DIR.mkdir()


    codex_auth = LOGS_DIR / "codex" / "auth.json"
    if not codex_auth.exists():
        debug("copying codex auth.json")
        try:
            codex_auth.parent.mkdir(exist_ok=True)
            copy(Path("~/.codex/auth.json").expanduser(), codex_auth)
        except Exception as e:
            error(f"Could not get ~/.codex/auth.json: {e}")
            exit(1)
    

    if CTFD_OWL and MAX_CODEX_WORKERS > 1:
        error("CTFD OWL allows only 1 worker at a time. Disable CTFD OWL or set MAX_CODEX_WORKERS=1")
        exit(1)

    info(f"FLAG_REGEX: {FLAG_RE.pattern}")
    info("Starting Codex worker …")
    run_tasks()


if __name__ == "__main__":
    main()
