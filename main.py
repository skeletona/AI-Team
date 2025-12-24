#!/usr/bin/env python3

try:
    from sys import executable
    from shutil import rmtree
    import typer

    from src import *
    from src import codex, website, ctfd

except ModuleNotFoundError as e:
    print("Run pip install -r requirements.txt\n")
    raise e


ROOT = Path(__file__).resolve().parent
PROCS = dict()
GRACE_TIME = 5

path = os.environ.get("PATH", "")
if ROOT not in path.split(os.pathsep):
    os.environ["PATH"] = str(ROOT) + path

app = typer.Typer(help = "AI-Team",
                  context_settings = {"help_option_names": ["-h", "--help"]},
                  no_args_is_help = True,
                  pretty_exceptions_enable=True,
                  pretty_exceptions_short=True,)


@app.command("start")
@app.command("run", hidden=True)
def run(
    services: list[str] = typer.Argument(
        None,
        help="What to run: download website codex (default: all)",
    ),
    task: str | None = typer.Option(
        None,
        "--task",
        "-t",
        help="Run codex only for a specific task name",
    ),
    clean_lst: list[str] = typer.Option(
        None,
        "--clean",
        "-c",
        help="What to clean before run: tasks codex logs database all",
    ),
    attach_lst: list[str] = typer.Option(
        [],
        "--attach",
        "-a",
        help="What to attach to: website codex",
    ),
):
    """
    Run AI-Team
    """
    
    if clean:
        clean(clean_lst)

    if not services:
        services = ["download", "website", "codex"]
    if "download" in services:
        start_background("ctfd", attach=1)
    if "website" in services:
        start_background("website", log="flask.log", attach="website" in attach_lst)
    if "codex" in services:
        env_extra = {"CODEX_TASK": task} if task else None
        start_background("codex", attach="codex" in attach_lst, env_extra=env_extra)


@app.command("stop")
def stop(
    services: list[str] = typer.Argument(
        None,
        help="What to stop: website codex (default: all)",
    ),
):
    """
    Stop AI-Team
    """

    if not services:
        services = ["website", "codex"]

    if "website" in services:
        stop_background("website")
    if "codex" in services:
        stop_background("codex")


@app.command("restart")
@app.command("rerun", hidden=True)
def restart(
    services: list[str] = typer.Argument(
        None,
        help="What to restart: website codex (default: all)",
    ),
    attach_lst: list[str] = typer.Option(
        [],
        "--attach",
        "-a",
        help="What to attach to: website codex",
    ),
):
    """
    Restart AI-Team
    """

    if not services:
        services = ["website", "codex"]

    if "website" in services or "web in services":
        stop_background("website")
        if "website" in PROCS:
            del PROCS["website"]
        start_background("website", log="flask.log", attach="website" in attach_lst)
    if "codex" in services:
        stop_background("codex")
        if "codex" in PROCS:
            del PROCS["codex"]
        start_background("codex", attach="codex" in attach_lst)


@app.command("status")
def status(
    services: list[str] = typer.Argument(
        None,
        help="Services to show status for (e.g. website codex)",
    )
):
    """
    Show status
    """
    if not services:
        services = ["codex", "website"]

    
    for name in services:
        if name not in PROCS:
            info(f"{name}: not running".capitalize())
        else:
            info(f"{name}: running in background".capitalize())


@app.command("attach")
def attach(
    services: list[str] = typer.Argument(
        None,
        help="Services to show status for (e.g. website codex)",
    )
):
    """
    Attach to service
    """
    if not services:
        services = ["codex", "website"]

    for name in services:
        if name not in PROCS:
            warning(f"{name}: not running".capitalize())
        else:
            tail_f(PROCS[name]["log"])


@app.command("clean")
def clean(
    things: list[str] = typer.Argument(
        None,
        help="What to clean: tasks codex logs database (default: all)",
    ),
    force: bool = typer.Option(False, "--force", "-f", help="Do not ask for confirmation"),
):
    """
        Cleaning
    """
    if not things:
        return

    if "all" in things:
        if not force:
            confirm = input("Are you sure you want to DELETE ALL? [Y/N]: ")
            if confirm.lower() not in ["yes", "y"]:
                info("Did not confirm. Be careful!")
                return
        things = ["tasks", "codex", "logs", "database"]

    if "tasks" in things:
        rmtree(TASKS_DIR, ignore_errors=True)
        warning(f"Deleted tasks directory: {TASKS_DIR}")
    if "codex" in things:
        rmtree(CODEX_DIR, ignore_errors=True)
        warning(f"Deleted codex directory: {CODEX_DIR}")
    if "logs" in things:
        rmtree(LOGS_DIR, ignore_errors=True)
        warning(f"Deleted logs directory: {LOGS_DIR}")
    if "database" in things:
        os.remove(DB_PATH)
        warning(f"Deleted: {DB_PATH}")


@app.command("sql")
@app.command("database", hidden=True)
@app.command("db", hidden=True)
def sql():
    """
        Look in database
    """
    subprocess.run(
        ["sqlite3", DB_PATH, ".mode column", '''SELECT
            datetime(timestamp, 'unixepoch', 'localtime') AS timestamp,
            id,
            name,
            status,
            points,
            solves,
            category,
            flag,
            attempt,
            tokens,
            error
            FROM tasks
            ORDER BY timestamp;'''
         ])


@app.command("summarize")
def summarize():
    """
    Get short version of what codex has achieved
    """
    info("Running summarize_logs.py …")
    try:
        if summarize_logs_main([]) != 0:
            raise typer.Exit(code=1)
    except typer.Exit:
        info("[summarize] summarize_logs.py exited non-zero, ignoring")
    else:
        info("[summarize] done")


@app.command("download")
def download(
    clean_lst: list[str] = typer.Option(
        None,
        "--clean",
        "-c",
        help="What to clean before run: tasks codex logs database all",
    ),
):
    """
    Run the download service
    """
    run(services=["download"], clean_lst=clean_lst)

@app.command("website")
@app.command("web", hidden=True)
def website(
    clean_lst: list[str] = typer.Option(
        None,
        "--clean",
        "-c",
        help="What to clean before run: tasks codex logs database all",
    ),
    attach_lst: list[str] = typer.Option(
        [],
        "--attach",
        "-a",
        help="What to attach to: website codex",
    ),
):
    """
    Run the website service
    """
    run(services=["website"], clean_lst=clean_lst, attach_lst=attach_lst)


@app.command("codex")
def codex(
    clean_lst: list[str] = typer.Option(
        None,
        "--clean",
        "-c",
        help="What to clean before run: tasks codex logs database all",
    ),
    attach_lst: list[str] = typer.Option(
        [],
        "--attach",
        "-a",
        help="What to attach to: website codex",
    ),
):
    """
    Run the codex service
    """
    run(services=["codex"], clean_lst=clean_lst, attach_lst=attach_lst)


def start_background(
    name: str,
    log: str = "",
    attach: bool = False,
    env_extra: dict[str, str] | None = None,
) -> int:
    os.makedirs(LOGS_DIR, exist_ok=True)

    if log:
        log_path = LOGS_DIR / log
    else:
        log_path = LOGS_DIR / f"{name}.log"

    if name in PROCS:
        warning(f"{name}: can not run: already running")
        return 0

    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)

    if attach:
        info(f"{name}: attaching")
        with log_path.open("a", encoding="utf-8") as f:
            p = subprocess.Popen(
                [executable, "-m", "src." + name],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env=env,
                text=True,
                bufsize=1,
                start_new_session=True,
            )
            proc = Process(name=name, log=str(log_path), pid=p.pid)
            change_json(proc)
            try:
                with p.stdout:
                    for line in p.stdout:
                        f.write(line)
                        f.flush()
                        print(line, end="\r")
                p.wait()
            except KeyboardInterrupt:
                typer.echo()
                try:
                    p.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    p.terminate()
                    try:
                        p.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        p.kill()
            finally:
                change_json(proc, delete=True)

    else:
        info(f"{name}: Starting")
        with log_path.open("a", encoding="utf-8") as f:
            p = subprocess.Popen(
                [executable, "-m", "src." + name],
                stdout=f,
                stderr=subprocess.STDOUT,
                env=env,
                start_new_session=True,
            )
        change_json(Process(name=name, log=str(log_path), pid=p.pid))
        info(f"{name} started in background.".capitalize())
    return 0


def stop_background(name: str) -> None:
    if name not in PROCS:
        warning(f"{name}: not running. Cannot stop.")
        return

    proc = Process(**PROCS[name])

    try:
        os.killpg(proc.pid, SIGTERM)
        info(f"{name}: stopping (PID {proc.pid})")

        waited = 0
        while waited < GRACE_TIME:
            try:
                os.kill(proc.pid, 0)
            except ProcessLookupError:
                info(f"{name}: stopped")
                return
            sleep(0.5)
            waited += 0.5

        warning(f"{name}: did not exit gracefully in {GRACE_TIME} seconds. Killing.")
        os.killpg(proc.pid, SIGKILL)

    except ProcessLookupError:
        warning(f"No {name} process found")
    except Exception as e:
        error(f"{name}: error stopping {e}")
        raise typer.Exit(code=1)
    finally:
        change_json(proc, delete=True)


def change_json(proc: Process, delete: bool = False) -> None:
    global PROCS
    if not JSON_FILE.exists():
        with open(JSON_FILE, "w") as json_file:
            json.dump({"sus": "sas"}, json_file, indent=2)
        data: dict[str, Process] = {}
    else:
        data = json.loads(JSON_FILE.read_text(encoding="utf-8"))

    if delete:
        del data[proc.name]
    else:
        data[proc.name] = asdict(proc)

    with open(JSON_FILE, "w") as json_file:
        json.dump(data, json_file, indent=2)
    PROCS = data


def tail_f(path: str, sleep_time: float = 0.5):
    with open(path, "r", encoding="utf-8") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                sleep(sleep_time)
                continue
            print(line, end="")


if __name__ == "__main__":
    basicConfig(level=INFO, format="%(levelname)s: %(message)s", force=True)
    if JSON_FILE.exists():
        try:
            PROCS = json.loads(JSON_FILE.read_text(encoding="utf-8"))
        except Exception as e:
            error(f"Failed to load JSON: {e}")
            PROCS = dict()
        else:
            for proc in PROCS.values():
                try:
                    os.kill(proc["pid"], 0)
                except ProcessLookupError:
                    warning(f"{proc["name"]} is in JSON but not running")
                    change_json(Process(**proc), delete=True)
    else:
        PROCS = dict()

    app()
