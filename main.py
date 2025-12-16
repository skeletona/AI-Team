#!/usr/bin/env python3
from __future__ import annotations

try:
    from signal import SIGTERM, SIGKILL
    from sys import executable
    from shutil import rmtree
    import subprocess
    import typer
    import json

    from src import *

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

@dataclass
class Process:
    name:       str
    pid:        int
    log:        Path




@app.command("run")
@app.command("start", hidden=True)
def run(
    services: list[str] = typer.Argument(
        None,
        help="What to run: download website codex (default: all)",
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
        if ctfd.main() != 0:
            raise typer.Exit(code=1)
            typer.echo("download done")
    if "website" in services:
        start_background(name="website", log="flask.log", attach="website" in attach_lst)
    if "codex" in services:
        start_background(name="codex", attach="codex" in attach_lst)


@app.command("status")
def status(
    services: list[str] = typer.Argument(
        None,
        help="Services to show status for (e.g. website codex)",
    )
):
    """
    Show status of services
    """
    if not services:
        services = ["codex", "website"]

    
    for name in services:
        if name not in PROCS:
            typer.echo(f"{name}: not running".capitalize())
        else:
            typer.echo(f"{name}: running in background".capitalize())


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
            typer.echo(f"{name} not running!".capitalize())
        else:
            tail_f(PROCS[name]["log"])


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

    if "website" in services:
        stop_background("website")
        if "website" in PROCS:
            del PROCS["website"]
        start_background(name="website", log="flask.log", attach="website" in attach_lst)
    if "codex" in services:
        stop_background("codex")
        if "codex" in PROCS:
            del PROCS["codex"]
        start_background(name="codex", attach="codex" in attach_lst)



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
                typer.echo("Did not confirm. Be careful!")
                return
        things = ["tasks", "codex", "logs", "database"]

    if "tasks" in things:
        rmtree(TASKS_DIR, ignore_errors=True)
        typer.echo(f"Deleted tasks directory: {TASKS_DIR}")
    if "codex" in things:
        rmtree(CODEX_DIR, ignore_errors=True)
        typer.echo(f"Deleted codex directory: {CODEX_DIR}")
    if "logs" in things:
        rmtree(LOGS_DIR, ignore_errors=True)
        typer.echo(f"Deleted logs directory: {LOGS_DIR}")
    if "database" in things:
        os.remove(DB_PATH)
        typer.echo(f"Deleted: {DB_PATH}")


@app.command("summarize")
def summarize():
    """
    Get short version of what codex has achieved
    """
    typer.echo("[summarize] running summarize_logs.py …")
    try:
        if summarize_logs_main([]) != 0:
            raise typer.Exit(code=1)
    except typer.Exit:
        typer.echo("[summarize] summarize_logs.py exited non-zero, ignoring")
    else:
        typer.echo("[summarize] done")


def start_background(name: str, log: str = "", attach: bool = False) -> int:
    os.makedirs(LOGS_DIR, exist_ok=True)

    if log:
        log_path = LOGS_DIR / log
    else:
        log_path = LOGS_DIR / f"{name}.log"

    if name in PROCS:
        typer.echo(f"{name} already running".capitalize())
        return 0

    if attach:
        typer.echo("Attaching to {name} …")
        with log_path.open("a", encoding="utf-8") as f:
            p = subprocess.Popen(
                [executable, "-m", "src." + name],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                start_new_session=True,
            )
            change_json(Process(name=name, log=str(log_path), pid=p.pid))
            with p.stdout:
                for line in p.stdout:
                    f.write(line)
                    f.flush()
                    typer.echo(line, nl=False)
            p.wait()
    else:
        typer.echo(f"Starting {name} …")
        with log_path.open("a", encoding="utf-8") as f:
            p = subprocess.Popen(
                [executable, "-m", "src." + name],
                stdout=f,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        change_json(Process(name=name, log=str(log_path), pid=p.pid))
        typer.echo(f"{name} started in background.".capitalize())
    return 0


def stop_background(name: str) -> None:
    if name not in PROCS:
        typer.echo(f"{name} not running!")
        return

    proc = Process(**PROCS[name])

    try:
        os.kill(proc.pid, SIGTERM)
        typer.echo(f"Stopping {name}")

        waited = 0
        while waited < GRACE_TIME:
            try:
                os.kill(proc.pid, 0)
            except ProcessLookupError:
                typer.echo(f"{name} stopped".capitalize())
                return
            sleep(0.5)
            waited += 0.5

        typer.echo(f"{name} did not exit gracefully in {GRACE_TIME} seconds. Killing.")
        os.kill(proc.pid, SIGKILL)

    except ProcessLookupError:
        typer.echo(f"No {name} process found")
    except Exception as e:
        typer.echo(f"Error stopping {name}: {e}")
        raise typer.Exit(code=1)
    finally:
        change_json(proc, delete=True)


def change_json(proc: Process, delete: bool = False) -> none:
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
    if JSON_FILE.exists():
        PROCS = json.loads(JSON_FILE.read_text(encoding="utf-8"))
    else:
        PROCS = dict()

    app()
