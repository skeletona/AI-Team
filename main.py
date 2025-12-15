#!/usr/bin/env python3
from __future__ import annotations

try:
    from src import *
    from typing import Optional
    import subprocess
    import shutil
    import sys
    import typer
    import signal

except ModuleNotFoundError as e:
    print("Run pip install -r requirements.txt\n")
    raise e


ROOT = Path(__file__).resolve().parent

path = os.environ.get("PATH", "")
if ROOT not in path.split(os.pathsep):
    os.environ["PATH"] = str(ROOT) + path

app = typer.Typer(help = "AI-Team",
                  context_settings = {"help_option_names": ["-h", "--help"]},
                  no_args_is_help = True,
                  pretty_exceptions_enable=True,
                  pretty_exceptions_short=True,)

website_app = typer.Typer(help="Website", no_args_is_help = True)
app.add_typer(website_app, name="website")
codex_app = typer.Typer(help="Codex", no_args_is_help = True)
app.add_typer(codex_app, name="codex")

@app.command("run")
def run(
    clean_tasks: bool = typer.Option(False,     "--clean-tasks",    help="Clean tasks before run"),
    clean_codex: bool = typer.Option(False,      "--clean-codex",     help="Clean codex thoughts before run"),
    clean_logs: bool = typer.Option(False,      "--clean-logs",     help="Clean logs  before run"),
    clean_database: bool = typer.Option(False,  "--clean-stats",    help="Clean database before run"),
    no_download: bool = typer.Option(False,     "--no-download",    help="No downloading"),
    no_website: bool = typer.Option(False,      "--no-website",     help="No website"),
    no_codex: bool = typer.Option(False,        "--no-codex",       help="No Codex"),
    attach_website: bool = typer.Option(False,  "--attach_website", "-aw", help="Attach to website"),
    attach_codex: bool = typer.Option(False,    "--attach_codex",   "-ac", help="Attach to codex"),
):
    """
    Run AI-Team
    """
    if clean_tasks:
        run_clean(tasks=True)
    if clean_codex:
        run_clean(codex=True)
    if clean_logs:
        run_clean(logs=True)
    if clean_database:
        run_clean(database=True)

    if not no_download:
        run_download()
    if not no_website:
        start_website(attach_website)
    if not no_codex:
        start_codex(attach_codex)


@app.command("download")
def run_download():
    """
    Only Download
    """
    typer.echo("Downloading tasks …")
    if download.main() != 0:
        raise typer.Exit(code=1)
        typer.echo("[download] done")


@codex_app.command("start")
def start_codex(
        attach: bool = typer.Option(False, "--attach", "-a", help="Attach to Codex runner logs"),
):
    """
        Start Codex runner
    """
    start_background(["-m", "src.codex"], name="codex", attach=attach)


@codex_app.command("stop")
def stop_codex():
    """
        Stop Codex runner
    """
    stop_backgroud(name="codex")


@website_app.command("start")
def start_website(
        attach: bool = typer.Option(False, "--attach", "-a", help="Attach to flask logs"),
):
    """
        Start website
    """
    start_background(["-m", "src.website"], name="website", log="flask.log", attach=attach)
    

@website_app.command("stop")
def stop_website(
):
    """
        Stop website
    """
    
    stop_background(name="website")


@app.command("clean", no_args_is_help=True)
def run_clean(
    all: bool = typer.Option(False, "--all", "-a", help="Clean all"),
    tasks: bool = typer.Option(False, "--tasks", help="Clean tasks folder"),
    codex: bool = typer.Option(False, "--codex", help="Clean codex thoughts"),
    logs: bool = typer.Option(False, "--logs", help="Clean logs"),
    database: bool = typer.Option(False, "--database", help="Clean Database"),
):
    """
        Cleaning
    """
    if tasks or all:
        shutil.rmtree(TASKS_DIR, ignore_errors=True)
        typer.echo(f"Deleted tasks directory: {TASKS_DIR}")

    if logs or all:
        shutil.rmtree(LOGS_DIR, ignore_errors=True)
        typer.echo(f"Deleted logs directory: {LOGS_DIR}")

    if database or all:
        try:
            os.remove(DB_PATH)
            typer.echo(f"Deleted: {DB_PATH}")
        except Exception as e:
            typer.echo(f"Error: {e}")


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


def start_background(command: list, name: str, log: str = "", attach: bool = False) -> int:
    os.makedirs(LOGS_DIR, exist_ok=True)

    if log:
        log_path = LOGS_DIR / log
    else:
        log_path = LOGS_DIR / f"{name}.log"

    pid_file = LOGS_DIR / Path(name + ".pid")

    if pid_file.exists():
        typer.echo(f"{name} is already running".capitalize())
        return 0

    if attach:
        typer.echo("Attaching to " + name)
        with log_path.open("a", encoding="utf-8") as f:
            p = subprocess.Popen(
                [sys.executable] + command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                start_new_session=True,
            )
            with p.stdout:
                for line in p.stdout:
                    f.write(line)
                    f.flush()
                    typer.echo(line, nl=False)
            p.wait()
    else:
        with log_path.open("a", encoding="utf-8") as f:
            p = subprocess.Popen(
                [sys.executable] + command,
                stdout=f,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )

    with pid_file.open("w") as f_pid:
        f_pid.write(str(p.pid))

    typer.echo(f"{name} started in background.".capitalize())
    return 0


def stop_background(name: str) -> None:
    pid_file = LOGS_DIR / name
    if pid_file.exists():
        with open(pid_file, "r") as f_pid:
            pid = int(f_pid.read())

        try:
            os.killpg(pid, signal.SIGTERM)
            pid_file.unlink()
            typer.echo(f"{name} stopped".capitalize())
        except ProcessLookupError:
            typer.echo(f"No {name} process found")
            pid_file.unlink()
        except Exception as e:
            typer.echo(f"Error stopping {name}: {e}")
            raise typer.Exit(code=1)
    else:
        typer.echo(f"{name} is not running!".capitalize())


def main() -> None:
    app()


if __name__ == "__main__":
    main()
