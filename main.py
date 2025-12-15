#!/usr/bin/env python3
from __future__ import annotations

try:
    from src import *
    from typing import Optional
    import shutil
    import sys
    import typer

except ModuleNotFoundError as e:
    print("Run pip install -r requirements.txt\n")
    raise e


ROOT = Path(__file__).resolve().parent

app = typer.Typer(help = "AI-Team",
                  context_settings = {"help_option_names": ["-h", "--help"]},
                  no_args_is_help = True,
                  add_completion = False,
                  pretty_exceptions_enable=True,
                  pretty_exceptions_short=True,)


@app.command()
def run(
    clean_tasks: bool = typer.Option(False,     "--clean-tasks",    help="Clean tasks before run"),
    clean_logs: bool = typer.Option(False,  "--clean-logs", help="Clean logs  before run"),
    clean_database: bool = typer.Option(False,     "--clean-stats",    help="Clean database before run"),
    no_download: bool = typer.Option(False,   "--no-download",  help="No downloading"),
    no_website: bool = typer.Option(False,      "--no-website",     help="No website"),
    no_codex: bool = typer.Option(False,        "--no-codex",       help="No Codex"),
):
    """
    Run AI-Team
    """
    if clean_tasks:
        clean(tasks=True)
    if clean_logs:
        clean(logs=True)
    if clean_database:
        clean(database=True)

    if not no_download:
        download()
    if not no_website:
        website()
    if not no_codex:
        codex()


@app.command()
def codex():
    """
        Run Codex without website
    """
    run_codex.main()
    typer.echo("Codex worker finished")


@app.command()
def website():
    """
        Run website
    """
    try:
        typer.echo("Starting website …")
        run_website.main()
    except KeyboardInterrupt:
        typer.echo(f"\nShutting down …")
    finally:
        typer.echo("Program stopeed!")


@app.command(no_args_is_help=True)
def clean(
    all: bool = typer.Option(False, "--all", help="Delete all"),
    tasks: bool = typer.Option(False, "--tasks", help="Delete TASKS_DIR"),
    logs: bool = typer.Option(False, "--logs", help="Delete LOGS_DIR"),
    database: bool = typer.Option(False, "--database", help="Delete Database"),
):
    """
    Delete something
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


@app.command()
def download() -> None:
    """
    Скачать или обновить задачи (extract_tasks.py).
    """
    typer.echo("[download] running extract_tasks.py …")
    if run_download.main() != 0:
        raise typer.Exit(code=1)
    typer.echo("[download] done")


@app.command()
def summarize() -> None:
    """
    Собрать контекст из старых логов.
    """
    typer.echo("[summarize] running summarize_logs.py …")
    try:
        if summarize_logs_main([]) != 0:
            raise typer.Exit(code=1)
    except typer.Exit:
        typer.echo("[summarize] summarize_logs.py exited non-zero, ignoring")
    else:
        typer.echo("[summarize] done")


@app.command()
def serve(
    host: str = typer.Option(
        "127.0.0.1",
        "--host",
        help="Адрес для веб-интерфейса",
        show_default=True,
    ),
    port: int = typer.Option(
        5000,
        "--port",
        help="Порт для веб-интерфейса",
        show_default=True,
    ),
) -> None:
    """
    Запустить веб-интерфейс (serve_stats.py).
    """
    typer.echo(f"[serve] starting web UI on http://{host}:{port} …")
    os.environ["STATS_HOST"] = host
    os.environ["STATS_PORT"] = str(port)
    serve_stats_main()


def main() -> None:
    app()


if __name__ == "__main__":
    main()
