#!/usr/bin/env python3
from __future__ import annotations

try:
    import os
    import shutil
    import signal
    import sys
    import time
    from pathlib import Path
    from typing import Optional
    import multiprocessing

    import typer
    from dotenv import load_dotenv
except ModuleNotFoundError as e:
    print("Run pip install -r requirements.txt\n")
    raise e

from src.extract_tasks import main as extract_tasks_main
from src.summarize_logs import main as summarize_logs_main
from src.serve_stats import serve_stats_main
from src.run_codex import run_codex_main

load_dotenv()

ROOT = Path(__file__).resolve().parent

app = typer.Typer(help="AI-Team helper: задачи, веб-интерфейс и Codex-воркеры")


def terminate_process(proc: Optional[multiprocessing.Process], timeout: float = 3.0) -> None:
    if not proc or not proc.is_alive():
        return
    try:
        proc.terminate()
        proc.join(timeout=timeout)
        if proc.is_alive():
            proc.kill()
            proc.join()
    except Exception:
        pass


@app.command()
def clean(
    tasks: bool = typer.Option(
        False, "--tasks", help="Удалить каталог задач (TASKS_ROOT)"
    ),
    thinking: bool = typer.Option(
        False, "--thinking", help="Удалить каталог thinking_logs"
    ),
    stats: bool = typer.Option(
        False, "--stats", help="Удалить файл базы статистики (DB_PATH)"
    ),
) -> None:
    """
    Очистить задачи, логи и/или базу статистики.
    """
    tasks_root = Path(os.environ.get("TASKS_ROOT", "tasks"))
    thinking_root = Path(os.environ.get("THINKING_LOGS_DIR", "thinking_logs"))
    db_path = Path(os.environ.get("DB_PATH", "codex_stats.db"))

    if tasks:
        shutil.rmtree(ROOT / tasks_root, ignore_errors=True)
        typer.echo(f"[clean] removed tasks directory: {tasks_root}")

    if thinking:
        shutil.rmtree(ROOT / thinking_root, ignore_errors=True)
        typer.echo(f"[clean] removed thinking logs: {thinking_root}")

    if stats:
        try:
            (ROOT / db_path).unlink()
            typer.echo(f"[clean] removed stats db: {db_path}")
        except FileNotFoundError:
            typer.echo(f"[clean] stats db not found: {db_path}")


@app.command()
def download() -> None:
    """
    Скачать или обновить задачи (extract_tasks.py).
    """
    typer.echo("[download] running extract_tasks.py …")
    if extract_tasks_main() != 0:
        raise typer.Exit(code=1)
    typer.echo("[download] done")


@app.command()
def summarize() -> None:
    """
    Собрать контекст из старых логов (summarize_logs.py).
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


@app.command()
def run() -> None:
    """
    Запустить Codex-воркер (run_codex.py).
    """
    typer.echo("[run] starting Codex worker …")
    run_codex_main()
    typer.echo("[run] Codex worker finished")


@app.command("all")
def run_all(
    clean_tasks: bool = typer.Option(
        False, "--clean-tasks", help="Перед стартом удалить каталог задач"
    ),
    clean_thinking: bool = typer.Option(
        False, "--clean-thinking", help="Перед стартом удалить thinking_logs"
    ),
    clean_stats: bool = typer.Option(
        False, "--clean-stats", help="Перед стартом удалить базу статистики"
    ),
    skip_download: bool = typer.Option(
        False, "--skip-download", help="Не скачивать задачи (пропустить extract_tasks.py)"
    ),
    skip_serve: bool = typer.Option(
        False, "--skip-serve", help="Не запускать веб-интерфейс"
    ),
    skip_run: bool = typer.Option(
        False, "--skip-run", help="Не запускать Codex-воркер"
    ),
    serve_wait: float = typer.Option(
        0.75,
        "--serve-wait",
        help="Секунд подождать после запуска serve_stats.py перед Codex",
        show_default=True,
    ),
) -> None:
    """
    Полный цикл: (опционально) очистить, скачать задачи, собрать логи,
    запустить веб-интерфейс и Codex-воркер.
    """
    if clean_tasks:
        clean(tasks=True)
    if clean_thinking:
        clean(thinking=True)
    if clean_stats:
        clean(stats=True)

    if not skip_download:
        download()

    summarize()

    server_proc: Optional[multiprocessing.Process] = None

    def handle_signal(signum: int, _frame) -> None:
        typer.echo(f"\n[all] received signal {signum}, shutting down …")
        terminate_process(server_proc)
        raise typer.Exit(code=128 + signum)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    try:
        if not skip_serve:
            typer.echo("[all] starting web UI in background …")
            server_proc = multiprocessing.Process(target=serve_stats_main)
            server_proc.start()
            time.sleep(max(0.0, serve_wait))

        if not skip_run:
            run()
    finally:
        terminate_process(server_proc)
        typer.echo("[all] web UI stopped")


def main() -> None:
    app()


if __name__ == "__main__":
    main()