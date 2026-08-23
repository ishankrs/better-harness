from __future__ import annotations

import os
import tempfile

try:
    os.getcwd()
except OSError:
    os.chdir(tempfile.gettempdir())

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from . import runner, ui
from .redact import redact_tree
from .spec import SpecError, load_task

app = typer.Typer(add_completion=False, help="SwarmHarness — Docker-isolated, provider-agnostic agent evals")
console = Console()


@app.command()
def create(
    task_name: str = typer.Argument(..., help="new task folder name"),
    path: Path = typer.Option(Path("."), "--path", help="parent directory for the new task folder"),
) -> None:
    """Scaffold a new task: runnable verifier + passing oracle solution included."""
    from .scaffold import create_task
    from .spec import SpecError

    try:
        target = create_task(task_name, path)
    except SpecError as exc:
        console.print(f"[red]cannot create:[/] {exc}")
        raise typer.Exit(1)
    rel = "\n".join(
        f"  {p.relative_to(target)}" for p in sorted(target.rglob("*")) if p.is_file()
    )
    console.print(f"[green]created[/] {target}\n{rel}")
    console.print("\nNext steps:")
    console.print("  1. edit instruction.md (and tests/verify.py to grade it)")
    console.print(f"  2. [bold]swarm oracle {target}[/]  — must stay PASSED while you iterate")
    console.print(f"  3. [bold]swarm run {target} --mode single -m <model-id>[/]")


@app.command()
def validate(task: Path = typer.Argument(..., exists=True, file_okay=False)) -> None:
    """Validate a task folder without running anything."""
    try:
        spec = load_task(task)
    except SpecError as exc:
        console.print(f"[red]invalid:[/] {exc}")
        raise typer.Exit(1)
    table = Table(show_header=False)
    table.add_row("name", spec.name)
    table.add_row("model", spec.model)
    table.add_row("sub_tasks", str(len(spec.sub_tasks)) or "-")
    table.add_row("internet", f"{spec.internet_mode}" + (" · " + ", ".join(spec.net_egress) if spec.net_egress else ""))
    table.add_row("limits", f"{spec.cpus} cpu / {spec.memory_mb} MB")
    table.add_row(
        "timeouts",
        f"build={spec.build_timeout_sec}s agent={spec.agent_timeout_sec}s verifier={spec.verifier_timeout_sec}s",
    )
    console.print(table)
    console.print("[green]OK[/]")


@app.command()
def run(
    task: Path = typer.Argument(..., exists=True, file_okay=False),
    mode: str = typer.Option("multi", "--mode", help="single | multi"),
    keep: bool = typer.Option(False, "--keep", help="keep containers/volumes after the run"),
    model: str = typer.Option(None, "-m", "--model", help="override the task's model id for this run (recorded in run.json)"),
) -> None:
    """Run a task end-to-end: build, execute agent, verify fail-closed, write manifest."""
    if mode not in {"single", "multi"}:
        raise typer.Exit("--mode must be single or multi")
    try:
        spec = load_task(task)
    except SpecError as exc:
        console.print(f"[red]invalid task:[/] {exc}")
        raise typer.Exit(1)
    try:
        result = runner.run_task(spec, mode=mode, keep=keep, console=console, model_override=model)
    except (SpecError, RuntimeError) as exc:
        console.print(f"[red]run failed:[/] {exc}")
        raise typer.Exit(1)
    ui.print_run_summary(console, result)


@app.command()
def oracle(
    task: Path = typer.Argument(..., exists=True, file_okay=False),
    threshold: float = typer.Option(None, "--threshold", help="minimum passing score (default: task.yaml oracle.threshold, else 1.0)"),
    keep: bool = typer.Option(False, "--keep"),
) -> None:
    """Opt-in reference-solution check: runs solution/solve.sh in the sandbox and
    verifies it scores >= threshold through the real verifier. Never required for
    normal runs."""
    try:
        spec = load_task(task)
    except SpecError as exc:
        console.print(f"[red]invalid task:[/] {exc}")
        raise typer.Exit(1)
    if not spec.solution_script:
        console.print(f"[red]no solution/solve.sh in {spec.root} — oracle mode is optional[/]")
        raise typer.Exit(1)
    try:
        result = runner.run_oracle(spec, keep=keep, threshold=threshold, console=console)
    except (SpecError, RuntimeError) as exc:
        console.print(f"[red]oracle run failed:[/] {exc}")
        raise typer.Exit(1)
    ui.print_oracle_summary(console, result)
    raise typer.Exit(0 if result.passed else 1)


@app.command()
def redact(path: Path = typer.Argument(..., exists=True)) -> None:
    """Scrub known secret patterns from all files under PATH (in place)."""
    count = redact_tree(path)
    console.print(f"redacted {count} occurrence(s) under {path}")


if __name__ == "__main__":
    app()
