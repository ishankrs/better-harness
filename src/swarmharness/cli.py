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
    if spec.model:
        table.add_row("model", spec.model)
    if spec.judge_model:
        table.add_row("judge", spec.judge_model)
    if spec.judge_base_url:
        table.add_row("judge url", spec.judge_base_url)
    if spec.provider_npm:
        table.add_row("provider", spec.provider_npm)
    if spec.coordination_pattern:
        table.add_row("coordination", spec.coordination_pattern)
    if spec.tags:
        table.add_row("tags", ", ".join(spec.tags))
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
    judge_model: str = typer.Option(None, "--judge-model", help="model the verifier's LLM judge uses via the proxy (default: task.toml judge_model, else the run model)"),
    judge_base_url: str = typer.Option(None, "--judge-base-url", help="separate API root for the verifier judge; key via SWARM_JUDGE_API_KEY (else the agent key). Default: task.toml judge_base_url, else the run's base URL"),
    min_score: float = typer.Option(None, "--min-score", help="exit non-zero when the final score is below this threshold"),
) -> None:
    """Run a task end-to-end: build, execute agent, verify fail-closed, write manifest."""
    if mode not in {"single", "multi"}:
        raise typer.Exit("--mode must be single or multi")
    try:
        from .spec import validate_judge_base_url
        from .spec import validate_model_id as _validate_model

        spec = load_task(task)
        if model is not None:
            spec.model = _validate_model(model)
        if not spec.model:
            raise SpecError(
                "no model configured: set 'model' in task.toml or pass -m/--model"
            )
        if judge_model is not None:
            spec.judge_model = _validate_model(judge_model)
        if judge_base_url is not None:
            spec.judge_base_url = validate_judge_base_url(judge_base_url)
    except SpecError as exc:
        console.print(f"[red]invalid task:[/] {exc}")
        raise typer.Exit(1)
    try:
        result = runner.run_task(spec, mode=mode, keep=keep, console=console, model_override=None, judge_model_override=None)
    except (SpecError, RuntimeError) as exc:
        console.print(f"[red]run failed:[/] {exc}")
        raise typer.Exit(1)
    ui.print_run_summary(console, result)
    if min_score is not None and float(result.reward.get("score", 0.0)) < min_score:
        console.print(f"[yellow]score {result.reward.get('score')} below --min-score {min_score}[/]")
        raise typer.Exit(1)


@app.command()
def oracle(
    task: Path = typer.Argument(..., exists=True, file_okay=False),
    threshold: float = typer.Option(None, "--threshold", help="minimum passing score (default: task.yaml oracle.threshold, else 1.0)"),
    keep: bool = typer.Option(False, "--keep"),
    judge_model: str = typer.Option(None, "--judge-model", help="model the verifier's LLM judge uses via the proxy (default: task.toml judge_model, else the task model)"),
    judge_base_url: str = typer.Option(None, "--judge-base-url", help="separate API root for the verifier judge; key via SWARM_JUDGE_API_KEY (else the agent key). Default: task.toml judge_base_url, else the run's base URL"),
) -> None:
    """Opt-in reference-solution check: runs solution/solve.sh in the sandbox and
    verifies it scores >= threshold through the real verifier. Never required for
    normal runs."""
    try:
        spec = load_task(task)
        if judge_model is not None:
            from .spec import validate_model_id as _validate_model

            spec.judge_model = _validate_model(judge_model)
        if judge_base_url is not None:
            from .spec import validate_judge_base_url as _validate_judge_url

            spec.judge_base_url = _validate_judge_url(judge_base_url)
    except SpecError as exc:
        console.print(f"[red]invalid task:[/] {exc}")
        raise typer.Exit(1)
    if not spec.solution_script:
        console.print(f"[red]no solution/solve.sh in {spec.root} — oracle mode is optional[/]")
        raise typer.Exit(1)
    try:
        result = runner.run_oracle(spec, keep=keep, threshold=threshold, console=console, judge_model_override=None)
    except (SpecError, RuntimeError) as exc:
        console.print(f"[red]oracle run failed:[/] {exc}")
        raise typer.Exit(1)
    ui.print_oracle_summary(console, result)
    raise typer.Exit(0 if result.passed else 1)


@app.command()
def regrade(
    task: Path = typer.Argument(..., exists=True, file_okay=False),
    logs: Path = typer.Argument(..., exists=True, file_okay=False, help="agent_logs dir from a previous run"),
    keep: bool = typer.Option(False, "--keep"),
    judge_model: str = typer.Option(None, "--judge-model", help="model the verifier's LLM judge uses via the proxy (default: task.toml judge_model, else the task model)"),
    judge_base_url: str = typer.Option(None, "--judge-base-url", help="separate API root for the verifier judge; key via SWARM_JUDGE_API_KEY (else the agent key). Default: task.toml judge_base_url, else the run's base URL"),
) -> None:
    """Re-run ONLY the verifier over existing agent logs (e.g. the judge was
    down). Writes a fresh results/<id>-regrade/ record linking source_run —
    the original run.json is never modified, so this cannot re-mint a score."""
    try:
        spec = load_task(task)
    except SpecError as exc:
        console.print(f"[red]invalid task:[/] {exc}")
        raise typer.Exit(1)
    try:
        result = runner.regrade_task(spec, logs_src=logs, keep=keep, console=console,
                                     judge_model_override=judge_model,
                                     judge_base_url_override=judge_base_url)
    except (SpecError, RuntimeError) as exc:
        console.print(f"[red]regrade failed:[/] {exc}")
        raise typer.Exit(1)
    ui.print_run_summary(console, result)


@app.command()
def redact(path: Path = typer.Argument(..., exists=True)) -> None:
    """Scrub known secret patterns from all files under PATH (in place)."""
    count = redact_tree(path)
    console.print(f"redacted {count} occurrence(s) under {path}")


@app.command()
def cleanup(
    project: str = typer.Option(None, "--project", help="only remove objects for this compose project (prefix match)"),
    dry_run: bool = typer.Option(False, "--dry-run", help="list what would be removed without removing it"),
) -> None:
    """Remove stray swarm containers, networks and volumes (e.g. after Ctrl-C).

    Only touches names starting with 'swarm-'. Never touches images.
    Safe to run while another run is active if --project names the dead one.
    """
    import json
    import subprocess

    def _lines(*args: str) -> list[str]:
        try:
            out = subprocess.run(
                ["docker", *args], capture_output=True, text=True, timeout=60,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            console.print(f"[red]docker failed:[/] {exc}")
            raise typer.Exit(1)
        if out.returncode != 0:
            console.print(f"[red]docker failed:[/] {out.stderr.strip()[-500:]}")
            raise typer.Exit(1)
        return [ln for ln in out.stdout.splitlines() if ln.strip()]

    prefix = project or "swarm-"
    if not prefix.startswith("swarm-"):
        console.print("[red]refusing: --project must start with 'swarm-'[/]")
        raise typer.Exit(1)

    removed = 0
    containers = [
        json.loads(ln)["ID"]
        for ln in _lines("ps", "-a", "--filter", f"name={prefix}", "--format", "{{json .}}")
        if json.loads(ln).get("Names", "").startswith(prefix)
    ]
    networks = [
        ln for ln in _lines("network", "ls", "--format", "{{.Name}}")
        if ln.startswith(prefix)
    ]
    volumes = [
        ln for ln in _lines("volume", "ls", "--format", "{{.Name}}")
        if ln.startswith(prefix)
    ]
    # Containers first (networks/volumes refuse removal while in use).
    for kind, names, verb in (
        ("container", containers, ["rm", "-f"]),
        ("network", networks, ["network", "rm"]),
        ("volume", volumes, ["volume", "rm"]),
    ):
        for name in names:
            if dry_run:
                console.print(f"[yellow]would remove[/] {kind} {name}")
                continue
            out = subprocess.run(
                ["docker", *verb, name], capture_output=True, text=True, timeout=120,
            )
            if out.returncode == 0:
                console.print(f"[green]removed[/] {kind} {name}")
                removed += 1
            else:
                console.print(
                    f"[yellow]kept[/] {kind} {name}: {out.stderr.strip()[-200:]}")
    if dry_run:
        console.print("dry run — nothing removed")
    else:
        console.print(f"removed {removed} object(s)")


if __name__ == "__main__":
    app()
