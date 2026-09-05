from __future__ import annotations

import sys
import time
from contextlib import nullcontext

from rich.markup import escape
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)

STAGE_COLUMNS = [
    {"description": "{task.description}", "justify": "left"},
]


def make_display(console):
    if console is not None and getattr(console, "is_terminal", False):
        return RichDisplay(console)
    return PlainDisplay()


class PlainDisplay:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def begin(self, name: str, cap: float | None = None, label: str | None = None) -> None:
        print(f"* {label or name} …", flush=True)

    def tick(self, name: str, elapsed: float, note: str = "") -> None:
        pass

    def finish(self, name: str, outcome: str = "ok", note: str = "") -> None:
        mark = "✓" if outcome == "ok" else "✗"
        suffix = f" ({note})" if note else ""
        print(f"* {mark} {name} {outcome}{suffix}", flush=True)

    def message(self, text: str) -> None:
        print(f"* {text}", flush=True)


class RichDisplay:
    def __init__(self, console):
        self._console = console
        self._started: dict[str, float] = {}
        self._progress = Progress(
            SpinnerColumn(style="cyan"),
            TextColumn("[bold]{task.description}"),
            BarColumn(bar_width=28),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            TextColumn("[dim]{task.fields[note]}"),
            console=console,
            refresh_per_second=6,
        )
        self._tasks: dict[str, int] = {}

    def __enter__(self):
        self._progress.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        self._progress.stop()
        return False

    def begin(self, name: str, cap: float | None = None, label: str | None = None) -> None:
        self._started[name] = time.monotonic()
        self._tasks[name] = self._progress.add_task(
            f"[cyan]{(label or name).upper()}[/]",
            total=cap,
            note="",
        )

    def tick(self, name: str, elapsed: float, note: str = "") -> None:
        tid = self._tasks.get(name)
        if tid is None:
            return
        cap = self._progress.tasks[tid].total or elapsed
        self._progress.update(
            tid,
            completed=min(elapsed, cap),
            note=note,
        )

    def finish(self, name: str, outcome: str = "ok", note: str = "") -> None:
        tid = self._tasks.get(name)
        if tid is None:
            return
        style = "green" if outcome == "ok" else "red"
        mark = "✓" if outcome == "ok" else "✗"
        cap = self._progress.tasks[tid].total
        self._progress.update(
            tid,
            description=f"[{style}]{mark} {name.upper()}[/{style}]",
            completed=cap if cap else self._progress.tasks[tid].completed,
            note=f"{outcome}{(' · ' + note) if note else ''}",
            stop=True,
        )
        self._progress.tasks[tid].visible = True

    def message(self, text: str) -> None:
        self._progress.console.print(f"[dim]·[/] {text}")


def _fmt_secs(s: float) -> str:
    m, sec = divmod(int(s), 60)
    h, m = divmod(m, 60)
    return f"{h:d}:{m:02d}:{sec:02d}" if h else f"{m:02d}:{sec:02d}"


def print_run_summary(console, result) -> None:
    if console is None:
        console = _bare_console()
    ok = result.status in ("completed", "regraded") and result.reward.get("score", 0.0) >= 0.999
    color = "green" if ok else ("yellow" if result.status in ("completed", "regraded") else "red")
    rows = [
        ("score", f"{result.reward.get('score')} ({result.reward.get('status')})"),
        ("checks", result.reward.get("checks", [])),
        ("agent exit", result.exit_code),
        ("redactions", result.redactions),
        ("results", str(result.results_dir)),
    ]
    internet_mode = getattr(result, "internet_mode", "")
    if internet_mode:
        rows.insert(4, ("internet", internet_mode))
    table = _summary_table(
        title=f"run · {result.status}",
        rows=rows,
    )
    console.print(table)


def print_oracle_summary(console, result) -> None:
    if console is None:
        console = _bare_console()
    color = "green" if result.passed else "red"
    table = _summary_table(
        title=f"oracle · {'PASSED' if result.passed else 'FAILED'}",
        rows=[
            ("score", f"{result.reward.get('score')} ({result.reward.get('status')})"),
            ("threshold", result.threshold),
            ("execution", result.status),
            ("results", str(result.results_dir)),
        ],
    )
    console.print(table)
    if not result.passed:
        console.print(f"[{color}]task NOT trustworthy — fix solution or verifier before publishing[/]")


def _summary_table(title: str, rows):
    from rich.table import Table

    t = Table(title=title, title_style="bold", show_header=False, box=None, padding=(0, 2))
    t.add_column("k", style="dim")
    t.add_column("v")
    for k, v in rows:
        if k == "checks" and isinstance(v, list):
            for c in v:
                name = escape(str(c.get("name", "check")))
                t.add_row(f"  ↳ {name}", escape(str(c.get("score"))))
            continue
        t.add_row(k, escape(str(v)))
    return t


def _bare_console():
    from rich.console import Console

    return Console()
