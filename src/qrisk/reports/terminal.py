"""Colour-coded terminal summary."""

from __future__ import annotations

from collections import Counter

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..models import Rating, ScanResult
from ..scoring import grade, readiness_score

STYLES = {
    Rating.CRITICAL: "bold red",
    Rating.QUANTUM_VULNERABLE: "dark_orange",
    Rating.HYBRID: "dodger_blue1",  # not yellow: too close to orange
    Rating.QUANTUM_SAFE: "green",
}
NOTE_STYLES = {"error": "red", "warning": "yellow", "info": "dim"}


def score_style(score: int | None) -> str:
    if score is None:
        return "dim"
    return "green" if score >= 80 else "dodger_blue1" if score >= 50 else "dark_orange" if score >= 25 else "red"


def render(result: ScanResult, console: Console | None = None) -> None:
    console = console or Console()
    score = readiness_score(result.findings)
    counts = result.counts()

    headline = Text()
    headline.append("Quantum Readiness: ", style="bold")
    headline.append("n/a" if score is None else f"{score}/100", style=f"bold {score_style(score)}")
    headline.append(f"  ({grade(score)})\n", style=score_style(score))
    for r in Rating:
        headline.append("● ", style=STYLES[r])
        headline.append(f"{r.label} {counts[r]}   ")
    console.print(Panel(headline, title="QRisk Scanner", subtitle=f"{len(result.targets)} target(s)", expand=False))

    if result.findings:
        table = Table(show_lines=False, header_style="bold", expand=True)
        table.add_column("Rating", no_wrap=True)
        table.add_column("Target", overflow="fold", ratio=2)
        table.add_column("Category", no_wrap=True)
        table.add_column("Asset", overflow="fold", ratio=3)
        table.add_column("Why / NIST deadline", overflow="fold", ratio=5)
        for f in result.sorted_findings():
            why = f.reason + (f"\n[dim]{f.nist}[/dim]" if f.nist else "")
            table.add_row(Text(f.rating.label, style=STYLES[f.rating]), f.where,
                          f.category, f.asset, why)
        console.print(table)

        recs: Counter[tuple[Rating, str]] = Counter(
            (f.rating, f.recommendation) for f in result.findings if f.rating is not Rating.QUANTUM_SAFE
        )
        if recs:
            console.print("\n[bold]Top recommendations[/bold]")
            for (rating, rec), n in sorted(recs.items(), key=lambda kv: (kv[0][0].severity, -kv[1]))[:8]:
                console.print(Text("  ● ", style=STYLES[rating]), Text(f"{rec}  ", style=""),
                              Text(f"({n} finding{'s' if n > 1 else ''})", style="dim"), sep="")

    if result.notes:
        console.print("\n[bold]Notes[/bold]")
        for n in result.notes:
            console.print(f"  [{NOTE_STYLES.get(n.level, '')}]{n.level:<7}[/] {n.target}: {n.message}",
                          highlight=False)
