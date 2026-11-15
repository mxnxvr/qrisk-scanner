"""Colour-coded terminal summary."""

from __future__ import annotations

from collections import Counter

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..models import Rating, ScanResult
from ..scoring import grade, readiness_score

# The report's "dusk" screen palette (see report.html.j2). Rich converts these to the nearest colour
# on terminals without true colour.
CRITICAL, VULNERABLE, HYBRID, SAFE, ACCENT = "#e8576b", "#f2b56b", "#8f9fd9", "#9ccfb7", "#e98a6a"
STYLES = {
    Rating.CRITICAL: f"bold {CRITICAL}",
    Rating.QUANTUM_VULNERABLE: VULNERABLE,
    Rating.HYBRID: HYBRID,
    Rating.QUANTUM_SAFE: SAFE,
}
NOTE_STYLES = {"error": CRITICAL, "warning": VULNERABLE, "info": "dim"}


def score_style(score: int | None) -> str:
    if score is None:
        return "dim"
    return SAFE if score >= 80 else HYBRID if score >= 50 else VULNERABLE if score >= 25 else CRITICAL


def bullet(console: Console) -> str:
    """'●' where the output can show it; '*' on legacy encodings such as cp1252 (piped output on Windows)."""
    try:
        "●".encode(console.encoding)
        return "●"
    except (UnicodeEncodeError, LookupError):
        return "*"


def render(result: ScanResult, console: Console | None = None) -> None:
    console = console or Console()
    dot = bullet(console)
    score = readiness_score(result.findings)
    counts = result.counts()

    headline = Text()
    headline.append("Quantum Readiness: ", style="bold")
    headline.append("n/a" if score is None else f"{score}/100", style=f"bold {score_style(score)}")
    headline.append(f"  ({grade(score)})\n", style=score_style(score))
    for r in Rating:
        headline.append(f"{dot} ", style=STYLES[r])
        headline.append(f"{r.label} {counts[r]}   ")
    console.print(Panel(headline, title=f"[bold {ACCENT}]QRisk Scanner[/]", subtitle=f"{len(result.targets)} target(s)",
                        border_style=ACCENT, expand=False))

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
                console.print(Text(f"  {dot} ", style=STYLES[rating]), Text(f"{rec}  ", style=""),
                              Text(f"({n} finding{'s' if n > 1 else ''})", style="dim"), sep="")

    if result.notes:
        console.print("\n[bold]Notes[/bold]")
        for n in result.notes:
            console.print(f"  [{NOTE_STYLES.get(n.level, '')}]{n.level:<7}[/] {n.target}: {n.message}",
                          highlight=False)
