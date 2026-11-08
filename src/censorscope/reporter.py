"""Terminal rendering (Rich) and JSON serialization of diagnostic reports."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from censorscope import __version__
from censorscope.models import (
    STATUS_ERROR,
    STATUS_SUCCESS,
    STATUS_WARNING,
    VERDICT_INCONCLUSIVE,
    VERDICT_INTERFERENCE,
    VERDICT_OK,
    VERDICT_RESTRICTION,
    DiagnosticReport,
)

_STATUS_STYLE = {
    STATUS_SUCCESS: ("OK", "green"),
    STATUS_WARNING: ("WARN", "yellow"),
    STATUS_ERROR: ("FAIL", "red"),
}

_VERDICT_PRESENTATION = {
    VERDICT_OK: ("No problem detected", "green"),
    VERDICT_INTERFERENCE: ("Possible network interference", "yellow"),
    VERDICT_RESTRICTION: ("Possible service-side restriction", "yellow"),
    VERDICT_INCONCLUSIVE: ("Inconclusive", "blue"),
}


def render_report(report: DiagnosticReport, console: Console) -> None:
    """Print a polished, readable report to the terminal."""
    console.print(
        Panel(
            Text.assemble(("Target: ", "bold"), report.target),
            title=f"Censorscope {__version__}",
            subtitle="network reachability diagnostic",
            border_style="blue",
        )
    )

    table = Table(show_header=True, header_style="bold", box=None, pad_edge=False)
    table.add_column("Probe", style="bold", width=6)
    table.add_column("Status", width=6)
    table.add_column("Summary", ratio=1)
    table.add_column("Time", justify="right", width=9)
    for result in report.probe_results:
        label, style = _STATUS_STYLE.get(result.status, (result.status, "white"))
        table.add_row(
            result.name,
            Text(label, style=style),
            result.summary,
            f"{result.duration_ms:.0f} ms",
        )
    console.print(table)

    title, style = _VERDICT_PRESENTATION.get(report.verdict, (report.verdict, "white"))
    body = Text.assemble(
        (title, f"bold {style}"),
        f"\nConfidence: {report.confidence}",
        "\n\n",
        "\n".join(f"• {reason}" for reason in report.reasons),
    )
    console.print(Panel(body, title="Verdict", border_style=style))
    console.print(Text(f"Completed in {report.duration_ms / 1000:.2f} s", style="dim"))


def report_to_json(report: DiagnosticReport) -> str:
    """Serialize a report to a valid JSON string."""
    return report.to_json()
