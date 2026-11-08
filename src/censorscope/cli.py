"""Typer CLI entry point."""

from __future__ import annotations

from typing import Annotated

import typer
from rich.console import Console

from censorscope import __version__
from censorscope.diagnostics import run_diagnostic
from censorscope.models import (
    VERDICT_INCONCLUSIVE,
    VERDICT_INTERFERENCE,
    VERDICT_OK,
    VERDICT_RESTRICTION,
)
from censorscope.reporter import render_report, report_to_json

_EXIT_CODES = {
    VERDICT_OK: 0,
    VERDICT_INTERFERENCE: 1,
    VERDICT_RESTRICTION: 1,
    VERDICT_INCONCLUSIVE: 2,
}

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Diagnose why a domain may be inaccessible from your network.",
    epilog="Exit codes: 0 no problem detected, 1 possible problem detected, "
    "2 inconclusive or invalid input.",
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"censorscope {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            callback=_version_callback,
            is_eager=True,
            help="Show the version and exit.",
        ),
    ] = False,
) -> None:
    """Censorscope: evidence-based network reachability diagnostics.

    Results are heuristic and cannot always identify the source of a restriction.
    """


@app.command()
def check(
    target: Annotated[str, typer.Argument(help="Domain to check, e.g. example.com")],
    json_output: Annotated[
        bool, typer.Option("--json", help="Print valid JSON only (no Rich output).")
    ] = False,
    timeout: Annotated[
        float,
        typer.Option(
            "--timeout",
            min=0.5,
            max=60.0,
            help="Timeout in seconds for each network operation.",
        ),
    ] = 5.0,
) -> None:
    """Check DNS, TCP, TLS, and HTTP behavior for TARGET."""
    console = Console()
    try:
        if json_output:
            report = run_diagnostic(target, timeout)
            typer.echo(report_to_json(report))
        else:
            with console.status("Starting diagnostics...") as status:
                report = run_diagnostic(
                    target, timeout, progress=lambda name: status.update(f"Running {name} probe...")
                )
            render_report(report, console)
    except ValueError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(2) from exc
    raise typer.Exit(_EXIT_CODES[report.verdict])


if __name__ == "__main__":
    app()
