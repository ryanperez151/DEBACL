"""
CLI entry point — Typer commands for DEBACL.

@decision DEC-PKG-001
@title Typer CLI — cleaner than click for typed Python, auto-generates help
@status accepted
@rationale Typer wraps Click and adds automatic type annotations from Python type hints,
           reducing boilerplate and keeping command signatures self-documenting.
           All commands are guarded against missing optional subsystems (collectors,
           uvicorn) so the CLI degrades gracefully in partial builds.
"""

from __future__ import annotations

from typing import Annotated

import typer

app = typer.Typer(
    name="debacl",
    help="Dynamic Endpoint-Based Access Control List — anomaly detection tool",
    no_args_is_help=True,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SEVERITY_LEVELS = {"critical", "high", "medium", "low", "info"}


def _get_engine():
    """Return the default SQLite engine, initialising tables if needed."""
    from debacl.storage.database import get_engine, init_db

    engine = get_engine("sqlite:///debacl.db")
    init_db(engine)
    return engine


# ---------------------------------------------------------------------------
# collect
# ---------------------------------------------------------------------------


@app.command()
def collect(
    source: Annotated[
        str | None,
        typer.Option(
            "--source",
            help="Collector source (crowdstrike/intune/jamf/okta/entra/vpn_log)",
        ),
    ] = None,
    all_sources: Annotated[
        bool,
        typer.Option("--all", help="Collect from all configured sources"),
    ] = False,
    mock: Annotated[
        bool,
        typer.Option("--mock/--no-mock", help="Use mock mode (no real credentials required)"),
    ] = True,
    save: Annotated[
        bool,
        typer.Option("--save/--no-save", help="Persist collected data to SQLite"),
    ] = True,
) -> None:
    """Collect endpoint telemetry or connection events from configured sources."""
    try:
        from debacl.collectors.crowdstrike import CrowdStrikeCollector  # noqa: F401
    except ImportError as exc:
        typer.echo("Collectors not available in this build.", err=True)
        raise typer.Exit(1) from exc

    sources_to_collect: list[str] = []
    if all_sources:
        sources_to_collect = ["crowdstrike", "intune", "jamf", "okta", "entra", "vpn_log"]
    elif source:
        sources_to_collect = [source]
    else:
        typer.echo("Specify --source <name> or --all.", err=True)
        raise typer.Exit(1)

    for src in sources_to_collect:
        typer.echo(f"Collecting from {src} (mock={mock}) ...")
        # Collectors from Phase 2 — each has its own import path.
        # The exact invocation depends on the collector API not yet merged.
        typer.echo(f"  Collected 0 items from {src} (placeholder — Phase 2 not merged)")


# ---------------------------------------------------------------------------
# correlate
# ---------------------------------------------------------------------------


@app.command()
def correlate(
    window: Annotated[
        int,
        typer.Option("--window", help="Time window in hours for correlation"),
    ] = 24,
    since: Annotated[
        str | None,
        typer.Option("--since", help="ISO datetime — only process events from this time onward"),
    ] = None,
    save: Annotated[
        bool,
        typer.Option("--save/--no-save", help="Persist findings to SQLite"),
    ] = True,
) -> None:
    """Run the correlation engine against stored telemetry and events."""
    from datetime import datetime

    from debacl.correlation.engine import CorrelationConfig, CorrelationEngine
    from debacl.storage.repository import EventRepository, FindingRepository, TelemetryRepository

    engine = _get_engine()
    t_repo = TelemetryRepository(engine)
    e_repo = EventRepository(engine)
    f_repo = FindingRepository(engine)

    telemetry = t_repo.get_all()
    events = e_repo.get_all()

    if since is not None:
        cutoff = datetime.fromisoformat(since)
        naive_cutoff = cutoff.replace(tzinfo=None)
        telemetry = [t for t in telemetry if t.timestamp.replace(tzinfo=None) >= naive_cutoff]
        events = [e for e in events if e.timestamp.replace(tzinfo=None) >= naive_cutoff]

    config = CorrelationConfig(time_window_hours=window)
    corr_engine = CorrelationEngine(config=config)
    findings = corr_engine.correlate(telemetry, events)

    if save:
        for f in findings:
            f_repo.save(f)

    if not findings:
        typer.echo("No findings produced.")
        return

    # Summary table
    typer.echo(f"\n{'Finding ID':<38} {'Type':<18} {'Severity':<10} {'Source IP'}")
    typer.echo("-" * 90)
    for f in findings:
        typer.echo(
            f"{str(f.finding_id):<38} {f.finding_type:<18} {f.severity:<10} {f.source_ip}"
        )
    typer.echo(f"\nTotal findings: {len(findings)}")


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------


@app.command()
def report(
    fmt: Annotated[
        str,
        typer.Option("--format", help="Export format: json, csv, or jsonl"),
    ] = "json",
    output: Annotated[
        str,
        typer.Option("--output", help="Output directory for exported files"),
    ] = "output",
    since: Annotated[
        str | None,
        typer.Option("--since", help="ISO datetime filter — only export findings from this time"),
    ] = None,
    severity: Annotated[
        str | None,
        typer.Option("--severity", help="Severity filter: critical, high, medium, low, info"),
    ] = None,
) -> None:
    """Export findings to JSON, CSV, or SIEM JSON Lines format."""
    from datetime import datetime

    from debacl.output.exporters import FindingExporter
    from debacl.storage.repository import FindingRepository

    if fmt not in ("json", "csv", "jsonl"):
        typer.echo(f"Unknown format {fmt!r}. Use json, csv, or jsonl.", err=True)
        raise typer.Exit(1)

    if severity is not None and severity not in _SEVERITY_LEVELS:
        levels = ", ".join(sorted(_SEVERITY_LEVELS))
        typer.echo(f"Unknown severity {severity!r}. Use: {levels}", err=True)
        raise typer.Exit(1)

    engine = _get_engine()
    f_repo = FindingRepository(engine)

    if severity is not None:
        findings = f_repo.get_by_severity(severity)
    elif since is not None:
        cutoff = datetime.fromisoformat(since)
        findings = f_repo.get_since(cutoff)
    else:
        findings = f_repo.get_all()

    exporter = FindingExporter(output_dir=output)

    if fmt == "json":
        path = exporter.export_json(findings)
    elif fmt == "csv":
        path = exporter.export_csv(findings)
    else:
        path = exporter.export_siem_jsonl(findings)

    typer.echo(f"Exported {len(findings)} findings to: {path}")


# ---------------------------------------------------------------------------
# serve
# ---------------------------------------------------------------------------


@app.command()
def serve(
    port: Annotated[
        int,
        typer.Option("--port", help="Port to listen on"),
    ] = 8000,
    host: Annotated[
        str,
        typer.Option("--host", help="Host address to bind"),
    ] = "127.0.0.1",
) -> None:
    """Start the DEBACL FastAPI server via uvicorn."""
    try:
        import uvicorn
    except ImportError as exc:
        typer.echo("uvicorn is not installed. Run: pip install uvicorn", err=True)
        raise typer.Exit(1) from exc

    typer.echo(f"Starting DEBACL API on http://{host}:{port}")
    uvicorn.run("debacl.api.app:app", host=host, port=port, reload=False)


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------


@app.command()
def status() -> None:
    """Print counts of stored telemetry, events, and findings by severity."""
    from debacl.storage.repository import EventRepository, FindingRepository, TelemetryRepository

    engine = _get_engine()
    t_repo = TelemetryRepository(engine)
    e_repo = EventRepository(engine)
    f_repo = FindingRepository(engine)

    telemetry_count = len(t_repo.get_all())
    event_count = len(e_repo.get_all())
    all_findings = f_repo.get_all()

    severity_counts: dict[str, int] = {}
    for f in all_findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    typer.echo(f"Telemetry records : {telemetry_count}")
    typer.echo(f"Connection events : {event_count}")
    typer.echo(f"Findings total    : {len(all_findings)}")
    for sev in ("critical", "high", "medium", "low", "info"):
        count = severity_counts.get(sev, 0)
        typer.echo(f"  {sev:<10}: {count}")
