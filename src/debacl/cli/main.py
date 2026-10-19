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
_ENDPOINT_SOURCES = ("crowdstrike", "intune", "jamf")
_EVENT_SOURCES = ("okta", "entra", "vpn_log")
_SOURCES = _ENDPOINT_SOURCES + _EVENT_SOURCES


class _ConfigurationError(Exception):
    """A source cannot run with the selected local configuration."""


def _get_engine():
    """Return the default SQLite engine, initialising tables if needed."""
    from debacl.config import get_settings
    from debacl.storage.database import get_engine, init_db

    engine = get_engine(f"sqlite:///{get_settings().db_path}")
    init_db(engine)
    return engine


def _require_live_settings(source: str, settings, *fields: str) -> None:
    missing = [f"DEBACL_{field.upper()}" for field in fields if not getattr(settings, field)]
    if missing:
        raise _ConfigurationError(f"{source} requires {', '.join(missing)} in live mode")


def _make_collector(source: str, settings, mock: bool):
    """Build an existing source adapter without touching a provider API."""
    common = {"source": source, "mock_mode": mock}

    if source == "crowdstrike":
        from debacl.collectors.crowdstrike import CrowdStrikeCollector, CrowdStrikeConfig

        if not mock:
            _require_live_settings(
                source, settings, "crowdstrike_client_id", "crowdstrike_client_secret"
            )
        return CrowdStrikeCollector(
            CrowdStrikeConfig(
                **common,
                client_id=settings.crowdstrike_client_id,
                client_secret=settings.crowdstrike_client_secret,
            )
        )
    if source == "intune":
        from debacl.collectors.intune import IntuneCollector, IntuneConfig

        if not mock:
            _require_live_settings(
                source, settings, "azure_tenant_id", "azure_client_id", "azure_client_secret"
            )
        return IntuneCollector(
            IntuneConfig(
                **common,
                tenant_id=settings.azure_tenant_id,
                client_id=settings.azure_client_id,
                client_secret=settings.azure_client_secret,
            )
        )
    if source == "jamf":
        from debacl.collectors.jamf import JamfCollector, JamfConfig

        if not mock:
            _require_live_settings(
                source, settings, "jamf_base_url", "jamf_client_id", "jamf_client_secret"
            )
        return JamfCollector(
            JamfConfig(
                **common,
                base_url=settings.jamf_base_url,
                client_id=settings.jamf_client_id,
                client_secret=settings.jamf_client_secret,
            )
        )
    if source == "okta":
        from debacl.collectors.okta import OktaCollector, OktaConfig

        if not mock:
            _require_live_settings(source, settings, "okta_domain", "okta_api_token")
        return OktaCollector(
            OktaConfig(
                **common,
                domain=settings.okta_domain,
                api_token=settings.okta_api_token,
            )
        )
    if source == "entra":
        from debacl.collectors.entra import EntraCollector, EntraConfig

        if not mock:
            _require_live_settings(
                source, settings, "azure_tenant_id", "azure_client_id", "azure_client_secret"
            )
        return EntraCollector(
            EntraConfig(
                **common,
                tenant_id=settings.azure_tenant_id,
                client_id=settings.azure_client_id,
                client_secret=settings.azure_client_secret,
            )
        )
    if source == "vpn_log":
        from debacl.collectors.vpn_log import VpnLogCollector, VpnLogConfig

        if not mock:
            _require_live_settings(source, settings, "vpn_log_path")
        return VpnLogCollector(
            VpnLogConfig(
                **common,
                log_path=settings.vpn_log_path,
                log_format=settings.vpn_log_format,
            )
        )
    raise _ConfigurationError(f"Unknown source {source!r}")


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
    from debacl.config import get_settings
    from debacl.models.events import ConnectionEvent
    from debacl.models.telemetry import EndpointTelemetry
    from debacl.storage.repository import EventRepository, TelemetryRepository

    if all_sources == bool(source):
        if all_sources:
            typer.echo("Use either --source or --all, not both.", err=True)
        else:
            typer.echo("Specify --source <name> or --all.", err=True)
        raise typer.Exit(1)
    if source is not None and source not in _SOURCES:
        typer.echo(f"Unknown source {source!r}. Use: {', '.join(_SOURCES)}.", err=True)
        raise typer.Exit(1)

    settings = get_settings()
    if all_sources:
        # Mock runs exercise all adapters; live runs only use enabled sources.
        sources_to_collect = [
            src for src in _SOURCES if mock or getattr(settings, f"{src}_enabled")
        ]
    else:
        sources_to_collect = [source]
    if not sources_to_collect:
        typer.echo("No sources are enabled. Set DEBACL_<SOURCE>_ENABLED or use --source.", err=True)
        raise typer.Exit(1)

    try:
        engine = _get_engine() if save else None
    except Exception as exc:
        typer.echo(f"Could not open collection database ({type(exc).__name__}).", err=True)
        raise typer.Exit(1) from None

    t_repo = TelemetryRepository(engine) if engine is not None else None
    e_repo = EventRepository(engine) if engine is not None else None
    failed = False
    for src in sources_to_collect:
        typer.echo(f"Collecting from {src} (mock={mock}) ...")
        try:
            collector = _make_collector(src, settings, mock)
            records = collector.collect()
            expected = EndpointTelemetry if src in _ENDPOINT_SOURCES else ConnectionEvent
            if not isinstance(records, list) or any(
                not isinstance(record, expected) or record.source != src for record in records
            ):
                raise TypeError("Collector returned unexpected canonical records")
            skipped = getattr(collector, "skipped_count", 0)
            if not isinstance(skipped, int) or skipped < 0:
                raise TypeError("Collector returned an invalid skipped count")

            if t_repo is not None and src in _ENDPOINT_SOURCES:
                persisted = t_repo.save_many(records)
            elif e_repo is not None:
                persisted = e_repo.save_many(records)
            else:
                persisted = 0

            summary = f"  Collected {len(records)} items from {src}"
            if save:
                summary += f"; persisted {persisted}; already present {len(records) - persisted}"
            else:
                summary += "; not saved"
            summary += f"; skipped {skipped} invalid/incomplete source records"
            typer.echo(summary)
            if not records:
                typer.echo(f"  No usable records returned by {src}.", err=True)
            if skipped:
                failed = True
        except _ConfigurationError as exc:
            typer.echo(f"  {exc}", err=True)
            failed = True
        except Exception as exc:
            # Provider errors may contain response bodies or credentials. Never
            # echo their text, and always mark this source/command as failed.
            typer.echo(f"  Collection failed for {src} ({type(exc).__name__}).", err=True)
            failed = True

    if failed:
        raise typer.Exit(1)


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
    from debacl.normalization import as_utc
    from debacl.storage.repository import EventRepository, FindingRepository, TelemetryRepository

    engine = _get_engine()
    t_repo = TelemetryRepository(engine)
    e_repo = EventRepository(engine)
    f_repo = FindingRepository(engine)

    telemetry = t_repo.get_all()
    events = e_repo.get_all()

    if since is not None:
        cutoff = as_utc(datetime.fromisoformat(since))
        telemetry = [t for t in telemetry if as_utc(t.timestamp) >= cutoff]
        events = [e for e in events if as_utc(e.timestamp) >= cutoff]

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
        typer.echo(f"{str(f.finding_id):<38} {f.finding_type:<18} {f.severity:<10} {f.source_ip}")
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
