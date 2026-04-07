"""
FastAPI application — REST endpoints for DEBACL findings and telemetry.

@decision DEC-MODEL-001
@title FastAPI with Pydantic models — native integration, auto-generated OpenAPI docs
@status accepted
@rationale FastAPI uses Pydantic v2 natively: request/response models validate at
           the boundary, OpenAPI docs are generated automatically, and the async
           testclient lets tests run synchronously without spinning up a server.
           Dependency injection (Depends) keeps the engine/repository creation
           testable — tests override get_engine_dep to inject an in-memory engine;
           production uses the file-based SQLite default. The single engine dependency
           is the root override point for tests, keeping the injection hierarchy shallow.
"""

from __future__ import annotations

from datetime import datetime

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel
from sqlalchemy import Engine

from debacl.correlation.engine import CorrelationConfig, CorrelationEngine
from debacl.models.events import ConnectionEvent
from debacl.models.findings import Finding
from debacl.models.telemetry import EndpointTelemetry
from debacl.storage.database import get_engine, init_db
from debacl.storage.repository import EventRepository, FindingRepository, TelemetryRepository

app = FastAPI(title="DEBACL API", version="0.1.0")

# ---------------------------------------------------------------------------
# Dependency injection
# ---------------------------------------------------------------------------

_DEFAULT_ENGINE: Engine | None = None


def get_engine_dep() -> Engine:
    """Return the module-level default SQLite engine, initialising it on first call.

    Tests override this single dependency to inject an in-memory engine.
    """
    global _DEFAULT_ENGINE
    if _DEFAULT_ENGINE is None:
        _DEFAULT_ENGINE = get_engine("sqlite:///debacl.db")
        init_db(_DEFAULT_ENGINE)
    return _DEFAULT_ENGINE


def get_finding_repo(engine: Engine = Depends(get_engine_dep)) -> FindingRepository:
    """Inject a FindingRepository backed by the current engine."""
    return FindingRepository(engine)


def get_telemetry_repo(engine: Engine = Depends(get_engine_dep)) -> TelemetryRepository:
    """Inject a TelemetryRepository backed by the current engine."""
    return TelemetryRepository(engine)


def get_event_repo(engine: Engine = Depends(get_engine_dep)) -> EventRepository:
    """Inject an EventRepository backed by the current engine."""
    return EventRepository(engine)


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


@app.get("/health")
def health() -> dict:
    """Return service health status and version."""
    return {"status": "ok", "version": "0.1.0"}


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


@app.get("/findings")
def list_findings(
    severity: str | None = None,
    since: str | None = None,
    limit: int = 100,
    repo: FindingRepository = Depends(get_finding_repo),
) -> list[Finding]:
    """Return stored findings with optional severity and time filters.

    Args:
        severity: Filter to one severity level (critical/high/medium/low/info).
        since: ISO 8601 datetime string — only findings at or after this time.
        limit: Maximum number of findings to return (default 100).
    """
    if severity is not None:
        findings = repo.get_by_severity(severity)
    elif since is not None:
        ts = datetime.fromisoformat(since)
        findings = repo.get_since(ts)
    else:
        findings = repo.get_all()

    return findings[:limit]


@app.get("/findings/{finding_id}")
def get_finding(
    finding_id: str,
    repo: FindingRepository = Depends(get_finding_repo),
) -> Finding:
    """Return a single finding by its UUID, or 404 if not found."""
    all_findings = repo.get_all()
    for f in all_findings:
        if str(f.finding_id) == finding_id:
            return f
    raise HTTPException(status_code=404, detail=f"Finding {finding_id!r} not found.")


# ---------------------------------------------------------------------------
# Telemetry
# ---------------------------------------------------------------------------


@app.get("/telemetry")
def list_telemetry(
    source: str | None = None,
    since: str | None = None,
    limit: int = 100,
    repo: TelemetryRepository = Depends(get_telemetry_repo),
) -> list[EndpointTelemetry]:
    """Return stored endpoint telemetry with optional source and time filters.

    Args:
        source: Filter to one source adapter (crowdstrike/intune/jamf).
        since: ISO 8601 datetime string — only records at or after this time.
        limit: Maximum number of records to return (default 100).
    """
    if source is not None:
        records = repo.get_by_source(source)
    else:
        records = repo.get_all()

    if since is not None:
        ts = datetime.fromisoformat(since)
        # naive comparison — strip tzinfo if present for SQLite-stored naive datetimes
        naive_ts = ts.replace(tzinfo=None)
        records = [r for r in records if r.timestamp.replace(tzinfo=None) >= naive_ts]

    return records[:limit]


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------


@app.get("/events")
def list_events(
    source: str | None = None,
    since: str | None = None,
    limit: int = 100,
    repo: EventRepository = Depends(get_event_repo),
) -> list[ConnectionEvent]:
    """Return stored connection events with optional source and time filters.

    Args:
        source: Filter to one source adapter (okta/entra/vpn_log).
        since: ISO 8601 datetime string — only events at or after this time.
        limit: Maximum number of events to return (default 100).
    """
    if source is not None:
        events = repo.get_by_source(source)
    else:
        events = repo.get_all()

    if since is not None:
        ts = datetime.fromisoformat(since)
        naive_ts = ts.replace(tzinfo=None)
        events = [e for e in events if e.timestamp.replace(tzinfo=None) >= naive_ts]

    return events[:limit]


# ---------------------------------------------------------------------------
# Correlate
# ---------------------------------------------------------------------------


class CorrelateBody(BaseModel):
    """POST /correlate request body."""

    window_hours: int = 24


class CorrelateResponse(BaseModel):
    """POST /correlate response body."""

    findings_count: int
    findings: list[Finding]


@app.post("/correlate")
def run_correlate(
    body: CorrelateBody = CorrelateBody(),
    engine: Engine = Depends(get_engine_dep),
) -> CorrelateResponse:
    """Run the correlation engine and persist new findings.

    Args:
        body: JSON body with ``window_hours`` (default 24).

    Returns:
        Count and list of findings produced by this run.
    """
    telemetry_repo = TelemetryRepository(engine)
    event_repo = EventRepository(engine)
    finding_repo = FindingRepository(engine)

    telemetry = telemetry_repo.get_all()
    events = event_repo.get_all()

    config = CorrelationConfig(time_window_hours=body.window_hours)
    correlation_engine = CorrelationEngine(config=config)
    findings = correlation_engine.correlate(telemetry, events)

    for f in findings:
        finding_repo.save(f)

    return CorrelateResponse(findings_count=len(findings), findings=findings)
