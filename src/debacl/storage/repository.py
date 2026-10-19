"""
Repository classes — bridge between Pydantic models and SQLAlchemy records.

@decision DEC-STORE-001
@title SQLite via SQLAlchemy — zero infrastructure, migration path to Postgres
@status accepted
@rationale Repository pattern keeps query logic centralised and out of business code.
           Each repository owns the bidirectional conversion between its canonical
           Pydantic model and the corresponding SQLAlchemy record. JSON serialization
           is used for nested objects (ConnectionEvent, EndpointTelemetry inside Finding)
           to avoid a complex join schema at the PoC stage.
"""

import json
from datetime import datetime
from ipaddress import ip_address

from sqlalchemy import Engine

from debacl.models.events import ConnectionEvent
from debacl.models.findings import Finding
from debacl.models.telemetry import EndpointTelemetry
from debacl.normalization import as_utc

from .database import get_session
from .tables import ConnectionEventRecord, EndpointTelemetryRecord, FindingRecord


def _utc_naive(timestamp: datetime) -> datetime:
    """Convert a timestamp to the UTC-naive form stored by SQLite."""
    return as_utc(timestamp).replace(tzinfo=None)


def _utc_aware(timestamp: datetime) -> datetime:
    """Treat legacy naive database timestamps as UTC on read."""
    return as_utc(timestamp)


def _telemetry_key(row: EndpointTelemetryRecord) -> tuple:
    """Observation identity available in the current telemetry schema."""
    return (
        row.source,
        row.device_id,
        row.hostname,
        row.public_ip,
        row.timestamp,
        row.health_status,
        row.raw_data_json,
    )


def _event_key(row: ConnectionEventRecord) -> tuple | None:
    """Deduplicate only events carrying stable source provenance.

    Equal normalized fields and timestamps do not prove two authentication
    events are the same event. An absent raw payload supplies no identity.
    """
    if row.raw_data_json is None:
        return None
    provenance = json.loads(row.raw_data_json)
    stable_log_line = (
        row.source == "vpn_log"
        and provenance.get("timestamp_basis") == "collection_time"
        and {"file_path", "line_number", "record_sha256"}.issubset(provenance)
    )
    return (
        row.source,
        row.source_ip,
        row.username,
        row.destination,
        row.event_type,
        None if stable_log_line else row.timestamp,
        row.raw_data_json,
    )


# ---------------------------------------------------------------------------
# TelemetryRepository
# ---------------------------------------------------------------------------


class TelemetryRepository:
    """Persist and query EndpointTelemetry records."""

    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    # -- conversion helpers --------------------------------------------------

    @staticmethod
    def _to_record(t: EndpointTelemetry) -> EndpointTelemetryRecord:
        return EndpointTelemetryRecord(
            device_id=t.device_id,
            hostname=t.hostname,
            public_ip=str(t.public_ip),
            source=t.source,
            timestamp=_utc_naive(t.timestamp),
            health_status=t.health_status,
            raw_data_json=json.dumps(t.raw_data, sort_keys=True)
            if t.raw_data is not None
            else None,
        )

    @staticmethod
    def _from_record(r: EndpointTelemetryRecord) -> EndpointTelemetry:
        return EndpointTelemetry(
            device_id=r.device_id,
            hostname=r.hostname,
            public_ip=ip_address(r.public_ip),  # type: ignore[arg-type]
            source=r.source,  # type: ignore[arg-type]
            timestamp=_utc_aware(r.timestamp),
            health_status=r.health_status,
            raw_data=json.loads(r.raw_data_json) if r.raw_data_json is not None else None,
        )

    # -- public API ----------------------------------------------------------

    def save(self, t: EndpointTelemetry) -> None:
        """Insert an EndpointTelemetry record."""
        with get_session(self._engine) as session:
            session.add(self._to_record(t))

    def save_many(self, telemetry: list[EndpointTelemetry]) -> int:
        """Atomically insert new observations; return the number inserted.

        A repeated observation with the same canonical fields, timestamp, and
        source payload is ignored.
        """
        if not telemetry:
            return 0
        inserted = 0
        with get_session(self._engine) as session:
            seen = {_telemetry_key(row) for row in session.query(EndpointTelemetryRecord).all()}
            for item in telemetry:
                record = self._to_record(item)
                key = _telemetry_key(record)
                if key in seen:
                    continue
                seen.add(key)
                session.add(record)
                inserted += 1
        return inserted

    def get_all(self) -> list[EndpointTelemetry]:
        """Return all stored endpoint telemetry records."""
        with get_session(self._engine) as session:
            rows = session.query(EndpointTelemetryRecord).all()
            return [self._from_record(r) for r in rows]

    def get_by_source(self, source: str) -> list[EndpointTelemetry]:
        """Return all records matching the given source adapter name."""
        with get_session(self._engine) as session:
            rows = (
                session.query(EndpointTelemetryRecord)
                .filter(EndpointTelemetryRecord.source == source)
                .all()
            )
            return [self._from_record(r) for r in rows]

    def get_by_ip(self, ip: str) -> list[EndpointTelemetry]:
        """Return all records whose public_ip matches the given string."""
        with get_session(self._engine) as session:
            rows = (
                session.query(EndpointTelemetryRecord)
                .filter(EndpointTelemetryRecord.public_ip == ip)
                .all()
            )
            return [self._from_record(r) for r in rows]


# ---------------------------------------------------------------------------
# EventRepository
# ---------------------------------------------------------------------------


class EventRepository:
    """Persist and query ConnectionEvent records."""

    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    @staticmethod
    def _to_record(e: ConnectionEvent) -> ConnectionEventRecord:
        return ConnectionEventRecord(
            source_ip=str(e.source_ip),
            username=e.username,
            destination=e.destination,
            event_type=e.event_type,
            timestamp=_utc_naive(e.timestamp),
            source=e.source,
            raw_data_json=json.dumps(e.raw_data, sort_keys=True)
            if e.raw_data is not None
            else None,
        )

    @staticmethod
    def _from_record(r: ConnectionEventRecord) -> ConnectionEvent:
        return ConnectionEvent(
            source_ip=ip_address(r.source_ip),  # type: ignore[arg-type]
            username=r.username,
            destination=r.destination,
            event_type=r.event_type,  # type: ignore[arg-type]
            timestamp=_utc_aware(r.timestamp),
            source=r.source,  # type: ignore[arg-type]
            raw_data=json.loads(r.raw_data_json) if r.raw_data_json is not None else None,
        )

    def save(self, e: ConnectionEvent) -> None:
        """Insert a ConnectionEvent record."""
        with get_session(self._engine) as session:
            session.add(self._to_record(e))

    def save_many(self, events: list[ConnectionEvent]) -> int:
        """Atomically insert new events; return the number inserted.

        Raw source provenance is required for deduplication. Syslog lines with
        only collection time use stable file/line provenance across replays.
        Events without provenance are retained even when fields match.
        """
        if not events:
            return 0
        inserted = 0
        with get_session(self._engine) as session:
            seen = {
                key
                for row in session.query(ConnectionEventRecord).all()
                if (key := _event_key(row)) is not None
            }
            for item in events:
                record = self._to_record(item)
                key = _event_key(record)
                if key is not None:
                    if key in seen:
                        continue
                    seen.add(key)
                session.add(record)
                inserted += 1
        return inserted

    def get_all(self) -> list[ConnectionEvent]:
        """Return all stored connection event records."""
        with get_session(self._engine) as session:
            rows = session.query(ConnectionEventRecord).all()
            return [self._from_record(r) for r in rows]

    def get_by_source(self, source: str) -> list[ConnectionEvent]:
        """Return all records matching the given source adapter name."""
        with get_session(self._engine) as session:
            rows = (
                session.query(ConnectionEventRecord)
                .filter(ConnectionEventRecord.source == source)
                .all()
            )
            return [self._from_record(r) for r in rows]

    def get_by_ip(self, ip: str) -> list[ConnectionEvent]:
        """Return all records whose source_ip matches the given string."""
        with get_session(self._engine) as session:
            rows = (
                session.query(ConnectionEventRecord)
                .filter(ConnectionEventRecord.source_ip == ip)
                .all()
            )
            return [self._from_record(r) for r in rows]


# ---------------------------------------------------------------------------
# FindingRepository
# ---------------------------------------------------------------------------


class FindingRepository:
    """Persist and query Finding records."""

    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    @staticmethod
    def _to_record(f: Finding) -> FindingRecord:
        return FindingRecord(
            finding_id=str(f.finding_id),
            finding_type=f.finding_type,
            severity=f.severity,
            source_ip=str(f.source_ip),
            description=f.description,
            timestamp=_utc_naive(f.timestamp),
            connection_event_json=f.connection_event.model_dump_json(),
            matched_telemetry_json=(
                f.matched_telemetry.model_dump_json() if f.matched_telemetry else None
            ),
        )

    @staticmethod
    def _from_record(r: FindingRecord) -> Finding:
        event = ConnectionEvent.model_validate_json(r.connection_event_json)
        telemetry = (
            EndpointTelemetry.model_validate_json(r.matched_telemetry_json)
            if r.matched_telemetry_json
            else None
        )
        return Finding(
            finding_id=r.finding_id,  # type: ignore[arg-type]
            finding_type=r.finding_type,  # type: ignore[arg-type]
            severity=r.severity,  # type: ignore[arg-type]
            source_ip=ip_address(r.source_ip),  # type: ignore[arg-type]
            expected_ips=[],  # not persisted separately in PoC
            connection_event=event,
            matched_telemetry=telemetry,
            description=r.description,
            timestamp=_utc_aware(r.timestamp),
        )

    def save(self, f: Finding) -> None:
        """Insert a Finding record."""
        with get_session(self._engine) as session:
            session.add(self._to_record(f))

    def get_all(self) -> list[Finding]:
        """Return all stored findings."""
        with get_session(self._engine) as session:
            rows = session.query(FindingRecord).all()
            return [self._from_record(r) for r in rows]

    def get_by_severity(self, severity: str) -> list[Finding]:
        """Return all findings with the given severity level."""
        with get_session(self._engine) as session:
            rows = session.query(FindingRecord).filter(FindingRecord.severity == severity).all()
            return [self._from_record(r) for r in rows]

    def get_since(self, ts: datetime) -> list[Finding]:
        """Return all findings with timestamp >= ts."""
        naive_ts = _utc_naive(ts)
        with get_session(self._engine) as session:
            rows = session.query(FindingRecord).filter(FindingRecord.timestamp >= naive_ts).all()
            return [self._from_record(r) for r in rows]
