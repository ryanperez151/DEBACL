"""
SQLAlchemy 2.0 declarative table definitions.

@decision DEC-STORE-001
@title SQLite via SQLAlchemy — zero infrastructure, migration path to Postgres
@status accepted
@rationale DeclarativeBase with mapped_column() uses the modern SQLAlchemy 2.0 API.
           IP addresses are stored as strings (VARCHAR) — the canonical models handle
           ipaddress parsing so the DB layer stays simple. JSON blobs (connection_event_json,
           matched_telemetry_json) avoid a complex join schema for the PoC while keeping
           all Finding data recoverable.
"""

from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class EndpointTelemetryRecord(Base):
    """Persisted representation of EndpointTelemetry."""

    __tablename__ = "endpoint_telemetry"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    device_id: Mapped[str] = mapped_column(String, nullable=False)
    hostname: Mapped[str] = mapped_column(String, nullable=False)
    public_ip: Mapped[str] = mapped_column(String, nullable=False)
    source: Mapped[str] = mapped_column(String, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    health_status: Mapped[str | None] = mapped_column(String, nullable=True)


class ConnectionEventRecord(Base):
    """Persisted representation of ConnectionEvent."""

    __tablename__ = "connection_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    source_ip: Mapped[str] = mapped_column(String, nullable=False)
    username: Mapped[str] = mapped_column(String, nullable=False)
    destination: Mapped[str] = mapped_column(String, nullable=False)
    event_type: Mapped[str] = mapped_column(String, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    source: Mapped[str] = mapped_column(String, nullable=False)


class FindingRecord(Base):
    """Persisted representation of Finding."""

    __tablename__ = "findings"

    finding_id: Mapped[str] = mapped_column(String, primary_key=True)
    finding_type: Mapped[str] = mapped_column(String, nullable=False)
    severity: Mapped[str] = mapped_column(String, nullable=False)
    source_ip: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    connection_event_json: Mapped[str] = mapped_column(Text, nullable=False)
    matched_telemetry_json: Mapped[str | None] = mapped_column(Text, nullable=True)
