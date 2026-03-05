"""
Canonical finding model — output of the correlation engine.

@decision DEC-MODEL-001
@title Pydantic v2 canonical models — type safety at ingestion boundary
@status accepted
@rationale Finding aggregates a ConnectionEvent with optional matched EndpointTelemetry
           and metadata about the anomaly. UUID primary key ensures global uniqueness
           across distributed collection runs. Severity is a closed Literal set to
           prevent typos in downstream reporting.
"""

from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from .events import ConnectionEvent
from .telemetry import EndpointTelemetry


class Finding(BaseModel):
    """An anomaly detected by the correlation engine."""

    finding_id: UUID = Field(default_factory=uuid4)
    finding_type: Literal["unmanaged_ip", "ip_mismatch", "unknown_device"]
    severity: Literal["critical", "high", "medium", "low", "info"]
    source_ip: IPv4Address | IPv6Address
    expected_ips: list[IPv4Address | IPv6Address]
    connection_event: ConnectionEvent
    matched_telemetry: EndpointTelemetry | None = None
    description: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
