"""
Canonical endpoint telemetry model.

@decision DEC-MODEL-001
@title Pydantic v2 canonical models — type safety at ingestion boundary
@status accepted
@rationale Pydantic v2 provides runtime type validation, automatic JSON serialization,
           and native FastAPI integration. All raw adapter data is coerced into these
           models before entering the system, creating a single trust boundary.
"""

from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Literal

from pydantic import BaseModel


class EndpointTelemetry(BaseModel):
    """Represents the current known state of a managed endpoint device."""

    device_id: str
    hostname: str
    public_ip: IPv4Address | IPv6Address
    source: Literal["crowdstrike", "intune", "jamf"]
    timestamp: datetime
    health_status: str | None = None
    raw_data: dict | None = None
