"""
Canonical connection event model.

@decision DEC-MODEL-001
@title Pydantic v2 canonical models — type safety at ingestion boundary
@status accepted
@rationale All authentication/VPN log data normalizes to ConnectionEvent before
           entering the correlation engine. Literal types enforce valid source
           and event_type values at parse time rather than runtime.
"""

from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Literal

from pydantic import BaseModel


class ConnectionEvent(BaseModel):
    """Represents a single authentication or connection event from a security edge."""

    source_ip: IPv4Address | IPv6Address
    username: str
    destination: str
    event_type: Literal["vpn_connect", "auth_success", "auth_failure"]
    timestamp: datetime
    source: Literal["okta", "entra", "vpn_log"]
    raw_data: dict | None = None
