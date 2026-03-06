"""
Synthetic telemetry generator for testing and mock-mode collectors.

@decision DEC-TEST-001
@title Synthetic telemetry — deterministic, credential-free, edge-case-covering
@status accepted
@rationale Real API credentials must never appear in tests or CI. A seeded random
           generator produces deterministic yet realistic datasets: mixed IPv4/IPv6,
           healthy/outdated/None health states, a configurable anomaly_ratio to
           exercise the correlation engine's detection path, and a VPN log CSV
           that exercises the file-based collector. The seed=42 default makes every
           test run produce identical data without needing fixtures checked in.
"""

import csv
import ipaddress
import random
import uuid
from datetime import UTC, datetime, timedelta
from typing import Literal

from debacl.models.events import ConnectionEvent
from debacl.models.telemetry import EndpointTelemetry

# ---------------------------------------------------------------------------
# IP address pools (documentation ranges — non-routable but not RFC1918)
# ---------------------------------------------------------------------------

_IPV4_PREFIXES = [
    "203.0.113",   # TEST-NET-3 (RFC 5737)
    "198.51.100",  # TEST-NET-2 (RFC 5737)
    "192.0.2",     # TEST-NET-1 (RFC 5737)
]

_IPV6_PREFIX = "2001:db8"  # documentation range (RFC 3849)

_FIRST_NAMES = [
    "alice", "bob", "carol", "dave", "eve", "frank", "grace", "henry",
    "iris", "jack", "karen", "liam", "mia", "noah", "olivia", "peter",
    "quinn", "rachel", "sam", "tara",
]
_LAST_NAMES = [
    "smith", "jones", "williams", "brown", "taylor", "davies", "wilson",
    "evans", "thomas", "roberts", "johnson", "white", "martin", "jackson",
    "thompson", "harris", "robinson", "walker", "wright", "green",
]

_HEALTH_STATUSES = ["healthy", "outdated", None]
_VPN_STATUSES = ["connected", "failed"]


def _now_utc() -> datetime:
    return datetime.now(tz=UTC)


class MockDataGenerator:
    """Generates deterministic synthetic telemetry for tests and mock-mode collectors.

    All randomness is seeded so test runs are reproducible. IPs are drawn from
    IANA documentation ranges (not RFC1918) so the correlation engine sees them
    as public addresses.

    Args:
        seed: Random seed for reproducibility.
        device_count: Number of endpoint records to generate.
        event_count: Number of connection events to generate.
        anomaly_ratio: Fraction of events whose IP is NOT in the known-IP pool.
    """

    def __init__(
        self,
        seed: int = 42,
        device_count: int = 20,
        event_count: int = 50,
        anomaly_ratio: float = 0.2,
    ) -> None:
        self.rng = random.Random(seed)
        self.device_count = device_count
        self.event_count = event_count
        self.anomaly_ratio = anomaly_ratio

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _random_ipv4(self, prefix: str) -> ipaddress.IPv4Address:
        octet = self.rng.randint(1, 254)
        return ipaddress.IPv4Address(f"{prefix}.{octet}")

    def _random_ipv6(self) -> ipaddress.IPv6Address:
        groups = [format(self.rng.randint(0, 0xFFFF), "x") for _ in range(2)]
        return ipaddress.IPv6Address(f"{_IPV6_PREFIX}::{':'.join(groups)}")

    def _random_public_ip(self) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
        """Return a random public (doc-range) IP — mix of IPv4 and IPv6."""
        if self.rng.random() < 0.15:  # ~15% IPv6
            return self._random_ipv6()
        prefix = self.rng.choice(_IPV4_PREFIXES)
        return self._random_ipv4(prefix)

    def _random_unknown_ip(
        self, known: list[ipaddress.IPv4Address | ipaddress.IPv6Address]
    ) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
        """Return a public IP guaranteed not to be in *known*."""
        known_set = {str(ip) for ip in known}
        for _ in range(100):
            candidate = self._random_public_ip()
            if str(candidate) not in known_set:
                return candidate
        # Fallback: construct one we know is absent
        return ipaddress.IPv4Address("203.0.113.254")

    def _random_timestamp(self, hours_back: int = 24) -> datetime:
        offset = timedelta(seconds=self.rng.randint(0, hours_back * 3600))
        return _now_utc() - offset

    def _random_username(self) -> str:
        first = self.rng.choice(_FIRST_NAMES)
        last = self.rng.choice(_LAST_NAMES)
        return f"{first}.{last}@corp.com"

    # ------------------------------------------------------------------
    # Public generators
    # ------------------------------------------------------------------

    def generate_endpoint_telemetry(
        self, source: Literal["crowdstrike", "intune", "jamf"]
    ) -> list[EndpointTelemetry]:
        """Return *device_count* synthetic endpoint records for *source*.

        Hostnames follow the CORP-LAPTOP-NNN pattern. Health statuses cycle
        through healthy, outdated, and None to exercise all branches.
        """
        devices = []
        for i in range(1, self.device_count + 1):
            health = _HEALTH_STATUSES[i % len(_HEALTH_STATUSES)]
            devices.append(
                EndpointTelemetry(
                    device_id=str(uuid.UUID(int=self.rng.getrandbits(128))),
                    hostname=f"CORP-LAPTOP-{i:03d}",
                    public_ip=self._random_public_ip(),
                    source=source,
                    timestamp=self._random_timestamp(),
                    health_status=health,
                    raw_data={"mock": True, "index": i},
                )
            )
        return devices

    def generate_connection_events(
        self,
        source: Literal["okta", "entra", "vpn_log"],
        known_ips: list[ipaddress.IPv4Address | ipaddress.IPv6Address] | None = None,
    ) -> list[ConnectionEvent]:
        """Return *event_count* synthetic connection events for *source*.

        *anomaly_ratio* fraction of events use IPs not present in *known_ips*,
        simulating the suspicious behaviour the correlation engine should flag.
        """
        if known_ips is None:
            known_ips = [self._random_public_ip() for _ in range(10)]

        anomaly_count = int(round(self.event_count * self.anomaly_ratio))
        normal_count = self.event_count - anomaly_count

        events: list[ConnectionEvent] = []

        # Normal events — use IPs from known_ips pool
        for _ in range(normal_count):
            ip = self.rng.choice(known_ips) if known_ips else self._random_public_ip()
            if source == "vpn_log":
                event_type = self.rng.choice(["vpn_connect", "auth_success", "auth_failure"])
            else:
                event_type = self.rng.choice(["auth_success", "auth_failure"])
            events.append(
                ConnectionEvent(
                    source_ip=ip,
                    username=self._random_username(),
                    destination="corp-vpn.example.com",
                    event_type=event_type,
                    timestamp=self._random_timestamp(),
                    source=source,
                    raw_data={"mock": True, "anomaly": False},
                )
            )

        # Anomalous events — IPs not in known_ips
        for _ in range(anomaly_count):
            ip = self._random_unknown_ip(known_ips)
            if source == "vpn_log":
                event_type = self.rng.choice(["vpn_connect", "auth_success", "auth_failure"])
            else:
                event_type = self.rng.choice(["auth_success", "auth_failure"])
            events.append(
                ConnectionEvent(
                    source_ip=ip,
                    username=self._random_username(),
                    destination="corp-vpn.example.com",
                    event_type=event_type,
                    timestamp=self._random_timestamp(),
                    source=source,
                    raw_data={"mock": True, "anomaly": True},
                )
            )

        self.rng.shuffle(events)
        return events

    def generate_vpn_log_file(self, path: str) -> str:
        """Write a synthetic VPN log CSV to *path* and return the path.

        Columns: timestamp, username, source_ip, destination, status
        *anomaly_ratio* fraction of rows use unknown IPs (not in the known pool).
        """
        known_ips = [str(self._random_public_ip()) for _ in range(10)]
        anomaly_count = int(round(self.event_count * self.anomaly_ratio))
        normal_count = self.event_count - anomaly_count

        rows = []
        for _ in range(normal_count):
            rows.append(
                {
                    "timestamp": self._random_timestamp().isoformat(),
                    "username": self._random_username(),
                    "source_ip": self.rng.choice(known_ips),
                    "destination": "corp-vpn.example.com",
                    "status": self.rng.choice(_VPN_STATUSES),
                }
            )
        for _ in range(anomaly_count):
            prefix = self.rng.choice(_IPV4_PREFIXES)
            unknown_ip = str(self._random_ipv4(prefix))
            # ensure it is not accidentally in known_ips
            while unknown_ip in known_ips:
                unknown_ip = str(self._random_ipv4(prefix))
            rows.append(
                {
                    "timestamp": self._random_timestamp().isoformat(),
                    "username": self._random_username(),
                    "source_ip": unknown_ip,
                    "destination": "corp-vpn.example.com",
                    "status": self.rng.choice(_VPN_STATUSES),
                }
            )

        self.rng.shuffle(rows)

        fieldnames = ["timestamp", "username", "source_ip", "destination", "status"]
        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

        return path
