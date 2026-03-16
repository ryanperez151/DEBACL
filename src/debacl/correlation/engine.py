"""
Core correlation engine — matches ConnectionEvents against EndpointTelemetry.

@decision DEC-CORR-001
@title Set-based IP correlation — O(1) membership, auditable, PoC-scale sufficient
@status accepted
@rationale At PoC scale (hundreds to low-thousands of endpoints) a Python set over
           string-serialised IPs gives O(1) membership tests with near-zero overhead.
           The algorithm is explicit and auditable: build known-IP set from telemetry,
           classify each event as clean / unmanaged_ip / ip_mismatch, score, emit
           Finding. No probabilistic matching or ML — every finding has a deterministic
           causal chain that a human analyst can reproduce from raw inputs alone.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv6Address

from debacl.models.events import ConnectionEvent
from debacl.models.findings import Finding
from debacl.models.telemetry import EndpointTelemetry

from .scoring import SeverityScorer
from .windowing import TimeWindowFilter


@dataclass
class CorrelationConfig:
    """Runtime configuration for the CorrelationEngine.

    Attributes:
        time_window_hours: Only telemetry within this many hours of now is used
                          to build the known-IP set. Events outside the window
                          are also filtered. Default is 24 hours.
        privileged_patterns: Username substrings (case-insensitive) that indicate
                             a privileged account. Used to escalate severity of
                             unmanaged_ip findings. Default covers the most common
                             privileged naming conventions.
    """

    time_window_hours: int = 24
    privileged_patterns: list[str] = field(
        default_factory=lambda: ["admin", "svc-", "root", "system"]
    )


def _username_parts(username: str) -> list[str]:
    """Extract searchable parts from a username for hostname matching.

    Splits on "@" to drop the domain, then splits the local part on "."
    so "john.doe@corp.com" yields ["john", "doe"].  Each part with 3+
    characters is kept to avoid matching on single-letter initials.
    """
    local = username.split("@")[0]
    parts = local.replace("-", ".").split(".")
    return [p.lower() for p in parts if len(p) >= 3]


def _find_device_for_username(
    username: str,
    telemetry: list[EndpointTelemetry],
) -> EndpointTelemetry | None:
    """Return the best-matching device for *username*, or None.

    Matching is loose / best-effort: the local part of the email address is
    split into tokens and we look for a device whose hostname contains at least
    one of those tokens (case-insensitive substring match).  The first match
    found is returned; order is determined by the caller's telemetry list.
    """
    parts = _username_parts(username)
    if not parts:
        return None

    for device in telemetry:
        hostname_lower = device.hostname.lower()
        if any(part in hostname_lower for part in parts):
            return device

    return None


class CorrelationEngine:
    """Correlates connection events against endpoint telemetry to produce findings.

    The engine applies three passes over the input data:

    1. Time-window filtering (via TimeWindowFilter) — stale records are dropped
       before the known-IP set is built, preventing aged-out devices from
       suppressing findings on their former IPs.

    2. Known-IP set construction — all telemetry public_ip values are collected
       into a set of string-serialised IPs for O(1) membership testing.

    3. Per-event classification — each ConnectionEvent is matched against the
       known-IP set; unknown IPs are further classified as ``ip_mismatch``
       (a managed device exists for that username but on a different IP) or
       ``unmanaged_ip`` (no matching device at all).  Severity is delegated to
       SeverityScorer.

    Args:
        config: Optional CorrelationConfig.  Defaults are used if None.
    """

    def __init__(self, config: CorrelationConfig | None = None) -> None:
        self._config = config or CorrelationConfig()
        self._scorer = SeverityScorer()
        self._window = TimeWindowFilter(window_hours=self._config.time_window_hours)

    def correlate(
        self,
        telemetry: list[EndpointTelemetry],
        events: list[ConnectionEvent],
    ) -> list[Finding]:
        """Correlate *events* against *telemetry* and return anomaly findings.

        Only telemetry and events within the configured time window are
        considered.  Events from IPs present in the known-IP set are clean and
        produce no finding.

        Args:
            telemetry: Endpoint telemetry records (current device inventory).
            events: Connection / authentication events to classify.

        Returns:
            A list of Finding objects, one per anomalous event.  Clean events
            produce no finding.  The list order mirrors the event input order.
        """
        # Apply time-window filtering before any analysis
        filtered_telemetry, filtered_events = self._window.apply(telemetry, events)

        # Build known-IP set (string-serialised for hash equality across address types)
        known_ips: set[str] = {str(t.public_ip) for t in filtered_telemetry}

        findings: list[Finding] = []

        for event in filtered_events:
            event_ip_str = str(event.source_ip)

            if event_ip_str in known_ips:
                # Source IP is a known managed endpoint — no anomaly
                continue

            # IP is not in the managed inventory — classify further
            matched_device = _find_device_for_username(event.username, filtered_telemetry)

            if matched_device is not None:
                # A device matching this username exists but on a different IP
                finding_type = "ip_mismatch"
                expected_ips: list[IPv4Address | IPv6Address] = [matched_device.public_ip]
                description = (
                    f"User '{event.username}' connected from {event.source_ip} "
                    f"but their known device '{matched_device.hostname}' is registered "
                    f"at {matched_device.public_ip}."
                )
            else:
                # No managed device corresponds to this IP or username
                finding_type = "unmanaged_ip"
                expected_ips = list(known_ips.__class__())  # empty — no expected IP
                description = (
                    f"Connection from {event.source_ip} by '{event.username}' "
                    f"does not match any managed endpoint in the inventory."
                )

            severity = self._scorer.score(
                finding_type=finding_type,
                event=event,
                matched_telemetry=matched_device,
                privileged_patterns=self._config.privileged_patterns,
            )

            findings.append(
                Finding(
                    finding_type=finding_type,  # type: ignore[arg-type]
                    severity=severity,
                    source_ip=event.source_ip,
                    expected_ips=expected_ips,
                    connection_event=event,
                    matched_telemetry=matched_device,
                    description=description,
                )
            )

        return findings
