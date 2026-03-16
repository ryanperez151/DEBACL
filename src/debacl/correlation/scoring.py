"""
Severity scoring for correlation findings.

@decision DEC-CORR-001
@title Severity rules are data, not logic — configurable thresholds decouple policy from engine
@status accepted
@rationale Different organizations have different risk tolerances. Privileged-account
           escalation is handled as a post-classification step: unmanaged_ip + auth_success
           is normally "high", but escalates to "critical" when the username matches a
           privileged pattern (admin, svc-*, root, system). This keeps the base matrix
           readable while encoding the most important security signal. Fall-through to
           "info" for unrecognised combinations avoids silently dropping findings.
"""

from typing import Literal

from debacl.models.events import ConnectionEvent
from debacl.models.telemetry import EndpointTelemetry

SEVERITY_ORDER: dict[str, int] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}

_DEFAULT_RULES: dict[str, dict[str, str]] = {
    "unmanaged_ip": {
        "auth_success": "high",
        "vpn_connect": "critical",
        "auth_failure": "low",
    },
    "ip_mismatch": {
        "auth_success": "medium",
        "vpn_connect": "high",
        "auth_failure": "low",
    },
    "unknown_device": {
        "auth_success": "medium",
        "vpn_connect": "medium",
        "auth_failure": "info",
    },
    "info": {},
}

_VALID_SEVERITIES: frozenset[str] = frozenset({"critical", "high", "medium", "low", "info"})


def is_privileged(username: str, patterns: list[str]) -> bool:
    """Return True if *username* contains any privileged pattern (case-insensitive).

    Matching is substring-based so patterns like "svc-" match "svc-backup@corp.com"
    without requiring a full prefix/suffix anchor.

    Args:
        username: The full username string (e.g. "admin@corp.com").
        patterns: List of substrings that indicate a privileged account
                  (e.g. ["admin", "svc-", "root", "system"]).
    """
    lower = username.lower()
    return any(p.lower() in lower for p in patterns)


class SeverityScorer:
    """Maps (finding_type, event, privileged) tuples to a severity level.

    The base matrix covers common (finding_type, event_type) combinations.
    Privileged-account escalation is applied on top: an unmanaged_ip hit on
    auth_success that would normally be "high" escalates to "critical" when
    the username matches a privileged pattern.

    Args:
        rules: Optional custom rules dict with the same structure as the default
               scoring matrix. Any provided keys override the defaults; missing
               keys fall through to the defaults and ultimately to "info".
    """

    def __init__(self, rules: dict | None = None) -> None:
        # Start from defaults; overlay custom rules on top
        self._rules: dict[str, dict[str, str]] = {
            k: dict(v) for k, v in _DEFAULT_RULES.items()
        }
        if rules:
            for finding_type, event_map in rules.items():
                if finding_type not in self._rules:
                    self._rules[finding_type] = {}
                self._rules[finding_type].update(event_map)

    def score(
        self,
        finding_type: str,
        event: ConnectionEvent,
        matched_telemetry: EndpointTelemetry | None = None,
        privileged_patterns: list[str] | None = None,
    ) -> Literal["critical", "high", "medium", "low", "info"]:
        """Return the severity for a (finding_type, event) combination.

        Privileged escalation rule:
          - unmanaged_ip + auth_success/vpn_connect + privileged username → "critical"

        Falls back to "info" for the ``"info"`` finding type and to "info" for
        any combination not covered by the rules matrix.

        Args:
            finding_type: One of "unmanaged_ip", "ip_mismatch", "unknown_device", "info".
            event: The ConnectionEvent that triggered the finding.
            matched_telemetry: Optional device telemetry matched to this event (unused
                               in base scoring but available for custom rule extensions).
            privileged_patterns: Username substrings that indicate privileged accounts.
                                 Defaults to ["admin", "svc-", "root", "system"].
        """
        if finding_type == "info":
            return "info"

        effective_patterns: list[str] = (
            privileged_patterns
            if privileged_patterns is not None
            else ["admin", "svc-", "root", "system"]
        )

        event_map = self._rules.get(finding_type, {})
        severity = event_map.get(event.event_type, "info")

        # Escalate unmanaged_ip + successful connection + privileged account → critical
        if (
            finding_type == "unmanaged_ip"
            and event.event_type in {"auth_success", "vpn_connect"}
            and is_privileged(event.username, effective_patterns)
        ):
            severity = "critical"

        return severity if severity in _VALID_SEVERITIES else "info"  # type: ignore[return-value]
