"""
Tests for the CorrelationEngine.

All test fixtures are inline — no dependency on Phase 2 mock_data.
Timestamps are set well within the 24-hour default window so time-window
filtering never interferes with classification correctness tests.
"""

from datetime import UTC, datetime
from ipaddress import IPv4Address
from uuid import UUID

from debacl.correlation.engine import CorrelationConfig, CorrelationEngine
from debacl.models.events import ConnectionEvent
from debacl.models.telemetry import EndpointTelemetry

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_NOW = datetime.now(UTC)


def _telemetry(
    device_id: str,
    hostname: str,
    ip: str,
) -> EndpointTelemetry:
    return EndpointTelemetry(
        device_id=device_id,
        hostname=hostname,
        public_ip=IPv4Address(ip),
        source="crowdstrike",
        timestamp=_NOW,
    )


def _event(
    ip: str,
    username: str = "john.doe@corp.com",
    event_type: str = "auth_success",
) -> ConnectionEvent:
    return ConnectionEvent(
        source_ip=IPv4Address(ip),
        username=username,
        destination="vpn.corp.com",
        event_type=event_type,  # type: ignore[arg-type]
        timestamp=_NOW,
        source="okta",
    )


# ---------------------------------------------------------------------------
# Scenario 1 — Clean: all event IPs are in the known-IP set
# ---------------------------------------------------------------------------


class TestScenario1Clean:
    def test_no_findings_when_all_ips_known(self) -> None:
        telemetry = [
            _telemetry("d1", "ws-alice", "10.0.0.1"),
            _telemetry("d2", "ws-bob", "10.0.0.2"),
            _telemetry("d3", "ws-carol", "10.0.0.3"),
        ]
        events = [
            _event("10.0.0.1"),
            _event("10.0.0.2"),
            _event("10.0.0.3"),
        ]
        engine = CorrelationEngine()
        findings = engine.correlate(telemetry, events)
        assert findings == []


# ---------------------------------------------------------------------------
# Scenario 2 — Unmanaged IP, successful auth, non-privileged user → high
# ---------------------------------------------------------------------------


class TestScenario2UnmanagedHigh:
    def test_unmanaged_ip_auth_success_non_privileged_is_high(self) -> None:
        telemetry = [
            _telemetry("d1", "ws-alice", "10.0.0.1"),
            _telemetry("d2", "ws-bob", "10.0.0.2"),
        ]
        events = [_event("10.0.0.99", username="john.doe@corp.com", event_type="auth_success")]
        engine = CorrelationEngine()
        findings = engine.correlate(telemetry, events)

        assert len(findings) == 1
        f = findings[0]
        assert f.finding_type == "unmanaged_ip"
        assert f.severity == "high"


# ---------------------------------------------------------------------------
# Scenario 3 — Unmanaged IP, successful auth, privileged user → critical
# ---------------------------------------------------------------------------


class TestScenario3UnmanagedCritical:
    def test_unmanaged_ip_auth_success_privileged_is_critical(self) -> None:
        telemetry = [
            _telemetry("d1", "ws-alice", "10.0.0.1"),
            _telemetry("d2", "ws-bob", "10.0.0.2"),
        ]
        events = [_event("10.0.0.99", username="admin@corp.com", event_type="auth_success")]
        engine = CorrelationEngine()
        findings = engine.correlate(telemetry, events)

        assert len(findings) == 1
        f = findings[0]
        assert f.finding_type == "unmanaged_ip"
        assert f.severity == "critical"

    def test_svc_account_is_also_critical(self) -> None:
        telemetry = [_telemetry("d1", "ws-host", "10.0.0.1")]
        events = [_event("10.0.0.99", username="svc-deploy@corp.com", event_type="auth_success")]
        engine = CorrelationEngine()
        findings = engine.correlate(telemetry, events)

        assert len(findings) == 1
        assert findings[0].severity == "critical"


# ---------------------------------------------------------------------------
# Scenario 4 — Unmanaged IP, failed auth → low
# ---------------------------------------------------------------------------


class TestScenario4UnmanagedLow:
    def test_unmanaged_ip_auth_failure_is_low(self) -> None:
        telemetry = [
            _telemetry("d1", "ws-alice", "10.0.0.1"),
            _telemetry("d2", "ws-bob", "10.0.0.2"),
        ]
        events = [_event("10.0.0.99", event_type="auth_failure")]
        engine = CorrelationEngine()
        findings = engine.correlate(telemetry, events)

        assert len(findings) == 1
        assert findings[0].severity == "low"


# ---------------------------------------------------------------------------
# Scenario 5 — Mixed: some known, some unknown
# ---------------------------------------------------------------------------


class TestScenario5Mixed:
    def test_mixed_events_produce_correct_finding_count(self) -> None:
        telemetry = [
            _telemetry("d1", "ws-alpha", "192.168.1.1"),
            _telemetry("d2", "ws-beta", "192.168.1.2"),
            _telemetry("d3", "ws-gamma", "192.168.1.3"),
        ]
        events = [
            _event("192.168.1.1"),  # clean
            _event("192.168.1.2"),  # clean
            _event("192.168.1.3"),  # clean
            _event("10.0.0.50", username="nobody@corp.com", event_type="auth_success"),  # unmanaged
            _event("10.0.0.51", event_type="auth_failure"),  # unmanaged low
        ]
        engine = CorrelationEngine()
        findings = engine.correlate(telemetry, events)

        assert len(findings) == 2
        types = {f.finding_type for f in findings}
        assert types == {"unmanaged_ip"}
        severities = {f.severity for f in findings}
        assert severities == {"high", "low"}


# ---------------------------------------------------------------------------
# Scenario 6 — Empty inputs
# ---------------------------------------------------------------------------


class TestScenario6EmptyInputs:
    def test_no_telemetry_all_events_are_unmanaged(self) -> None:
        events = [
            _event("10.0.0.1"),
            _event("10.0.0.2"),
            _event("10.0.0.3"),
        ]
        engine = CorrelationEngine()
        findings = engine.correlate([], events)

        assert len(findings) == 3
        assert all(f.finding_type == "unmanaged_ip" for f in findings)

    def test_no_events_produces_no_findings(self) -> None:
        telemetry = [
            _telemetry("d1", "ws-a", "10.0.0.1"),
            _telemetry("d2", "ws-b", "10.0.0.2"),
            _telemetry("d3", "ws-c", "10.0.0.3"),
        ]
        engine = CorrelationEngine()
        findings = engine.correlate(telemetry, [])
        assert findings == []

    def test_both_empty_produces_no_findings(self) -> None:
        engine = CorrelationEngine()
        assert engine.correlate([], []) == []


# ---------------------------------------------------------------------------
# Scenario 7 — Finding field integrity
# ---------------------------------------------------------------------------


class TestScenario7FindingFields:
    def test_finding_has_required_fields(self) -> None:
        telemetry = [_telemetry("d1", "ws-host", "10.0.0.1")]
        event = _event("10.0.0.99", username="bob@corp.com", event_type="auth_success")
        engine = CorrelationEngine()
        findings = engine.correlate(telemetry, [event])

        assert len(findings) == 1
        f = findings[0]

        # finding_id must be a valid UUID
        assert isinstance(f.finding_id, UUID)

        # source_ip must match the event source
        assert str(f.source_ip) == "10.0.0.99"

        # finding_type must be set
        assert f.finding_type in {"unmanaged_ip", "ip_mismatch", "unknown_device", "info"}

        # severity must be set
        assert f.severity in {"critical", "high", "medium", "low", "info"}

        # connection_event must be the triggering event
        assert f.connection_event is event

        # description must be a non-empty string
        assert isinstance(f.description, str)
        assert len(f.description) > 0

    def test_finding_id_is_unique_per_finding(self) -> None:
        """Each Finding gets a different UUID even when inputs are identical."""
        telemetry: list[EndpointTelemetry] = []
        events = [_event("10.0.0.1"), _event("10.0.0.1")]
        engine = CorrelationEngine()
        findings = engine.correlate(telemetry, events)

        ids = [f.finding_id for f in findings]
        assert len(set(ids)) == len(ids), "Duplicate finding_ids detected"

    def test_finding_description_mentions_source_ip(self) -> None:
        event = _event("172.16.0.5", username="mystery@corp.com", event_type="auth_failure")
        engine = CorrelationEngine()
        findings = engine.correlate([], [event])

        assert "172.16.0.5" in findings[0].description


# ---------------------------------------------------------------------------
# Additional edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_ipv6_source_ip_is_classified_correctly(self) -> None:
        from ipaddress import IPv6Address

        telemetry = [
            EndpointTelemetry(
                device_id="d-v6",
                hostname="ws-ipv6",
                public_ip=IPv6Address("2001:db8::1"),
                source="crowdstrike",
                timestamp=_NOW,
            )
        ]
        event = ConnectionEvent(
            source_ip=IPv6Address("2001:db8::2"),
            username="user@corp.com",
            destination="vpn.corp.com",
            event_type="auth_success",
            timestamp=_NOW,
            source="okta",
        )
        engine = CorrelationEngine()
        findings = engine.correlate(telemetry, [event])

        assert len(findings) == 1
        assert findings[0].finding_type == "unmanaged_ip"

    def test_clean_ipv6_produces_no_finding(self) -> None:
        from ipaddress import IPv6Address

        ip = IPv6Address("2001:db8::1")
        telemetry = [
            EndpointTelemetry(
                device_id="d-v6",
                hostname="ws-ipv6",
                public_ip=ip,
                source="crowdstrike",
                timestamp=_NOW,
            )
        ]
        event = ConnectionEvent(
            source_ip=ip,
            username="user@corp.com",
            destination="vpn.corp.com",
            event_type="auth_success",
            timestamp=_NOW,
            source="okta",
        )
        engine = CorrelationEngine()
        assert engine.correlate(telemetry, [event]) == []

    def test_custom_privileged_patterns_respected(self) -> None:
        config = CorrelationConfig(privileged_patterns=["superuser"])
        engine = CorrelationEngine(config=config)

        telemetry: list[EndpointTelemetry] = []
        # "superuser@corp.com" matches custom pattern → critical
        findings_priv = engine.correlate(
            telemetry, [_event("10.0.0.1", username="superuser@corp.com")]
        )
        # "admin@corp.com" does NOT match custom pattern → high (not in ["superuser"])
        findings_regular = engine.correlate(
            telemetry, [_event("10.0.0.2", username="admin@corp.com")]
        )

        assert findings_priv[0].severity == "critical"
        assert findings_regular[0].severity == "high"
