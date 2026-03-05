"""
Tests for canonical Pydantic data models.

@decision DEC-MODEL-001
@title Pydantic v2 canonical models — type safety at ingestion boundary
@status accepted
@rationale Tests validate that all three canonical models (EndpointTelemetry,
           ConnectionEvent, Finding) enforce IP address types, Literal constraints,
           and JSON round-trip fidelity. These properties are the core contract
           the rest of the system depends on.
"""

from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv6Address

import pytest
from pydantic import ValidationError

from debacl.models import ConnectionEvent, EndpointTelemetry, Finding

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

NOW_UTC = datetime(2026, 3, 5, 12, 0, 0, tzinfo=UTC)


def make_telemetry(**overrides) -> EndpointTelemetry:
    defaults = dict(
        device_id="dev-001",
        hostname="laptop-alice",
        public_ip="1.2.3.4",
        source="crowdstrike",
        timestamp=NOW_UTC,
        health_status="healthy",
    )
    defaults.update(overrides)
    return EndpointTelemetry(**defaults)


def make_event(**overrides) -> ConnectionEvent:
    defaults = dict(
        source_ip="1.2.3.4",
        username="alice",
        destination="vpn.example.com",
        event_type="vpn_connect",
        timestamp=NOW_UTC,
        source="okta",
    )
    defaults.update(overrides)
    return ConnectionEvent(**defaults)


def make_finding(**overrides) -> Finding:
    defaults = dict(
        finding_type="ip_mismatch",
        severity="high",
        source_ip="9.9.9.9",
        expected_ips=["1.2.3.4"],
        connection_event=make_event(),
        description="IP mismatch detected",
    )
    defaults.update(overrides)
    return Finding(**defaults)


# ---------------------------------------------------------------------------
# EndpointTelemetry
# ---------------------------------------------------------------------------


class TestEndpointTelemetry:
    def test_valid_instantiation_ipv4(self):
        t = make_telemetry()
        assert t.device_id == "dev-001"
        assert isinstance(t.public_ip, IPv4Address)
        assert t.source == "crowdstrike"

    def test_valid_instantiation_ipv6(self):
        t = make_telemetry(public_ip="2001:db8::1")
        assert isinstance(t.public_ip, IPv6Address)

    def test_optional_fields_default_none(self):
        t = make_telemetry(health_status=None, raw_data=None)
        assert t.health_status is None
        assert t.raw_data is None

    def test_json_round_trip(self):
        t = make_telemetry()
        json_str = t.model_dump_json()
        t2 = EndpointTelemetry.model_validate_json(json_str)
        assert t2.device_id == t.device_id
        assert t2.public_ip == t.public_ip
        assert t2.source == t.source

    def test_invalid_ip_raises(self):
        with pytest.raises(ValidationError):
            make_telemetry(public_ip="not-an-ip")

    def test_invalid_source_raises(self):
        with pytest.raises(ValidationError):
            make_telemetry(source="unknown_edr")

    def test_raw_data_dict_stored(self):
        t = make_telemetry(raw_data={"key": "value", "count": 42})
        assert t.raw_data == {"key": "value", "count": 42}


# ---------------------------------------------------------------------------
# ConnectionEvent
# ---------------------------------------------------------------------------


class TestConnectionEvent:
    def test_valid_instantiation(self):
        e = make_event()
        assert e.username == "alice"
        assert isinstance(e.source_ip, IPv4Address)
        assert e.event_type == "vpn_connect"

    def test_valid_ipv6(self):
        e = make_event(source_ip="::1")
        assert isinstance(e.source_ip, IPv6Address)

    def test_json_round_trip(self):
        e = make_event()
        json_str = e.model_dump_json()
        e2 = ConnectionEvent.model_validate_json(json_str)
        assert e2.username == e.username
        assert e2.source_ip == e.source_ip
        assert e2.event_type == e.event_type

    def test_invalid_ip_raises(self):
        with pytest.raises(ValidationError):
            make_event(source_ip="999.999.999.999")

    def test_invalid_event_type_raises(self):
        with pytest.raises(ValidationError):
            make_event(event_type="ssh_login")

    def test_invalid_source_raises(self):
        with pytest.raises(ValidationError):
            make_event(source="splunk")

    def test_all_event_types_accepted(self):
        for et in ("vpn_connect", "auth_success", "auth_failure"):
            e = make_event(event_type=et)
            assert e.event_type == et

    def test_all_sources_accepted(self):
        for src in ("okta", "entra", "vpn_log"):
            e = make_event(source=src)
            assert e.source == src


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------


class TestFinding:
    def test_valid_instantiation(self):
        f = make_finding()
        assert f.severity == "high"
        assert f.finding_type == "ip_mismatch"
        assert isinstance(f.source_ip, IPv4Address)

    def test_finding_id_auto_generated(self):
        f1 = make_finding()
        f2 = make_finding()
        assert f1.finding_id != f2.finding_id

    def test_timestamp_default_is_utc_aware(self):
        f = make_finding()
        assert f.timestamp.tzinfo is not None

    def test_json_round_trip(self):
        f = make_finding()
        json_str = f.model_dump_json()
        f2 = Finding.model_validate_json(json_str)
        assert f2.finding_id == f.finding_id
        assert f2.severity == f.severity
        assert f2.source_ip == f.source_ip

    def test_invalid_severity_raises(self):
        with pytest.raises(ValidationError):
            make_finding(severity="urgent")

    def test_invalid_finding_type_raises(self):
        with pytest.raises(ValidationError):
            make_finding(finding_type="suspicious_activity")

    def test_matched_telemetry_optional(self):
        f = make_finding(matched_telemetry=None)
        assert f.matched_telemetry is None

    def test_matched_telemetry_accepted(self):
        t = make_telemetry()
        f = make_finding(matched_telemetry=t)
        assert f.matched_telemetry is not None
        assert f.matched_telemetry.device_id == "dev-001"

    def test_expected_ips_list(self):
        f = make_finding(expected_ips=["1.2.3.4", "5.6.7.8"])
        assert len(f.expected_ips) == 2
        assert all(isinstance(ip, IPv4Address) for ip in f.expected_ips)

    def test_all_severities_accepted(self):
        for sev in ("critical", "high", "medium", "low", "info"):
            f = make_finding(severity=sev)
            assert f.severity == sev

    def test_timezone_aware_timestamp_accepted(self):
        ts = datetime(2026, 1, 1, tzinfo=UTC)
        f2 = Finding(
            finding_type="unmanaged_ip",
            severity="low",
            source_ip="1.1.1.1",
            expected_ips=[],
            connection_event=make_event(),
            description="test",
            timestamp=ts,
        )
        assert f2.timestamp.tzinfo is not None
