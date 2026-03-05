"""
Tests for the SQLite storage layer (repositories).

@decision DEC-STORE-001
@title SQLite via SQLAlchemy — zero infrastructure, migration path to Postgres
@status accepted
@rationale Uses sqlite:///:memory: so tests are isolated, fast, and leave no
           file-system artifacts. Tests cover insert + retrieve for all three
           repositories and exercise all filter methods (get_by_source, get_by_ip,
           get_by_severity, get_since).
"""

from datetime import UTC, datetime, timedelta

import pytest

from debacl.models import ConnectionEvent, EndpointTelemetry, Finding
from debacl.storage.database import get_engine, init_db
from debacl.storage.repository import EventRepository, FindingRepository, TelemetryRepository

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

NOW = datetime(2026, 3, 5, 12, 0, 0, tzinfo=UTC)
EARLIER = NOW - timedelta(hours=2)
LATER = NOW + timedelta(hours=1)


@pytest.fixture()
def engine():
    """In-memory SQLite engine, tables created fresh for each test."""
    eng = get_engine("sqlite:///:memory:")
    init_db(eng)
    return eng


@pytest.fixture()
def telemetry_repo(engine):
    return TelemetryRepository(engine)


@pytest.fixture()
def event_repo(engine):
    return EventRepository(engine)


@pytest.fixture()
def finding_repo(engine):
    return FindingRepository(engine)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_telemetry(**overrides) -> EndpointTelemetry:
    defaults = dict(
        device_id="dev-001",
        hostname="laptop-alice",
        public_ip="1.2.3.4",
        source="crowdstrike",
        timestamp=NOW,
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
        timestamp=NOW,
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
        timestamp=NOW,
    )
    defaults.update(overrides)
    return Finding(**defaults)


# ---------------------------------------------------------------------------
# TelemetryRepository
# ---------------------------------------------------------------------------


class TestTelemetryRepository:
    def test_save_and_get_all(self, telemetry_repo):
        t = make_telemetry()
        telemetry_repo.save(t)
        results = telemetry_repo.get_all()
        assert len(results) == 1
        assert results[0].device_id == "dev-001"
        assert str(results[0].public_ip) == "1.2.3.4"

    def test_get_all_multiple(self, telemetry_repo):
        telemetry_repo.save(make_telemetry(device_id="dev-001"))
        telemetry_repo.save(make_telemetry(device_id="dev-002", source="intune"))
        results = telemetry_repo.get_all()
        assert len(results) == 2

    def test_get_by_source_match(self, telemetry_repo):
        telemetry_repo.save(make_telemetry(source="crowdstrike"))
        telemetry_repo.save(make_telemetry(device_id="dev-002", source="intune"))
        results = telemetry_repo.get_by_source("crowdstrike")
        assert len(results) == 1
        assert results[0].source == "crowdstrike"

    def test_get_by_source_no_match(self, telemetry_repo):
        telemetry_repo.save(make_telemetry(source="crowdstrike"))
        results = telemetry_repo.get_by_source("jamf")
        assert results == []

    def test_get_by_ip_match(self, telemetry_repo):
        telemetry_repo.save(make_telemetry(public_ip="1.2.3.4"))
        telemetry_repo.save(make_telemetry(device_id="dev-002", public_ip="5.6.7.8"))
        results = telemetry_repo.get_by_ip("1.2.3.4")
        assert len(results) == 1
        assert str(results[0].public_ip) == "1.2.3.4"

    def test_get_by_ip_no_match(self, telemetry_repo):
        telemetry_repo.save(make_telemetry(public_ip="1.2.3.4"))
        results = telemetry_repo.get_by_ip("9.9.9.9")
        assert results == []

    def test_health_status_preserved(self, telemetry_repo):
        telemetry_repo.save(make_telemetry(health_status="degraded"))
        results = telemetry_repo.get_all()
        assert results[0].health_status == "degraded"

    def test_null_health_status_preserved(self, telemetry_repo):
        telemetry_repo.save(make_telemetry(health_status=None))
        results = telemetry_repo.get_all()
        assert results[0].health_status is None


# ---------------------------------------------------------------------------
# EventRepository
# ---------------------------------------------------------------------------


class TestEventRepository:
    def test_save_and_get_all(self, event_repo):
        e = make_event()
        event_repo.save(e)
        results = event_repo.get_all()
        assert len(results) == 1
        assert results[0].username == "alice"
        assert str(results[0].source_ip) == "1.2.3.4"

    def test_get_all_multiple(self, event_repo):
        event_repo.save(make_event(username="alice"))
        event_repo.save(make_event(username="bob", source="entra"))
        results = event_repo.get_all()
        assert len(results) == 2

    def test_get_by_source_match(self, event_repo):
        event_repo.save(make_event(source="okta"))
        event_repo.save(make_event(username="bob", source="entra"))
        results = event_repo.get_by_source("okta")
        assert len(results) == 1
        assert results[0].source == "okta"

    def test_get_by_source_no_match(self, event_repo):
        event_repo.save(make_event(source="okta"))
        results = event_repo.get_by_source("vpn_log")
        assert results == []

    def test_get_by_ip_match(self, event_repo):
        event_repo.save(make_event(source_ip="1.2.3.4"))
        event_repo.save(make_event(username="bob", source_ip="5.6.7.8"))
        results = event_repo.get_by_ip("1.2.3.4")
        assert len(results) == 1
        assert str(results[0].source_ip) == "1.2.3.4"

    def test_get_by_ip_no_match(self, event_repo):
        event_repo.save(make_event(source_ip="1.2.3.4"))
        results = event_repo.get_by_ip("9.9.9.9")
        assert results == []

    def test_event_type_preserved(self, event_repo):
        event_repo.save(make_event(event_type="auth_failure"))
        results = event_repo.get_all()
        assert results[0].event_type == "auth_failure"


# ---------------------------------------------------------------------------
# FindingRepository
# ---------------------------------------------------------------------------


class TestFindingRepository:
    def test_save_and_get_all(self, finding_repo):
        f = make_finding()
        finding_repo.save(f)
        results = finding_repo.get_all()
        assert len(results) == 1
        assert results[0].finding_type == "ip_mismatch"
        assert results[0].severity == "high"

    def test_finding_id_preserved(self, finding_repo):
        f = make_finding()
        finding_repo.save(f)
        results = finding_repo.get_all()
        assert str(results[0].finding_id) == str(f.finding_id)

    def test_connection_event_round_trip(self, finding_repo):
        f = make_finding()
        finding_repo.save(f)
        results = finding_repo.get_all()
        assert results[0].connection_event.username == "alice"
        assert results[0].connection_event.event_type == "vpn_connect"

    def test_matched_telemetry_none_preserved(self, finding_repo):
        f = make_finding(matched_telemetry=None)
        finding_repo.save(f)
        results = finding_repo.get_all()
        assert results[0].matched_telemetry is None

    def test_matched_telemetry_round_trip(self, finding_repo):
        t = make_telemetry()
        f = make_finding(matched_telemetry=t)
        finding_repo.save(f)
        results = finding_repo.get_all()
        assert results[0].matched_telemetry is not None
        assert results[0].matched_telemetry.device_id == "dev-001"

    def test_get_by_severity_match(self, finding_repo):
        finding_repo.save(make_finding(severity="high"))
        finding_repo.save(make_finding(severity="low"))
        results = finding_repo.get_by_severity("high")
        assert len(results) == 1
        assert results[0].severity == "high"

    def test_get_by_severity_no_match(self, finding_repo):
        finding_repo.save(make_finding(severity="low"))
        results = finding_repo.get_by_severity("critical")
        assert results == []

    def test_get_since_includes_at_boundary(self, finding_repo):
        f = make_finding(timestamp=NOW)
        finding_repo.save(f)
        results = finding_repo.get_since(NOW)
        assert len(results) == 1

    def test_get_since_excludes_earlier(self, finding_repo):
        finding_repo.save(make_finding(timestamp=EARLIER))
        results = finding_repo.get_since(NOW)
        assert results == []

    def test_get_since_includes_later(self, finding_repo):
        finding_repo.save(make_finding(timestamp=LATER))
        results = finding_repo.get_since(NOW)
        assert len(results) == 1

    def test_get_all_multiple_findings(self, finding_repo):
        finding_repo.save(make_finding(severity="high"))
        finding_repo.save(make_finding(severity="critical"))
        results = finding_repo.get_all()
        assert len(results) == 2
