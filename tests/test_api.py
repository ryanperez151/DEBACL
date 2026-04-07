"""
Tests for FastAPI DEBACL endpoints.

@decision DEC-MODEL-001
@title FastAPI with Pydantic models — native integration, auto-generated OpenAPI docs
@status accepted
@rationale TestClient lets tests run the full ASGI app synchronously without a server.
           Tests inject an in-memory SQLite engine via dependency_overrides on
           get_engine_dep — the single root dependency — so all repos automatically
           use the isolated in-memory database. Each fixture seeds its own data to
           avoid cross-test state.
"""

from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from debacl.api.app import app, get_engine_dep
from debacl.models.events import ConnectionEvent
from debacl.models.findings import Finding
from debacl.models.telemetry import EndpointTelemetry
from debacl.storage.database import init_db
from debacl.storage.repository import EventRepository, FindingRepository, TelemetryRepository

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

NOW_UTC = datetime(2026, 3, 5, 12, 0, 0, tzinfo=UTC)


def make_in_memory_engine():
    """Return a fresh in-memory SQLite engine with tables created.

    StaticPool + check_same_thread=False are required so FastAPI's threadpool
    executor can access the same in-memory connection that was initialised in
    the test thread.  Without StaticPool, each SQLAlchemy checkout creates a
    new connection, which sees an empty database with no tables.
    """
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    init_db(engine)
    return engine


def make_event(**overrides) -> ConnectionEvent:
    defaults = dict(
        source_ip="10.0.0.1",
        username="alice@example.com",
        destination="vpn.example.com",
        event_type="vpn_connect",
        timestamp=NOW_UTC,
        source="okta",
    )
    defaults.update(overrides)
    return ConnectionEvent(**defaults)


def make_telemetry(**overrides) -> EndpointTelemetry:
    defaults = dict(
        device_id="dev-001",
        hostname="laptop-alice",
        public_ip="10.0.0.2",
        source="crowdstrike",
        timestamp=NOW_UTC,
        health_status="healthy",
    )
    defaults.update(overrides)
    return EndpointTelemetry(**defaults)


def make_finding(**overrides) -> Finding:
    defaults = dict(
        finding_type="unmanaged_ip",
        severity="high",
        source_ip="10.0.0.1",
        expected_ips=[],
        connection_event=make_event(),
        matched_telemetry=None,
        description="Test finding.",
        timestamp=NOW_UTC,
    )
    defaults.update(overrides)
    return Finding(**defaults)


@pytest.fixture
def client_with_data():
    """TestClient with seeded in-memory repos via get_engine_dep override."""
    engine = make_in_memory_engine()

    # Seed data into the in-memory engine
    TelemetryRepository(engine).save(make_telemetry())
    EventRepository(engine).save(make_event())
    finding = make_finding()
    FindingRepository(engine).save(finding)

    # Override the root engine dependency so all repo factories use our engine
    app.dependency_overrides[get_engine_dep] = lambda: engine

    client = TestClient(app)
    yield client, finding

    app.dependency_overrides.clear()


@pytest.fixture
def client_empty():
    """TestClient with empty in-memory repos."""
    engine = make_in_memory_engine()
    app.dependency_overrides[get_engine_dep] = lambda: engine

    client = TestClient(app)
    yield client

    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# /health
# ---------------------------------------------------------------------------


class TestHealth:
    def test_returns_200(self, client_empty):
        resp = client_empty.get("/health")
        assert resp.status_code == 200

    def test_returns_ok_status(self, client_empty):
        resp = client_empty.get("/health")
        assert resp.json()["status"] == "ok"

    def test_returns_version(self, client_empty):
        resp = client_empty.get("/health")
        assert "version" in resp.json()


# ---------------------------------------------------------------------------
# /findings
# ---------------------------------------------------------------------------


class TestFindings:
    def test_list_returns_200(self, client_with_data):
        client, _ = client_with_data
        resp = client.get("/findings")
        assert resp.status_code == 200

    def test_list_returns_list(self, client_with_data):
        client, _ = client_with_data
        resp = client.get("/findings")
        assert isinstance(resp.json(), list)

    def test_list_contains_seeded_finding(self, client_with_data):
        client, finding = client_with_data
        resp = client.get("/findings")
        ids = [f["finding_id"] for f in resp.json()]
        assert str(finding.finding_id) in ids

    def test_empty_db_returns_empty_list(self, client_empty):
        resp = client_empty.get("/findings")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_severity_filter_returns_matching(self, client_with_data):
        client, finding = client_with_data
        resp = client.get(f"/findings?severity={finding.severity}")
        assert resp.status_code == 200
        results = resp.json()
        assert all(f["severity"] == finding.severity for f in results)

    def test_severity_filter_excludes_non_matching(self, client_with_data):
        client, _ = client_with_data
        resp = client.get("/findings?severity=info")
        assert resp.status_code == 200
        results = resp.json()
        # Our seeded finding is "high", not "info"
        assert all(f["severity"] == "info" for f in results)

    def test_get_by_valid_id_returns_200(self, client_with_data):
        client, finding = client_with_data
        resp = client.get(f"/findings/{finding.finding_id}")
        assert resp.status_code == 200

    def test_get_by_valid_id_returns_finding(self, client_with_data):
        client, finding = client_with_data
        resp = client.get(f"/findings/{finding.finding_id}")
        assert resp.json()["finding_id"] == str(finding.finding_id)

    def test_get_by_unknown_id_returns_404(self, client_empty):
        resp = client_empty.get("/findings/00000000-0000-0000-0000-000000000000")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# /telemetry
# ---------------------------------------------------------------------------


class TestTelemetry:
    def test_list_returns_200(self, client_with_data):
        client, _ = client_with_data
        resp = client.get("/telemetry")
        assert resp.status_code == 200

    def test_list_returns_list(self, client_with_data):
        client, _ = client_with_data
        resp = client.get("/telemetry")
        assert isinstance(resp.json(), list)

    def test_list_contains_seeded_record(self, client_with_data):
        client, _ = client_with_data
        resp = client.get("/telemetry")
        assert len(resp.json()) >= 1

    def test_empty_db_returns_empty_list(self, client_empty):
        resp = client_empty.get("/telemetry")
        assert resp.status_code == 200
        assert resp.json() == []


# ---------------------------------------------------------------------------
# /events
# ---------------------------------------------------------------------------


class TestEvents:
    def test_list_returns_200(self, client_with_data):
        client, _ = client_with_data
        resp = client.get("/events")
        assert resp.status_code == 200

    def test_list_returns_list(self, client_with_data):
        client, _ = client_with_data
        resp = client.get("/events")
        assert isinstance(resp.json(), list)

    def test_list_contains_seeded_event(self, client_with_data):
        client, _ = client_with_data
        resp = client.get("/events")
        assert len(resp.json()) >= 1

    def test_empty_db_returns_empty_list(self, client_empty):
        resp = client_empty.get("/events")
        assert resp.status_code == 200
        assert resp.json() == []


# ---------------------------------------------------------------------------
# POST /correlate
# ---------------------------------------------------------------------------


class TestCorrelate:
    def test_returns_200(self, client_empty):
        resp = client_empty.post("/correlate", json={"window_hours": 24})
        assert resp.status_code == 200

    def test_returns_findings_count(self, client_empty):
        resp = client_empty.post("/correlate", json={"window_hours": 24})
        body = resp.json()
        assert "findings_count" in body
        assert isinstance(body["findings_count"], int)

    def test_returns_findings_list(self, client_empty):
        resp = client_empty.post("/correlate", json={"window_hours": 24})
        body = resp.json()
        assert "findings" in body
        assert isinstance(body["findings"], list)

    def test_empty_db_produces_zero_findings(self, client_empty):
        resp = client_empty.post("/correlate", json={"window_hours": 24})
        body = resp.json()
        assert body["findings_count"] == 0
        assert body["findings"] == []

    def test_default_body_works(self, client_empty):
        """POST /correlate with no body uses default window_hours=24."""
        resp = client_empty.post("/correlate")
        assert resp.status_code == 200

    def test_findings_count_matches_list_length(self, client_empty):
        resp = client_empty.post("/correlate", json={"window_hours": 24})
        body = resp.json()
        assert body["findings_count"] == len(body["findings"])
