"""
End-to-end integration test for the full DEBACL pipeline.

W5-1: Exercises the complete data flow:
  generate synthetic data → store → correlate → export → query → API round-trip

No Phase 2 collector dependencies — all data is constructed inline using
canonical Pydantic models directly.

@decision DEC-CORR-001
@title Set-based IP correlation — O(1) membership, auditable, PoC-scale sufficient
@status accepted
@rationale The E2E test validates the full pipeline contract: deterministic inputs
           produce deterministic findings with the correct severity hierarchy.
           Using real in-memory SQLite (not mocks) confirms that the
           repository ↔ engine ↔ exporter integration holds end-to-end.
"""

import csv
import json
from datetime import UTC, datetime

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from debacl.api.app import app, get_engine_dep
from debacl.correlation.engine import CorrelationConfig, CorrelationEngine
from debacl.models.events import ConnectionEvent
from debacl.models.telemetry import EndpointTelemetry
from debacl.output.exporters import FindingExporter
from debacl.storage.database import init_db
from debacl.storage.repository import EventRepository, FindingRepository, TelemetryRepository

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

NOW = datetime(2026, 4, 7, 12, 0, 0, tzinfo=UTC)

# Five known managed-endpoint IPs (TEST-NET-3 block — safe for documentation use)
KNOWN_IPS = [f"203.0.113.{i}" for i in range(1, 6)]

# Unknown IPs used for anomalous events
ADMIN_IP = "198.51.100.99"    # TEST-NET-2 — privileged account hit
REGULAR_IP = "192.0.2.50"    # TEST-NET-1 — regular account hit
EVE_IP = "203.0.113.99"      # looks like managed range but not in inventory


def _make_engine():
    """Return an isolated in-memory SQLite engine with tables initialised.

    StaticPool + check_same_thread=False are required so the FastAPI
    TestClient's thread pool sees the same in-memory connection.
    """
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    init_db(engine)
    return engine


def _make_telemetry(ip: str, idx: int) -> EndpointTelemetry:
    return EndpointTelemetry(
        device_id=f"dev-{idx:03d}",
        hostname=f"workstation-{idx:03d}",
        public_ip=ip,
        source="crowdstrike",
        timestamp=NOW,
        health_status="healthy",
    )


def _make_event(
    source_ip: str,
    username: str,
    event_type: str,
) -> ConnectionEvent:
    return ConnectionEvent(
        source_ip=source_ip,
        username=username,
        destination="corp-vpn.example.com",
        event_type=event_type,
        timestamp=NOW,
        source="okta",
    )


# ---------------------------------------------------------------------------
# Synthetic dataset — built once, shared across test methods in the class
# ---------------------------------------------------------------------------

TELEMETRY_RECORDS = [_make_telemetry(ip, i + 1) for i, ip in enumerate(KNOWN_IPS)]

# 5 clean events from known IPs
CLEAN_EVENTS = [
    _make_event(ip, f"user{i + 1}@corp.com", "auth_success")
    for i, ip in enumerate(KNOWN_IPS)
]

# 3 anomalous events (should each produce a finding)
ANOMALOUS_EVENTS = [
    # critical: admin user, unmanaged IP, auth_success → privileged escalation
    _make_event(ADMIN_IP, "admin@corp.com", "auth_success"),
    # high: regular user, unmanaged IP, auth_success
    _make_event(REGULAR_IP, "john.doe@corp.com", "auth_success"),
    # low: any user, unmanaged IP, auth_failure
    _make_event(EVE_IP, "eve@corp.com", "auth_failure"),
]

ALL_EVENTS = CLEAN_EVENTS + ANOMALOUS_EVENTS


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestE2E:
    """Full pipeline: generate → store → correlate → export → query → API."""

    def test_full_pipeline(self, tmp_path):
        engine = _make_engine()
        telemetry_repo = TelemetryRepository(engine)
        event_repo = EventRepository(engine)
        finding_repo = FindingRepository(engine)

        # ---- Step 1: store synthetic data ----
        for t in TELEMETRY_RECORDS:
            telemetry_repo.save(t)
        for e in ALL_EVENTS:
            event_repo.save(e)

        assert len(telemetry_repo.get_all()) == 5
        assert len(event_repo.get_all()) == 8

        # ---- Step 2: correlate ----
        config = CorrelationConfig(time_window_hours=24)
        correlation_engine = CorrelationEngine(config=config)

        stored_telemetry = telemetry_repo.get_all()
        stored_events = event_repo.get_all()
        findings = correlation_engine.correlate(stored_telemetry, stored_events)

        # Exactly 3 findings — one per anomalous event
        assert len(findings) == 3, f"Expected 3 findings, got {len(findings)}: {findings}"

        # One critical (admin + auth_success)
        critical_findings = [f for f in findings if f.severity == "critical"]
        assert len(critical_findings) == 1, f"Expected 1 critical finding, got {critical_findings}"

        # One high (regular + auth_success)
        high_findings = [f for f in findings if f.severity == "high"]
        assert len(high_findings) == 1, f"Expected 1 high finding, got {high_findings}"

        # One low (auth_failure)
        low_findings = [f for f in findings if f.severity == "low"]
        assert len(low_findings) == 1, f"Expected 1 low finding, got {low_findings}"

        # All findings have non-empty descriptions
        for f in findings:
            assert f.description, f"Finding {f.finding_id} has empty description"

        # All findings have valid UUIDs
        for f in findings:
            assert f.finding_id is not None
            # UUID.__str__ produces a standard 36-char hyphenated string
            assert len(str(f.finding_id)) == 36

        # ---- Step 3: persist findings ----
        for f in findings:
            finding_repo.save(f)

        # ---- Step 4: export ----
        exporter = FindingExporter(output_dir=str(tmp_path))

        # JSON export
        json_path = str(tmp_path / "findings.json")
        exporter.export_json(findings, filename=json_path)
        with open(json_path, encoding="utf-8") as fh:
            json_data = json.load(fh)
        assert len(json_data) == 3
        assert all("finding_type" in item for item in json_data)

        # CSV export
        csv_path = str(tmp_path / "findings.csv")
        exporter.export_csv(findings, filename=csv_path)
        with open(csv_path, encoding="utf-8", newline="") as fh:
            reader = csv.DictReader(fh)
            rows = list(reader)
        assert len(rows) == 3
        assert "severity" in reader.fieldnames

        # SIEM JSON Lines export
        jsonl_path = str(tmp_path / "findings.jsonl")
        exporter.export_siem_jsonl(findings, filename=jsonl_path)
        with open(jsonl_path, encoding="utf-8") as fh:
            lines = [line.strip() for line in fh if line.strip()]
        assert len(lines) == 3
        for line in lines:
            record = json.loads(line)
            assert "@timestamp" in record

        # ---- Step 5: query repo ----
        assert len(finding_repo.get_by_severity("critical")) == 1
        assert len(finding_repo.get_by_severity("high")) == 1
        assert len(finding_repo.get_all()) == 3

        # ---- Step 6: API round-trip ----
        app.dependency_overrides[get_engine_dep] = lambda: engine
        try:
            client = TestClient(app)

            # GET /findings → 3 items
            resp = client.get("/findings")
            assert resp.status_code == 200
            assert len(resp.json()) == 3

            # GET /findings?severity=critical → 1 item
            resp = client.get("/findings?severity=critical")
            assert resp.status_code == 200
            assert len(resp.json()) == 1
            assert resp.json()[0]["severity"] == "critical"

            # POST /correlate → runs engine on stored data, returns findings_count
            # (findings already in DB from step 3 — correlate runs again on events,
            #  so findings_count reflects a fresh run; we verify it is non-negative
            #  and the response schema is correct)
            resp = client.post("/correlate", json={"window_hours": 24})
            assert resp.status_code == 200
            body = resp.json()
            assert "findings_count" in body
            assert isinstance(body["findings_count"], int)
            assert body["findings_count"] >= 0
        finally:
            app.dependency_overrides.clear()

    def test_empty_pipeline(self, tmp_path):
        """Empty telemetry + empty events → 0 findings, valid empty exports."""
        correlation_engine = CorrelationEngine()

        findings = correlation_engine.correlate([], [])
        assert findings == []

        exporter = FindingExporter(output_dir=str(tmp_path))

        # Empty JSON → valid JSON array
        json_path = str(tmp_path / "empty.json")
        exporter.export_json(findings, filename=json_path)
        with open(json_path, encoding="utf-8") as fh:
            data = json.load(fh)
        assert data == []

        # Empty CSV → headers only, no data rows
        csv_path = str(tmp_path / "empty.csv")
        exporter.export_csv(findings, filename=csv_path)
        with open(csv_path, encoding="utf-8", newline="") as fh:
            reader = csv.DictReader(fh)
            rows = list(reader)
        assert rows == []
        assert reader.fieldnames is not None
        assert len(reader.fieldnames) > 0
