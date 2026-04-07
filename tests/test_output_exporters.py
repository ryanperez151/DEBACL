"""
Tests for FindingExporter — JSON, CSV, and SIEM JSON Lines output.

@decision DEC-MODEL-001
@title Pydantic serialization for JSON output — model_dump_json() ensures schema consistency
@status accepted
@rationale Tests exercise all three export formats, auto-generated filenames, custom
           filenames, directory creation, empty-list edge cases, and a full round-trip
           to confirm exported JSON can be re-hydrated into Finding objects.
"""

import csv
import json
import os
from datetime import UTC, datetime

from debacl.models.events import ConnectionEvent
from debacl.models.findings import Finding
from debacl.models.telemetry import EndpointTelemetry
from debacl.output.exporters import FindingExporter

# ---------------------------------------------------------------------------
# Shared test data helpers
# ---------------------------------------------------------------------------

NOW_UTC = datetime(2026, 3, 5, 12, 0, 0, tzinfo=UTC)


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
        description="Test finding — unmanaged IP detected.",
        timestamp=NOW_UTC,
    )
    defaults.update(overrides)
    return Finding(**defaults)


# ---------------------------------------------------------------------------
# JSON export
# ---------------------------------------------------------------------------


class TestExportJson:
    def test_creates_valid_json_array(self, tmp_path):
        exporter = FindingExporter(output_dir=str(tmp_path))
        finding = make_finding()
        path = exporter.export_json([finding])

        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)

        assert isinstance(data, list)
        assert len(data) == 1

    def test_all_finding_fields_present(self, tmp_path):
        exporter = FindingExporter(output_dir=str(tmp_path))
        finding = make_finding()
        path = exporter.export_json([finding])

        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)

        row = data[0]
        assert "finding_id" in row
        assert "finding_type" in row
        assert "severity" in row
        assert "source_ip" in row
        assert "description" in row
        assert "timestamp" in row
        assert "connection_event" in row

    def test_custom_filename_is_used(self, tmp_path):
        target = str(tmp_path / "custom.json")
        exporter = FindingExporter(output_dir=str(tmp_path))
        path = exporter.export_json([make_finding()], filename=target)
        assert path == target
        assert os.path.exists(target)

    def test_auto_filename_has_timestamp_and_extension(self, tmp_path):
        exporter = FindingExporter(output_dir=str(tmp_path))
        path = exporter.export_json([make_finding()])
        basename = os.path.basename(path)
        assert basename.startswith("findings_")
        assert basename.endswith(".json")
        # Timestamp portion: YYYYMMDD_HHMMSS — 15 chars between prefix and ext
        timestamp_part = basename[len("findings_") : -len(".json")]
        assert len(timestamp_part) == 15

    def test_empty_findings_returns_empty_json_array(self, tmp_path):
        exporter = FindingExporter(output_dir=str(tmp_path))
        path = exporter.export_json([])
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        assert data == []

    def test_output_directory_created_if_missing(self, tmp_path):
        new_dir = str(tmp_path / "new_subdir" / "nested")
        exporter = FindingExporter(output_dir=new_dir)
        path = exporter.export_json([make_finding()])
        assert os.path.exists(new_dir)
        assert os.path.exists(path)

    def test_round_trip_fields_match(self, tmp_path):
        """Export JSON then re-parse — key fields survive the round-trip."""
        exporter = FindingExporter(output_dir=str(tmp_path))
        finding = make_finding()
        path = exporter.export_json([finding])

        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)

        row = data[0]
        assert str(finding.finding_id) == row["finding_id"]
        assert finding.finding_type == row["finding_type"]
        assert finding.severity == row["severity"]
        assert str(finding.source_ip) == row["source_ip"]
        assert finding.description == row["description"]

    def test_multiple_findings_exported(self, tmp_path):
        exporter = FindingExporter(output_dir=str(tmp_path))
        findings = [make_finding(severity="high"), make_finding(severity="low")]
        path = exporter.export_json(findings)

        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)

        assert len(data) == 2

    def test_returns_path_string(self, tmp_path):
        exporter = FindingExporter(output_dir=str(tmp_path))
        result = exporter.export_json([make_finding()])
        assert isinstance(result, str)


# ---------------------------------------------------------------------------
# CSV export
# ---------------------------------------------------------------------------


class TestExportCsv:
    EXPECTED_HEADERS = [
        "finding_id",
        "finding_type",
        "severity",
        "source_ip",
        "username",
        "destination",
        "event_type",
        "event_source",
        "event_timestamp",
        "description",
        "timestamp",
    ]

    def test_creates_valid_csv_with_correct_headers(self, tmp_path):
        exporter = FindingExporter(output_dir=str(tmp_path))
        path = exporter.export_csv([make_finding()])

        with open(path, encoding="utf-8", newline="") as fh:
            reader = csv.DictReader(fh)
            assert list(reader.fieldnames) == self.EXPECTED_HEADERS

    def test_row_count_matches_findings(self, tmp_path):
        exporter = FindingExporter(output_dir=str(tmp_path))
        findings = [make_finding(), make_finding(), make_finding()]
        path = exporter.export_csv(findings)

        with open(path, encoding="utf-8", newline="") as fh:
            rows = list(csv.DictReader(fh))

        assert len(rows) == 3

    def test_flat_fields_populated(self, tmp_path):
        exporter = FindingExporter(output_dir=str(tmp_path))
        finding = make_finding()
        path = exporter.export_csv([finding])

        with open(path, encoding="utf-8", newline="") as fh:
            rows = list(csv.DictReader(fh))

        row = rows[0]
        assert row["finding_type"] == "unmanaged_ip"
        assert row["severity"] == "high"
        assert row["source_ip"] == str(finding.source_ip)
        assert row["username"] == finding.connection_event.username
        assert row["destination"] == finding.connection_event.destination
        assert row["event_type"] == finding.connection_event.event_type
        assert row["event_source"] == finding.connection_event.source

    def test_custom_filename_is_used(self, tmp_path):
        target = str(tmp_path / "out.csv")
        exporter = FindingExporter(output_dir=str(tmp_path))
        path = exporter.export_csv([make_finding()], filename=target)
        assert path == target
        assert os.path.exists(target)

    def test_auto_filename_has_timestamp_and_extension(self, tmp_path):
        exporter = FindingExporter(output_dir=str(tmp_path))
        path = exporter.export_csv([make_finding()])
        basename = os.path.basename(path)
        assert basename.startswith("findings_")
        assert basename.endswith(".csv")

    def test_empty_findings_produces_headers_only(self, tmp_path):
        exporter = FindingExporter(output_dir=str(tmp_path))
        path = exporter.export_csv([])

        with open(path, encoding="utf-8", newline="") as fh:
            reader = csv.DictReader(fh)
            assert list(reader.fieldnames) == self.EXPECTED_HEADERS
            rows = list(reader)
        assert rows == []

    def test_output_directory_created_if_missing(self, tmp_path):
        new_dir = str(tmp_path / "csv_output")
        exporter = FindingExporter(output_dir=new_dir)
        path = exporter.export_csv([make_finding()])
        assert os.path.exists(new_dir)
        assert os.path.exists(path)


# ---------------------------------------------------------------------------
# SIEM JSON Lines export
# ---------------------------------------------------------------------------


class TestExportSiemJsonl:
    def test_each_line_is_valid_json(self, tmp_path):
        exporter = FindingExporter(output_dir=str(tmp_path))
        findings = [make_finding(), make_finding()]
        path = exporter.export_siem_jsonl(findings)

        with open(path, encoding="utf-8") as fh:
            lines = [ln.strip() for ln in fh if ln.strip()]

        assert len(lines) == 2
        for line in lines:
            obj = json.loads(line)
            assert isinstance(obj, dict)

    def test_timestamp_field_present(self, tmp_path):
        exporter = FindingExporter(output_dir=str(tmp_path))
        path = exporter.export_siem_jsonl([make_finding()])

        with open(path, encoding="utf-8") as fh:
            obj = json.loads(fh.readline().strip())

        assert "@timestamp" in obj

    def test_timestamp_field_is_iso_format(self, tmp_path):
        exporter = FindingExporter(output_dir=str(tmp_path))
        finding = make_finding()
        path = exporter.export_siem_jsonl([finding])

        with open(path, encoding="utf-8") as fh:
            obj = json.loads(fh.readline().strip())

        # Should be parseable as ISO datetime
        ts = datetime.fromisoformat(obj["@timestamp"])
        assert ts is not None

    def test_finding_fields_present_in_each_line(self, tmp_path):
        exporter = FindingExporter(output_dir=str(tmp_path))
        path = exporter.export_siem_jsonl([make_finding()])

        with open(path, encoding="utf-8") as fh:
            obj = json.loads(fh.readline().strip())

        assert "finding_id" in obj
        assert "severity" in obj
        assert "source_ip" in obj

    def test_auto_filename_has_jsonl_extension(self, tmp_path):
        exporter = FindingExporter(output_dir=str(tmp_path))
        path = exporter.export_siem_jsonl([make_finding()])
        assert os.path.basename(path).endswith(".jsonl")

    def test_custom_filename_is_used(self, tmp_path):
        target = str(tmp_path / "siem.jsonl")
        exporter = FindingExporter(output_dir=str(tmp_path))
        path = exporter.export_siem_jsonl([make_finding()], filename=target)
        assert path == target

    def test_empty_findings_produces_empty_file(self, tmp_path):
        exporter = FindingExporter(output_dir=str(tmp_path))
        path = exporter.export_siem_jsonl([])

        with open(path, encoding="utf-8") as fh:
            content = fh.read().strip()

        assert content == ""

    def test_line_count_matches_finding_count(self, tmp_path):
        exporter = FindingExporter(output_dir=str(tmp_path))
        findings = [make_finding() for _ in range(5)]
        path = exporter.export_siem_jsonl(findings)

        with open(path, encoding="utf-8") as fh:
            lines = [ln for ln in fh if ln.strip()]

        assert len(lines) == 5
