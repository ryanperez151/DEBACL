"""
Tests for VpnLogCollector — W2-7.

@decision DEC-COLLECT-001
@title Strategy pattern — VPN log file-based adapter tests
@status accepted
@rationale Tests cover CSV fixture parsing, syslog fixture parsing, mock mode
           (generate + parse), status→event_type mapping, and graceful skipping
           of invalid rows. No HTTP mocking needed — this collector is file-based.
"""

from __future__ import annotations

import csv
import logging
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path

import pytest

from debacl.collectors.exceptions import CollectorError
from debacl.collectors.vpn_log import VpnLogCollector, VpnLogConfig
from debacl.models.events import ConnectionEvent

# Absolute path to fixtures directory
_FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
_CSV_FIXTURE = os.path.join(_FIXTURES, "vpn_sample.csv")
_SYSLOG_FIXTURE = os.path.join(_FIXTURES, "vpn_sample_syslog.txt")


def _make_config(**kwargs) -> VpnLogConfig:
    return VpnLogConfig(source="vpn_log", **kwargs)


class TestVpnLogMockMode:
    def test_mock_mode_returns_list(self):
        collector = VpnLogCollector(_make_config(mock_mode=True))
        assert isinstance(collector.collect(), list)

    def test_mock_mode_returns_connection_events(self):
        collector = VpnLogCollector(_make_config(mock_mode=True))
        assert all(isinstance(e, ConnectionEvent) for e in collector.collect())

    def test_mock_mode_source_is_vpn_log(self):
        collector = VpnLogCollector(_make_config(mock_mode=True))
        assert all(e.source == "vpn_log" for e in collector.collect())

    def test_mock_mode_non_empty(self):
        collector = VpnLogCollector(_make_config(mock_mode=True))
        assert len(collector.collect()) > 0

    def test_mock_mode_generates_and_parses(self):
        """Mock mode must complete the full generate → parse pipeline."""
        collector = VpnLogCollector(_make_config(mock_mode=True))
        result = collector.collect()
        # MockDataGenerator defaults: event_count=50
        assert len(result) == 50

    def test_mock_mode_cleans_temp_file_and_resets_skip_count(self, monkeypatch):
        generated_paths = []

        def generate_empty_csv(_generator, path):
            generated_paths.append(Path(path))
            Path(path).write_text(
                "timestamp,username,source_ip,destination,status\n", encoding="utf-8"
            )

        monkeypatch.setattr(
            "debacl.collectors.vpn_log.MockDataGenerator.generate_vpn_log_file",
            generate_empty_csv,
        )
        collector = VpnLogCollector(_make_config(mock_mode=True))
        collector.skipped_count = 3

        assert collector.collect() == []
        assert collector.skipped_count == 0
        assert len(generated_paths) == 1
        assert not generated_paths[0].exists()


class TestVpnLogCsvParsing:
    @pytest.mark.parametrize(
        "contents",
        ["", "timestamp,username,source_ip,secret-header\n"],
    )
    def test_csv_missing_required_header_raises_sanitized_error(self, tmp_path, contents):
        path = tmp_path / "bad-header.csv"
        path.write_text(contents, encoding="utf-8")
        collector = VpnLogCollector(_make_config(log_path=str(path), log_format="csv"))

        with pytest.raises(CollectorError, match="^VPN log CSV is missing required columns$"):
            collector.collect()
        assert collector.skipped_count == 0

    def test_csv_fixture_parses_all_rows(self):
        collector = VpnLogCollector(_make_config(log_path=_CSV_FIXTURE, log_format="csv"))
        result = collector.collect()
        assert len(result) == 20

    def test_csv_fixture_returns_connection_events(self):
        collector = VpnLogCollector(_make_config(log_path=_CSV_FIXTURE, log_format="csv"))
        assert all(isinstance(e, ConnectionEvent) for e in collector.collect())

    def test_csv_fixture_source_is_vpn_log(self):
        collector = VpnLogCollector(_make_config(log_path=_CSV_FIXTURE, log_format="csv"))
        assert all(e.source == "vpn_log" for e in collector.collect())

    def test_csv_connected_maps_to_vpn_connect(self):
        collector = VpnLogCollector(_make_config(log_path=_CSV_FIXTURE, log_format="csv"))
        events = collector.collect()
        connected = [e for e in events if e.event_type == "vpn_connect"]
        assert len(connected) > 0

    def test_csv_failed_maps_to_auth_failure(self):
        collector = VpnLogCollector(_make_config(log_path=_CSV_FIXTURE, log_format="csv"))
        events = collector.collect()
        failures = [e for e in events if e.event_type == "auth_failure"]
        assert len(failures) > 0

    def test_csv_invalid_rows_skipped_gracefully(self):
        """A CSV with some invalid rows should not raise — only valid rows returned."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".csv", delete=False, encoding="utf-8", newline=""
        ) as f:
            writer = csv.DictWriter(
                f,
                fieldnames=["timestamp", "username", "source_ip", "destination", "status"],
            )
            writer.writeheader()
            # Valid row
            writer.writerow(
                {
                    "timestamp": "2026-03-05T08:00:00+00:00",
                    "username": "alice@corp.com",
                    "source_ip": "203.0.113.1",
                    "destination": "vpn",
                    "status": "connected",
                }
            )
            # Invalid row: missing source_ip
            writer.writerow(
                {
                    "timestamp": "2026-03-05T08:01:00+00:00",
                    "username": "bob@corp.com",
                    "source_ip": "",
                    "destination": "vpn",
                    "status": "connected",
                }
            )
            tmp_path = f.name

        try:
            collector = VpnLogCollector(_make_config(log_path=tmp_path, log_format="csv"))
            result = collector.collect()
            assert len(result) == 1
        finally:
            os.unlink(tmp_path)

    def test_csv_valid_ips_and_timestamps_with_aggregate_skip_warning(self, tmp_path, caplog):
        path = tmp_path / "vpn.csv"
        with path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(
                fh,
                fieldnames=["timestamp", "username", "source_ip", "destination", "status"],
            )
            writer.writeheader()
            for timestamp, username, source_ip in (
                ("2026-03-05T08:00:00+00:00", "alice", "203.0.113.1"),
                ("2026-03-05T09:00:00+00:00", "bob", "2001:db8::1"),
                ("2026-03-05T10:00:00+00:00", "missing-ip-secret", ""),
                ("2026-03-05T11:00:00+00:00", "invalid-ip-secret", "not-an-ip"),
                ("2026-03-05T12:00:00+00:00", "mac-secret", "aa:bb:cc:dd:ee:ff"),
                ("invalid-time-secret", "bad-time-secret", "192.0.2.5"),
                ("Mar 05 08:00:00", "yearless-secret", "192.0.2.6"),
            ):
                writer.writerow(
                    {
                        "timestamp": timestamp,
                        "username": username,
                        "source_ip": source_ip,
                        "destination": "vpn",
                        "status": "connected",
                    }
                )

        collector = VpnLogCollector(_make_config(log_path=str(path), log_format="csv"))
        with caplog.at_level(logging.WARNING, logger="debacl.collectors.vpn_log"):
            events = collector.collect()

        assert [str(event.source_ip) for event in events] == ["203.0.113.1", "2001:db8::1"]
        assert [event.timestamp for event in events] == [
            datetime(2026, 3, 5, 8, tzinfo=UTC),
            datetime(2026, 3, 5, 9, tzinfo=UTC),
        ]
        assert [event.raw_data["line_number"] for event in events] == [2, 3]
        assert all(event.raw_data["file_path"] == str(path.resolve()) for event in events)
        assert all(event.raw_data["timestamp_basis"] == "source_record" for event in events)
        assert all(len(event.raw_data["record_sha256"]) == 64 for event in events)
        assert collector.skipped_count == 5
        warnings = [
            record.message
            for record in caplog.records
            if record.name == "debacl.collectors.vpn_log"
        ]
        assert warnings == ["VPN log skipped 5 malformed row(s) or line(s)"]
        assert all("secret" not in message for message in warnings)

        empty_path = tmp_path / "empty.csv"
        empty_path.write_text("timestamp,username,source_ip,destination,status\n", encoding="utf-8")
        collector.config.log_path = str(empty_path)
        caplog.clear()
        assert collector.collect() == []
        assert collector.skipped_count == 0
        assert caplog.records == []

    def test_csv_missing_file_raises_collector_error(self):
        collector = VpnLogCollector(
            _make_config(log_path="/nonexistent/path.csv", log_format="csv")
        )
        with pytest.raises(CollectorError, match="read error"):
            collector.collect()


class TestVpnLogSyslogParsing:
    def test_syslog_fixture_parses_some_rows(self):
        collector = VpnLogCollector(_make_config(log_path=_SYSLOG_FIXTURE, log_format="syslog"))
        result = collector.collect()
        # Fixture has 10 lines, all parseable
        assert len(result) > 0

    def test_syslog_fixture_returns_connection_events(self):
        collector = VpnLogCollector(_make_config(log_path=_SYSLOG_FIXTURE, log_format="syslog"))
        assert all(isinstance(e, ConnectionEvent) for e in collector.collect())

    def test_syslog_fixture_source_is_vpn_log(self):
        collector = VpnLogCollector(_make_config(log_path=_SYSLOG_FIXTURE, log_format="syslog"))
        assert all(e.source == "vpn_log" for e in collector.collect())

    def test_syslog_failed_line_maps_to_auth_failure(self):
        collector = VpnLogCollector(_make_config(log_path=_SYSLOG_FIXTURE, log_format="syslog"))
        events = collector.collect()
        failures = [e for e in events if e.event_type == "auth_failure"]
        assert len(failures) > 0

    def test_syslog_repeated_read_has_stable_line_provenance(self, tmp_path):
        path = tmp_path / "repeated.log"
        path.write_text(
            "Mar  5 08:01:12 vpn: src=203.0.113.10 user=alice connected\n"
            "Mar  5 08:01:12 vpn: src=203.0.113.10 user=alice connected\n",
            encoding="utf-8",
        )
        collector = VpnLogCollector(_make_config(log_path=str(path), log_format="syslog"))

        first_read = collector.collect()
        second_read = collector.collect()

        assert len(first_read) == len(second_read) == 2
        assert [event.raw_data for event in first_read] == [event.raw_data for event in second_read]
        assert [event.raw_data["line_number"] for event in first_read] == [1, 2]
        assert all(event.raw_data["file_path"] == str(path.resolve()) for event in first_read)
        assert first_read[0].raw_data["record_sha256"] == first_read[1].raw_data["record_sha256"]
        assert all(event.raw_data["timestamp_basis"] == "collection_time" for event in first_read)
        assert all(event.timestamp.tzinfo is not None for event in first_read)

        direct_event = VpnLogCollector._syslog_line_to_event(
            "Mar  5 08:01:12 vpn: src=203.0.113.10 user=alice connected"
        )
        assert direct_event is not None
        assert direct_event.raw_data == {"timestamp_basis": "collection_time"}

    def test_syslog_invalid_ips_and_lines_are_counted_once(self, tmp_path, caplog):
        path = tmp_path / "vpn.log"
        path.write_text(
            "src=2001:db8::1 user=alice connected\n"
            "src=aa:bb:cc:dd:ee:ff user=mac-secret connected\n"
            "src=not-an-ip user=invalid-secret connected\n"
            "src=203.0.113.1garbage user=prefix-secret connected\n"
            "GlobalProtect: user: suffix-secret client-ip: 203.0.113.2garbage login success\n"
            "AnyConnect: User <angle-secret> IP <203.0.113.3garbage> connected\n"
            "unrecognized payload secret\n",
            encoding="utf-8",
        )
        collector = VpnLogCollector(_make_config(log_path=str(path), log_format="syslog"))
        with caplog.at_level(logging.WARNING, logger="debacl.collectors.vpn_log"):
            events = collector.collect()

        assert len(events) == 1
        assert str(events[0].source_ip) == "2001:db8::1"
        assert collector.skipped_count == 6
        warnings = [
            record.message
            for record in caplog.records
            if record.name == "debacl.collectors.vpn_log"
        ]
        assert warnings == ["VPN log skipped 6 malformed row(s) or line(s)"]
        assert all("secret" not in message for message in warnings)

    def test_syslog_missing_file_raises_collector_error(self):
        collector = VpnLogCollector(
            _make_config(log_path="/nonexistent/path.log", log_format="syslog")
        )
        with pytest.raises(CollectorError, match="read error"):
            collector.collect()


class TestVpnLogLiveModeErrors:
    def test_no_log_path_in_live_mode_raises(self):
        collector = VpnLogCollector(_make_config(log_path="", log_format="csv"))
        with pytest.raises(CollectorError, match="log_path"):
            collector.collect()
