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
import os
import tempfile

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


class TestVpnLogCsvParsing:
    def test_csv_fixture_parses_all_rows(self):
        collector = VpnLogCollector(
            _make_config(log_path=_CSV_FIXTURE, log_format="csv")
        )
        result = collector.collect()
        assert len(result) == 20

    def test_csv_fixture_returns_connection_events(self):
        collector = VpnLogCollector(
            _make_config(log_path=_CSV_FIXTURE, log_format="csv")
        )
        assert all(isinstance(e, ConnectionEvent) for e in collector.collect())

    def test_csv_fixture_source_is_vpn_log(self):
        collector = VpnLogCollector(
            _make_config(log_path=_CSV_FIXTURE, log_format="csv")
        )
        assert all(e.source == "vpn_log" for e in collector.collect())

    def test_csv_connected_maps_to_vpn_connect(self):
        collector = VpnLogCollector(
            _make_config(log_path=_CSV_FIXTURE, log_format="csv")
        )
        events = collector.collect()
        connected = [e for e in events if e.event_type == "vpn_connect"]
        assert len(connected) > 0

    def test_csv_failed_maps_to_auth_failure(self):
        collector = VpnLogCollector(
            _make_config(log_path=_CSV_FIXTURE, log_format="csv")
        )
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
            writer.writerow({
                "timestamp": "2026-03-05T08:00:00+00:00",
                "username": "alice@corp.com",
                "source_ip": "203.0.113.1",
                "destination": "vpn",
                "status": "connected",
            })
            # Invalid row: missing source_ip
            writer.writerow({
                "timestamp": "2026-03-05T08:01:00+00:00",
                "username": "bob@corp.com",
                "source_ip": "",
                "destination": "vpn",
                "status": "connected",
            })
            tmp_path = f.name

        try:
            collector = VpnLogCollector(_make_config(log_path=tmp_path, log_format="csv"))
            result = collector.collect()
            assert len(result) == 1
        finally:
            os.unlink(tmp_path)

    def test_csv_missing_file_raises_collector_error(self):
        collector = VpnLogCollector(
            _make_config(log_path="/nonexistent/path.csv", log_format="csv")
        )
        with pytest.raises(CollectorError, match="read error"):
            collector.collect()


class TestVpnLogSyslogParsing:
    def test_syslog_fixture_parses_some_rows(self):
        collector = VpnLogCollector(
            _make_config(log_path=_SYSLOG_FIXTURE, log_format="syslog")
        )
        result = collector.collect()
        # Fixture has 10 lines, all parseable
        assert len(result) > 0

    def test_syslog_fixture_returns_connection_events(self):
        collector = VpnLogCollector(
            _make_config(log_path=_SYSLOG_FIXTURE, log_format="syslog")
        )
        assert all(isinstance(e, ConnectionEvent) for e in collector.collect())

    def test_syslog_fixture_source_is_vpn_log(self):
        collector = VpnLogCollector(
            _make_config(log_path=_SYSLOG_FIXTURE, log_format="syslog")
        )
        assert all(e.source == "vpn_log" for e in collector.collect())

    def test_syslog_failed_line_maps_to_auth_failure(self):
        collector = VpnLogCollector(
            _make_config(log_path=_SYSLOG_FIXTURE, log_format="syslog")
        )
        events = collector.collect()
        failures = [e for e in events if e.event_type == "auth_failure"]
        assert len(failures) > 0

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
