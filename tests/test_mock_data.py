"""
Tests for MockDataGenerator — W2-1.

@decision DEC-TEST-001
@title Synthetic telemetry — tests verify determinism, IP-range correctness, anomaly ratio
@status accepted
@rationale These tests confirm MockDataGenerator's contract: correct counts, no
           RFC1918 IPs (so the correlation engine treats them as public), anomaly
           ratio within ±10%, deterministic output per seed, and valid CSV structure.
           All assertions use real objects — no mocks of internal functions.
"""

import csv
import ipaddress
import os
import tempfile

import pytest

from debacl.collectors.mock_data import MockDataGenerator
from debacl.models.events import ConnectionEvent
from debacl.models.telemetry import EndpointTelemetry

# RFC1918 networks used to verify IPs are public
_RFC1918 = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


def is_rfc1918(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(ip, ipaddress.IPv6Address):
        return False  # our IPv6 addrs are doc-range, not RFC1918
    return any(ip in net for net in _RFC1918)


class TestMockDataGeneratorEndpoints:
    def setup_method(self):
        self.gen = MockDataGenerator(seed=42, device_count=20, event_count=50, anomaly_ratio=0.2)

    def test_correct_device_count_crowdstrike(self):
        devices = self.gen.generate_endpoint_telemetry("crowdstrike")
        assert len(devices) == 20

    def test_correct_device_count_intune(self):
        devices = self.gen.generate_endpoint_telemetry("intune")
        assert len(devices) == 20

    def test_correct_device_count_jamf(self):
        devices = self.gen.generate_endpoint_telemetry("jamf")
        assert len(devices) == 20

    def test_all_items_are_endpoint_telemetry(self):
        devices = self.gen.generate_endpoint_telemetry("crowdstrike")
        assert all(isinstance(d, EndpointTelemetry) for d in devices)

    def test_source_field_matches_requested_source(self):
        for source in ("crowdstrike", "intune", "jamf"):
            devices = self.gen.generate_endpoint_telemetry(source)
            assert all(d.source == source for d in devices)

    def test_no_rfc1918_ips(self):
        devices = self.gen.generate_endpoint_telemetry("crowdstrike")
        for d in devices:
            assert not is_rfc1918(d.public_ip), f"RFC1918 IP found: {d.public_ip}"

    def test_hostname_pattern(self):
        devices = self.gen.generate_endpoint_telemetry("crowdstrike")
        for d in devices:
            assert d.hostname.startswith("CORP-LAPTOP-")

    def test_health_status_values(self):
        devices = self.gen.generate_endpoint_telemetry("crowdstrike")
        valid = {"healthy", "outdated", None}
        assert all(d.health_status in valid for d in devices)

    def test_deterministic_with_same_seed(self):
        g1 = MockDataGenerator(seed=99)
        g2 = MockDataGenerator(seed=99)
        d1 = g1.generate_endpoint_telemetry("crowdstrike")
        d2 = g2.generate_endpoint_telemetry("crowdstrike")
        assert [str(d.public_ip) for d in d1] == [str(d.public_ip) for d in d2]

    def test_different_seeds_different_results(self):
        g1 = MockDataGenerator(seed=1)
        g2 = MockDataGenerator(seed=2)
        d1 = g1.generate_endpoint_telemetry("crowdstrike")
        d2 = g2.generate_endpoint_telemetry("crowdstrike")
        assert [str(d.public_ip) for d in d1] != [str(d.public_ip) for d in d2]


class TestMockDataGeneratorEvents:
    def setup_method(self):
        self.gen = MockDataGenerator(seed=42, device_count=20, event_count=50, anomaly_ratio=0.2)

    def test_correct_event_count_okta(self):
        events = self.gen.generate_connection_events("okta")
        assert len(events) == 50

    def test_correct_event_count_entra(self):
        events = self.gen.generate_connection_events("entra")
        assert len(events) == 50

    def test_correct_event_count_vpn_log(self):
        events = self.gen.generate_connection_events("vpn_log")
        assert len(events) == 50

    def test_all_items_are_connection_events(self):
        events = self.gen.generate_connection_events("okta")
        assert all(isinstance(e, ConnectionEvent) for e in events)

    def test_source_field_matches_requested_source(self):
        for source in ("okta", "entra", "vpn_log"):
            events = self.gen.generate_connection_events(source)
            assert all(e.source == source for e in events)

    def test_no_rfc1918_ips(self):
        events = self.gen.generate_connection_events("okta")
        for e in events:
            assert not is_rfc1918(e.source_ip), f"RFC1918 IP found: {e.source_ip}"

    def test_anomaly_ratio_approximate(self):
        """Anomaly count should be within 10% of requested ratio."""
        known_ips = [ipaddress.IPv4Address("203.0.113.1")]
        gen = MockDataGenerator(seed=42, event_count=100, anomaly_ratio=0.3)
        events = gen.generate_connection_events("okta", known_ips=known_ips)
        known_set = {str(ip) for ip in known_ips}
        anomalous = sum(1 for e in events if str(e.source_ip) not in known_set)
        # Expected ~30, allow ±10
        assert 20 <= anomalous <= 40, f"Anomaly count {anomalous} outside tolerance"

    def test_username_format(self):
        events = self.gen.generate_connection_events("okta")
        for e in events:
            assert "@corp.com" in e.username

    def test_okta_entra_event_types_no_vpn_connect(self):
        """Okta and Entra events should not include vpn_connect."""
        for source in ("okta", "entra"):
            events = self.gen.generate_connection_events(source)
            assert all(e.event_type != "vpn_connect" for e in events), (
                f"{source} produced vpn_connect event"
            )


class TestMockDataGeneratorVpnLogFile:
    def test_generates_valid_csv(self):
        gen = MockDataGenerator(seed=42, event_count=50)
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            path = f.name
        try:
            result_path = gen.generate_vpn_log_file(path)
            assert result_path == path
            with open(path, newline="", encoding="utf-8") as fh:
                reader = csv.DictReader(fh)
                rows = list(reader)
            assert len(rows) == 50
        finally:
            os.unlink(path)

    def test_csv_has_expected_columns(self):
        gen = MockDataGenerator(seed=42, event_count=10)
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            path = f.name
        try:
            gen.generate_vpn_log_file(path)
            with open(path, newline="", encoding="utf-8") as fh:
                reader = csv.DictReader(fh)
                fieldnames = reader.fieldnames or []
            expected = {"timestamp", "username", "source_ip", "destination", "status"}
            assert expected.issubset(set(fieldnames))
        finally:
            os.unlink(path)

    def test_csv_status_values_valid(self):
        gen = MockDataGenerator(seed=42, event_count=20)
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            path = f.name
        try:
            gen.generate_vpn_log_file(path)
            with open(path, newline="", encoding="utf-8") as fh:
                reader = csv.DictReader(fh)
                statuses = {row["status"] for row in reader}
            assert statuses.issubset({"connected", "failed"})
        finally:
            os.unlink(path)

    @pytest.mark.parametrize("count", [10, 30])
    def test_csv_row_count_matches_event_count(self, count):
        gen = MockDataGenerator(seed=7, event_count=count)
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            path = f.name
        try:
            gen.generate_vpn_log_file(path)
            with open(path, newline="", encoding="utf-8") as fh:
                rows = list(csv.DictReader(fh))
            assert len(rows) == count
        finally:
            os.unlink(path)
