"""
Tests for JamfCollector — W2-4.

@decision DEC-COLLECT-001
@title Strategy pattern — Jamf adapter tests
@status accepted
@rationale Tests cover mock mode, normalization from realistic Jamf API responses,
           and CollectorError on HTTP failures. All HTTP is intercepted via
           pytest-httpx — no real network calls.
"""

from __future__ import annotations

import pytest
from pytest_httpx import HTTPXMock

from debacl.collectors.exceptions import CollectorError
from debacl.collectors.jamf import JamfCollector, JamfConfig
from debacl.models.telemetry import EndpointTelemetry


def _make_config(**kwargs) -> JamfConfig:
    return JamfConfig(
        source="jamf",
        base_url="https://test.jamfcloud.com",
        client_id="test-client",
        client_secret="test-secret",
        **kwargs,
    )


_TOKEN_URL = "https://test.jamfcloud.com/api/oauth/token"
_INVENTORY_URL = (
    "https://test.jamfcloud.com/api/v1/computers-inventory"
    "?section=GENERAL%2CHARDWARE%2COPERATING_SYSTEM&page=0&page-size=100"
)
_TOKEN_RESP = {"access_token": "test-token", "expires_in": 1800}

_COMPUTER_1 = {
    "id": 1,
    "general": {
        "name": "CORP-LAPTOP-001",
        "lastIpAddress": "203.0.113.10",
        "lastContactTime": "2026-03-05T08:00:00Z",
    },
    "operatingSystem": {"version": "14.3"},
}
_COMPUTER_2 = {
    "id": 2,
    "general": {
        "name": "CORP-LAPTOP-002",
        "lastIpAddress": "198.51.100.20",
        "lastContactTime": "2026-03-05T08:01:00Z",
    },
    "operatingSystem": {"version": "13.6"},
}


class TestJamfMockMode:
    def test_mock_mode_returns_list(self):
        collector = JamfCollector(_make_config(mock_mode=True))
        assert isinstance(collector.collect(), list)

    def test_mock_mode_returns_endpoint_telemetry(self):
        collector = JamfCollector(_make_config(mock_mode=True))
        assert all(isinstance(r, EndpointTelemetry) for r in collector.collect())

    def test_mock_mode_source_is_jamf(self):
        collector = JamfCollector(_make_config(mock_mode=True))
        assert all(r.source == "jamf" for r in collector.collect())

    def test_mock_mode_non_empty(self):
        collector = JamfCollector(_make_config(mock_mode=True))
        assert len(collector.collect()) > 0


class TestJamfLiveMode:
    def test_normalization_correct(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(method="POST", url=_TOKEN_URL, json=_TOKEN_RESP)
        httpx_mock.add_response(
            method="GET",
            url=_INVENTORY_URL,
            json={"results": [_COMPUTER_1, _COMPUTER_2], "totalCount": 2},
        )

        collector = JamfCollector(_make_config(mock_mode=False))
        result = collector.collect()

        assert len(result) == 2
        assert result[0].device_id == "1"
        assert str(result[0].public_ip) == "203.0.113.10"
        assert result[0].source == "jamf"
        assert result[0].hostname == "CORP-LAPTOP-001"

    def test_skips_computers_without_ip(self, httpx_mock: HTTPXMock):
        no_ip = {"id": 99, "general": {"name": "X", "lastContactTime": "2026-03-05T08:00:00Z"}}
        httpx_mock.add_response(method="POST", url=_TOKEN_URL, json=_TOKEN_RESP)
        httpx_mock.add_response(
            method="GET",
            url=_INVENTORY_URL,
            json={"results": [no_ip], "totalCount": 1},
        )

        collector = JamfCollector(_make_config(mock_mode=False))
        assert collector.collect() == []

    def test_token_failure_raises_collector_error(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(method="POST", url=_TOKEN_URL, status_code=401, text="Unauthorized")

        collector = JamfCollector(_make_config(mock_mode=False))
        with pytest.raises(CollectorError, match="OAuth token"):
            collector.collect()

    def test_inventory_failure_raises_collector_error(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(method="POST", url=_TOKEN_URL, json=_TOKEN_RESP)
        httpx_mock.add_response(
            method="GET",
            url=_INVENTORY_URL,
            status_code=500,
            text="Internal Server Error",
        )

        collector = JamfCollector(_make_config(mock_mode=False))
        with pytest.raises(CollectorError, match="inventory"):
            collector.collect()
