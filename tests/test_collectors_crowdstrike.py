"""
Tests for CrowdStrikeCollector — W2-2.

@decision DEC-COLLECT-001
@title Strategy pattern — CrowdStrike adapter tests
@status accepted
@rationale Tests cover mock mode, normalization from realistic API responses,
           and CollectorError on HTTP failures. All HTTP is intercepted via
           pytest-httpx — no real network calls.
"""

from __future__ import annotations

import pytest
from pytest_httpx import HTTPXMock

from debacl.collectors.crowdstrike import CrowdStrikeCollector, CrowdStrikeConfig
from debacl.collectors.exceptions import CollectorError
from debacl.models.telemetry import EndpointTelemetry

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_config(**kwargs) -> CrowdStrikeConfig:
    return CrowdStrikeConfig(
        source="crowdstrike",
        client_id="test-id",
        client_secret="test-secret",
        base_url="https://api.crowdstrike.com",
        **kwargs,
    )


_TOKEN_RESP = {
    "access_token": "test-token",
    "token_type": "bearer",
    "expires_in": 1800,
}

_DEVICE_IDS_RESP = {
    "resources": ["device-001", "device-002"],
    "meta": {"pagination": {"total": 2}},
}

_DEVICE_DETAILS_RESP = {
    "resources": [
        {
            "device_id": "device-001",
            "hostname": "CORP-LAPTOP-001",
            "external_ip": "203.0.113.10",
            "last_seen": "2026-03-05T08:00:00Z",
            "status": "normal",
        },
        {
            "device_id": "device-002",
            "hostname": "CORP-LAPTOP-002",
            "external_ip": "198.51.100.20",
            "last_seen": "2026-03-05T08:01:00Z",
            "status": "contained",
        },
    ]
}


# ---------------------------------------------------------------------------
# Mock-mode tests
# ---------------------------------------------------------------------------

class TestCrowdStrikeMockMode:
    def test_mock_mode_returns_list(self):
        collector = CrowdStrikeCollector(_make_config(mock_mode=True))
        result = collector.collect()
        assert isinstance(result, list)

    def test_mock_mode_returns_endpoint_telemetry(self):
        collector = CrowdStrikeCollector(_make_config(mock_mode=True))
        result = collector.collect()
        assert all(isinstance(r, EndpointTelemetry) for r in result)

    def test_mock_mode_source_is_crowdstrike(self):
        collector = CrowdStrikeCollector(_make_config(mock_mode=True))
        result = collector.collect()
        assert all(r.source == "crowdstrike" for r in result)

    def test_mock_mode_non_empty(self):
        collector = CrowdStrikeCollector(_make_config(mock_mode=True))
        result = collector.collect()
        assert len(result) > 0


# ---------------------------------------------------------------------------
# Live-mode normalization tests (HTTP mocked)
# ---------------------------------------------------------------------------

class TestCrowdStrikeLiveMode:
    def test_normalization_correct(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            method="POST",
            url="https://api.crowdstrike.com/oauth2/token",
            json=_TOKEN_RESP,
            status_code=201,
        )
        httpx_mock.add_response(
            method="GET",
            url="https://api.crowdstrike.com/devices/queries/devices/v1?limit=500&offset=0",
            json=_DEVICE_IDS_RESP,
        )
        httpx_mock.add_response(
            method="POST",
            url="https://api.crowdstrike.com/devices/entities/devices/v2",
            json=_DEVICE_DETAILS_RESP,
        )

        collector = CrowdStrikeCollector(_make_config(mock_mode=False))
        result = collector.collect()

        assert len(result) == 2
        assert all(isinstance(r, EndpointTelemetry) for r in result)
        assert result[0].device_id == "device-001"
        assert str(result[0].public_ip) == "203.0.113.10"
        assert result[0].source == "crowdstrike"
        assert result[0].hostname == "CORP-LAPTOP-001"

    def test_normalization_skips_missing_external_ip(self, httpx_mock: HTTPXMock):
        details_no_ip = {
            "resources": [
                {
                    "device_id": "device-003",
                    "hostname": "CORP-LAPTOP-003",
                    # external_ip intentionally absent
                    "last_seen": "2026-03-05T08:00:00Z",
                }
            ]
        }
        httpx_mock.add_response(
            method="POST",
            url="https://api.crowdstrike.com/oauth2/token",
            json=_TOKEN_RESP,
            status_code=201,
        )
        httpx_mock.add_response(
            method="GET",
            url="https://api.crowdstrike.com/devices/queries/devices/v1?limit=500&offset=0",
            json={"resources": ["device-003"], "meta": {"pagination": {"total": 1}}},
        )
        httpx_mock.add_response(
            method="POST",
            url="https://api.crowdstrike.com/devices/entities/devices/v2",
            json=details_no_ip,
        )

        collector = CrowdStrikeCollector(_make_config(mock_mode=False))
        result = collector.collect()
        assert result == []

    def test_token_failure_raises_collector_error(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            method="POST",
            url="https://api.crowdstrike.com/oauth2/token",
            status_code=401,
            text="Unauthorized",
        )
        collector = CrowdStrikeCollector(_make_config(mock_mode=False))
        with pytest.raises(CollectorError, match="OAuth2 token"):
            collector.collect()

    def test_device_query_failure_raises_collector_error(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            method="POST",
            url="https://api.crowdstrike.com/oauth2/token",
            json=_TOKEN_RESP,
            status_code=201,
        )
        httpx_mock.add_response(
            method="GET",
            url="https://api.crowdstrike.com/devices/queries/devices/v1?limit=500&offset=0",
            status_code=403,
            text="Forbidden",
        )
        collector = CrowdStrikeCollector(_make_config(mock_mode=False))
        with pytest.raises(CollectorError, match="device query"):
            collector.collect()

    def test_empty_device_list_returns_empty(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            method="POST",
            url="https://api.crowdstrike.com/oauth2/token",
            json=_TOKEN_RESP,
            status_code=201,
        )
        httpx_mock.add_response(
            method="GET",
            url="https://api.crowdstrike.com/devices/queries/devices/v1?limit=500&offset=0",
            json={"resources": [], "meta": {"pagination": {"total": 0}}},
        )
        collector = CrowdStrikeCollector(_make_config(mock_mode=False))
        result = collector.collect()
        assert result == []
