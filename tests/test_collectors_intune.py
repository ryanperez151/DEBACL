"""
Tests for IntuneCollector — W2-3.

@decision DEC-COLLECT-001
@title Strategy pattern — Intune adapter tests
@status accepted
@rationale Tests cover mock mode, normalization from realistic Graph API responses,
           @odata.nextLink pagination, and CollectorError on HTTP failures.
           All HTTP is intercepted via pytest-httpx.
"""

from __future__ import annotations

import pytest
from pytest_httpx import HTTPXMock

from debacl.collectors.exceptions import CollectorError
from debacl.collectors.intune import IntuneCollector, IntuneConfig
from debacl.models.telemetry import EndpointTelemetry

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_config(**kwargs) -> IntuneConfig:
    return IntuneConfig(
        source="intune",
        tenant_id="test-tenant",
        client_id="test-client",
        client_secret="test-secret",
        **kwargs,
    )


_TOKEN_URL = "https://login.microsoftonline.com/test-tenant/oauth2/v2.0/token"
_DEVICES_URL = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices"

_TOKEN_RESP = {"access_token": "test-token", "token_type": "Bearer", "expires_in": 3600}

_DEVICE_1 = {
    "id": "intune-dev-001",
    "deviceName": "CORP-LAPTOP-001",
    "publicIpAddress": "203.0.113.10",
    "lastSyncDateTime": "2026-03-05T08:00:00Z",
    "complianceState": "compliant",
}
_DEVICE_2 = {
    "id": "intune-dev-002",
    "deviceName": "CORP-LAPTOP-002",
    "publicIpAddress": "198.51.100.20",
    "lastSyncDateTime": "2026-03-05T08:01:00Z",
    "complianceState": "noncompliant",
}


# ---------------------------------------------------------------------------
# Mock-mode tests
# ---------------------------------------------------------------------------

class TestIntuneMockMode:
    def test_mock_mode_returns_list(self):
        collector = IntuneCollector(_make_config(mock_mode=True))
        result = collector.collect()
        assert isinstance(result, list)

    def test_mock_mode_returns_endpoint_telemetry(self):
        collector = IntuneCollector(_make_config(mock_mode=True))
        result = collector.collect()
        assert all(isinstance(r, EndpointTelemetry) for r in result)

    def test_mock_mode_source_is_intune(self):
        collector = IntuneCollector(_make_config(mock_mode=True))
        result = collector.collect()
        assert all(r.source == "intune" for r in result)

    def test_mock_mode_non_empty(self):
        collector = IntuneCollector(_make_config(mock_mode=True))
        result = collector.collect()
        assert len(result) > 0


# ---------------------------------------------------------------------------
# Live-mode normalization tests
# ---------------------------------------------------------------------------

class TestIntuneLiveMode:
    def test_normalization_correct(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(method="POST", url=_TOKEN_URL, json=_TOKEN_RESP)
        httpx_mock.add_response(
            method="GET",
            url=_DEVICES_URL,
            json={"value": [_DEVICE_1, _DEVICE_2]},
        )

        collector = IntuneCollector(_make_config(mock_mode=False))
        result = collector.collect()

        assert len(result) == 2
        assert all(isinstance(r, EndpointTelemetry) for r in result)
        assert result[0].device_id == "intune-dev-001"
        assert str(result[0].public_ip) == "203.0.113.10"
        assert result[0].source == "intune"
        assert result[0].hostname == "CORP-LAPTOP-001"

    def test_pagination_follows_next_link(self, httpx_mock: HTTPXMock):
        page2_url = _DEVICES_URL + "?$skiptoken=abc"
        httpx_mock.add_response(method="POST", url=_TOKEN_URL, json=_TOKEN_RESP)
        httpx_mock.add_response(
            method="GET",
            url=_DEVICES_URL,
            json={"value": [_DEVICE_1], "@odata.nextLink": page2_url},
        )
        httpx_mock.add_response(
            method="GET",
            url=page2_url,
            json={"value": [_DEVICE_2]},
        )

        collector = IntuneCollector(_make_config(mock_mode=False))
        result = collector.collect()
        assert len(result) == 2

    def test_skips_devices_without_ip(self, httpx_mock: HTTPXMock):
        device_no_ip = {
            "id": "dev-x", "deviceName": "X", "lastSyncDateTime": "2026-03-05T08:00:00Z"
        }
        httpx_mock.add_response(method="POST", url=_TOKEN_URL, json=_TOKEN_RESP)
        httpx_mock.add_response(method="GET", url=_DEVICES_URL, json={"value": [device_no_ip]})

        collector = IntuneCollector(_make_config(mock_mode=False))
        result = collector.collect()
        assert result == []

    def test_token_failure_raises_collector_error(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(method="POST", url=_TOKEN_URL, status_code=401, text="Unauthorized")

        collector = IntuneCollector(_make_config(mock_mode=False))
        with pytest.raises(CollectorError, match="MSAL token"):
            collector.collect()

    def test_graph_failure_raises_collector_error(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(method="POST", url=_TOKEN_URL, json=_TOKEN_RESP)
        httpx_mock.add_response(method="GET", url=_DEVICES_URL, status_code=403, text="Forbidden")

        collector = IntuneCollector(_make_config(mock_mode=False))
        with pytest.raises(CollectorError, match="Graph API"):
            collector.collect()
