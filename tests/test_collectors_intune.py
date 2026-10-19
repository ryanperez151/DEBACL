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

import traceback

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
        assert result[0].timestamp.isoformat() == "2026-03-05T08:00:00+00:00"
        assert result[0].raw_data == _DEVICE_1

    @pytest.mark.parametrize("public_ip", ["203.0.113.10", "2001:db8::10"])
    def test_accepts_ipv4_and_ipv6(self, httpx_mock: HTTPXMock, public_ip: str):
        device = {**_DEVICE_1, "publicIpAddress": public_ip}
        httpx_mock.add_response(method="POST", url=_TOKEN_URL, json=_TOKEN_RESP)
        httpx_mock.add_response(method="GET", url=_DEVICES_URL, json={"value": [device]})

        collector = IntuneCollector(_make_config(mock_mode=False))
        result = collector.collect()

        assert len(result) == 1
        assert str(result[0].public_ip) == public_ip
        assert collector.skipped_count == 0

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

    def test_skips_devices_without_ip(self, httpx_mock: HTTPXMock, caplog):
        device_no_ip = {
            "id": "dev-x",
            "deviceName": "X",
            "wiFiMacAddress": "00:11:22:33:44:55",
            "lastSyncDateTime": "2026-03-05T08:00:00Z",
        }
        httpx_mock.add_response(method="POST", url=_TOKEN_URL, json=_TOKEN_RESP)
        httpx_mock.add_response(
            method="GET",
            url=_DEVICES_URL,
            json={"value": [device_no_ip, {**device_no_ip, "publicIpAddress": "   "}, _DEVICE_1]},
        )

        collector = IntuneCollector(_make_config(mock_mode=False))
        result = collector.collect()
        assert len(result) == 1
        assert result[0].device_id == "intune-dev-001"
        assert collector.skipped_count == 2
        assert "Intune skipped 2 managed device(s) with missing or invalid data" in caplog.text
        assert "00:11:22:33:44:55" not in caplog.text

    @pytest.mark.parametrize("public_ip", ["00:11:22:33:44:55", "not-an-ip", "999.1.1.1", 1234])
    def test_invalid_present_ip_skips_record_and_keeps_valid(
        self, httpx_mock: HTTPXMock, public_ip: str | int, caplog
    ):
        device = {**_DEVICE_1, "publicIpAddress": public_ip}
        httpx_mock.add_response(method="POST", url=_TOKEN_URL, json=_TOKEN_RESP)
        httpx_mock.add_response(method="GET", url=_DEVICES_URL, json={"value": [device, _DEVICE_2]})

        collector = IntuneCollector(_make_config(mock_mode=False))
        result = collector.collect()

        assert [record.device_id for record in result] == ["intune-dev-002"]
        assert collector.skipped_count == 1
        assert "Intune skipped 1 managed device(s) with missing or invalid data" in caplog.text
        with pytest.raises(CollectorError, match="invalid publicIpAddress") as exc_info:
            collector._normalize(device)
        assert str(public_ip) not in str(exc_info.value)
        assert str(public_ip) not in "".join(traceback.format_exception(exc_info.value))
        assert str(public_ip) not in caplog.text

    @pytest.mark.parametrize("body", [{}, {"value": None}, {"value": {}}, []])
    def test_malformed_response_fails(self, httpx_mock: HTTPXMock, body):
        httpx_mock.add_response(method="POST", url=_TOKEN_URL, json=_TOKEN_RESP)
        httpx_mock.add_response(method="GET", url=_DEVICES_URL, json=body)

        collector = IntuneCollector(_make_config(mock_mode=False))
        with pytest.raises(CollectorError, match="invalid managedDevices data"):
            collector.collect()

    def test_malformed_record_does_not_discard_valid_device(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(method="POST", url=_TOKEN_URL, json=_TOKEN_RESP)
        httpx_mock.add_response(method="GET", url=_DEVICES_URL, json={"value": [None, _DEVICE_1]})

        collector = IntuneCollector(_make_config(mock_mode=False))
        result = collector.collect()

        assert len(result) == 1
        assert result[0].device_id == "intune-dev-001"
        assert collector.skipped_count == 1

    @pytest.mark.parametrize("device_id", [None, "", "   ", 1234])
    def test_device_without_identity_does_not_supply_known_ip(
        self, httpx_mock: HTTPXMock, device_id: str | int | None
    ):
        unidentified = {**_DEVICE_1, "id": device_id}
        httpx_mock.add_response(method="POST", url=_TOKEN_URL, json=_TOKEN_RESP)
        httpx_mock.add_response(
            method="GET", url=_DEVICES_URL, json={"value": [unidentified, _DEVICE_2]}
        )

        collector = IntuneCollector(_make_config(mock_mode=False))
        result = collector.collect()

        assert [record.device_id for record in result] == ["intune-dev-002"]
        assert collector.skipped_count == 1

    def test_empty_response_is_valid(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(method="POST", url=_TOKEN_URL, json=_TOKEN_RESP)
        httpx_mock.add_response(method="GET", url=_DEVICES_URL, json={"value": []})

        collector = IntuneCollector(_make_config(mock_mode=False))
        assert collector.collect() == []
        assert collector.skipped_count == 0

    def test_non_json_response_fails(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(method="POST", url=_TOKEN_URL, json=_TOKEN_RESP)
        httpx_mock.add_response(method="GET", url=_DEVICES_URL, text="not-json")

        collector = IntuneCollector(_make_config(mock_mode=False))
        with pytest.raises(CollectorError, match="invalid JSON"):
            collector.collect()

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
