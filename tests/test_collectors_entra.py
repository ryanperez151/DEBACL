"""
Tests for EntraCollector — W2-6.

@decision DEC-COLLECT-001
@title Strategy pattern — Entra ID adapter tests
@status accepted
@rationale Tests cover mock mode, sign-in log normalization, errorCode mapping
           (0→auth_success, non-zero→auth_failure), @odata.nextLink pagination,
           and CollectorError on HTTP failures. All HTTP intercepted via
           pytest-httpx.
"""

from __future__ import annotations

import traceback

import pytest
from pytest_httpx import HTTPXMock

from debacl.collectors.entra import EntraCollector, EntraConfig
from debacl.collectors.exceptions import CollectorError
from debacl.models.events import ConnectionEvent


def _make_config(**kwargs) -> EntraConfig:
    return EntraConfig(
        source="entra",
        tenant_id="test-tenant",
        client_id="test-client",
        client_secret="test-secret",
        **kwargs,
    )


_TOKEN_URL = "https://login.microsoftonline.com/test-tenant/oauth2/v2.0/token"
_SIGN_INS_URL = "https://graph.microsoft.com/v1.0/auditLogs/signIns?$top=100"
_TOKEN_RESP = {"access_token": "test-token", "token_type": "Bearer", "expires_in": 3600}

_SIGN_IN_SUCCESS = {
    "id": "signin-001",
    "createdDateTime": "2026-03-05T08:00:00Z",
    "userPrincipalName": "alice.smith@corp.com",
    "ipAddress": "203.0.113.10",
    "status": {"errorCode": 0},
}
_SIGN_IN_FAILURE = {
    "id": "signin-002",
    "createdDateTime": "2026-03-05T08:01:00Z",
    "userPrincipalName": "bob.jones@corp.com",
    "ipAddress": "198.51.100.20",
    "status": {"errorCode": 50126},  # invalid credentials
}


class TestEntraMockMode:
    def test_mock_mode_returns_list(self):
        collector = EntraCollector(_make_config(mock_mode=True))
        assert isinstance(collector.collect(), list)

    def test_mock_mode_returns_connection_events(self):
        collector = EntraCollector(_make_config(mock_mode=True))
        assert all(isinstance(e, ConnectionEvent) for e in collector.collect())

    def test_mock_mode_source_is_entra(self):
        collector = EntraCollector(_make_config(mock_mode=True))
        assert all(e.source == "entra" for e in collector.collect())

    def test_mock_mode_non_empty(self):
        collector = EntraCollector(_make_config(mock_mode=True))
        assert len(collector.collect()) > 0

    def test_mock_mode_resets_skip_count(self):
        collector = EntraCollector(_make_config(mock_mode=True))
        collector.skipped_count = 3
        collector.collect()
        assert collector.skipped_count == 0


class TestEntraLiveMode:
    def test_normalization_correct(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(method="POST", url=_TOKEN_URL, json=_TOKEN_RESP)
        httpx_mock.add_response(
            method="GET",
            url=_SIGN_INS_URL,
            json={"value": [_SIGN_IN_SUCCESS, _SIGN_IN_FAILURE]},
        )

        collector = EntraCollector(_make_config(mock_mode=False))
        result = collector.collect()

        assert len(result) == 2
        assert all(isinstance(e, ConnectionEvent) for e in result)
        assert result[0].source == "entra"
        assert str(result[0].source_ip) == "203.0.113.10"
        assert result[0].username == "alice.smith@corp.com"
        assert result[0].timestamp.isoformat() == "2026-03-05T08:00:00+00:00"
        assert result[0].raw_data == _SIGN_IN_SUCCESS

    def test_ipv6_normalization(self, httpx_mock: HTTPXMock):
        sign_in = {**_SIGN_IN_SUCCESS, "ipAddress": "2001:db8::10"}
        httpx_mock.add_response(method="POST", url=_TOKEN_URL, json=_TOKEN_RESP)
        httpx_mock.add_response(method="GET", url=_SIGN_INS_URL, json={"value": [sign_in]})

        collector = EntraCollector(_make_config(mock_mode=False))
        result = collector.collect()

        assert len(result) == 1
        assert str(result[0].source_ip) == "2001:db8::10"
        assert collector.skipped_count == 0

    def test_error_code_zero_maps_to_auth_success(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(method="POST", url=_TOKEN_URL, json=_TOKEN_RESP)
        httpx_mock.add_response(method="GET", url=_SIGN_INS_URL, json={"value": [_SIGN_IN_SUCCESS]})

        collector = EntraCollector(_make_config(mock_mode=False))
        result = collector.collect()
        assert result[0].event_type == "auth_success"

    def test_nonzero_error_code_maps_to_auth_failure(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(method="POST", url=_TOKEN_URL, json=_TOKEN_RESP)
        httpx_mock.add_response(method="GET", url=_SIGN_INS_URL, json={"value": [_SIGN_IN_FAILURE]})

        collector = EntraCollector(_make_config(mock_mode=False))
        result = collector.collect()
        assert result[0].event_type == "auth_failure"

    def test_pagination_follows_next_link(self, httpx_mock: HTTPXMock):
        page2_url = _SIGN_INS_URL + "&$skiptoken=xyz"
        httpx_mock.add_response(method="POST", url=_TOKEN_URL, json=_TOKEN_RESP)
        httpx_mock.add_response(
            method="GET",
            url=_SIGN_INS_URL,
            json={"value": [_SIGN_IN_SUCCESS], "@odata.nextLink": page2_url},
        )
        httpx_mock.add_response(
            method="GET",
            url=page2_url,
            json={"value": [_SIGN_IN_FAILURE]},
        )

        collector = EntraCollector(_make_config(mock_mode=False))
        result = collector.collect()
        assert len(result) == 2

    def test_skips_events_missing_required_fields(self, httpx_mock: HTTPXMock, caplog):
        # missing ip, username, createdDateTime
        incomplete = {"id": "x", "status": {"errorCode": 0}}
        blank_ip = {**_SIGN_IN_SUCCESS, "ipAddress": "   "}
        httpx_mock.add_response(method="POST", url=_TOKEN_URL, json=_TOKEN_RESP)
        httpx_mock.add_response(
            method="GET",
            url=_SIGN_INS_URL,
            json={"value": [incomplete, blank_ip, _SIGN_IN_SUCCESS]},
        )

        collector = EntraCollector(_make_config(mock_mode=False))
        result = collector.collect()
        assert len(result) == 1
        assert collector.skipped_count == 2
        assert "Entra skipped 2 sign-in(s) with missing or invalid data" in caplog.text
        assert "alice.smith@corp.com" not in caplog.text

    @pytest.mark.parametrize("bad_ip", ["00:11:22:33:44:55", "not-an-ip", "999.1.1.1", 1234])
    def test_invalid_present_ip_skips_record_and_keeps_valid(
        self, httpx_mock: HTTPXMock, bad_ip: str | int, caplog
    ):
        sign_in = {**_SIGN_IN_SUCCESS, "ipAddress": bad_ip}
        httpx_mock.add_response(method="POST", url=_TOKEN_URL, json=_TOKEN_RESP)
        httpx_mock.add_response(
            method="GET", url=_SIGN_INS_URL, json={"value": [sign_in, _SIGN_IN_FAILURE]}
        )

        collector = EntraCollector(_make_config(mock_mode=False))
        result = collector.collect()

        assert [record.username for record in result] == ["bob.jones@corp.com"]
        assert collector.skipped_count == 1
        assert "Entra skipped 1 sign-in(s) with missing or invalid data" in caplog.text
        with pytest.raises(CollectorError, match="invalid ipAddress") as exc_info:
            collector._normalize(sign_in)
        assert str(bad_ip) not in "".join(traceback.format_exception(exc_info.value))
        assert str(bad_ip) not in caplog.text

    def test_malformed_record_does_not_discard_valid_event(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(method="POST", url=_TOKEN_URL, json=_TOKEN_RESP)
        httpx_mock.add_response(
            method="GET", url=_SIGN_INS_URL, json={"value": [None, _SIGN_IN_SUCCESS]}
        )

        collector = EntraCollector(_make_config(mock_mode=False))
        result = collector.collect()

        assert len(result) == 1
        assert result[0].username == "alice.smith@corp.com"
        assert collector.skipped_count == 1

    @pytest.mark.parametrize("body", [{}, {"value": None}, {"value": {}}, []])
    def test_malformed_response_fails(self, httpx_mock: HTTPXMock, body):
        httpx_mock.add_response(method="POST", url=_TOKEN_URL, json=_TOKEN_RESP)
        httpx_mock.add_response(method="GET", url=_SIGN_INS_URL, json=body)

        collector = EntraCollector(_make_config(mock_mode=False))
        with pytest.raises(CollectorError, match="invalid event data"):
            collector.collect()

    def test_non_json_response_fails(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(method="POST", url=_TOKEN_URL, json=_TOKEN_RESP)
        httpx_mock.add_response(method="GET", url=_SIGN_INS_URL, text="not-json")

        collector = EntraCollector(_make_config(mock_mode=False))
        with pytest.raises(CollectorError, match="invalid JSON"):
            collector.collect()

    def test_empty_provider_response_resets_skip_count(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(method="POST", url=_TOKEN_URL, json=_TOKEN_RESP)
        httpx_mock.add_response(method="GET", url=_SIGN_INS_URL, json={"value": []})
        collector = EntraCollector(_make_config(mock_mode=False))
        collector.skipped_count = 3
        assert collector.collect() == []
        assert collector.skipped_count == 0

    def test_token_failure_raises_collector_error(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(method="POST", url=_TOKEN_URL, status_code=401, text="Unauthorized")

        collector = EntraCollector(_make_config(mock_mode=False))
        with pytest.raises(CollectorError, match="MSAL token"):
            collector.collect()

    def test_sign_ins_failure_raises_collector_error(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(method="POST", url=_TOKEN_URL, json=_TOKEN_RESP)
        httpx_mock.add_response(method="GET", url=_SIGN_INS_URL, status_code=403, text="Forbidden")

        collector = EntraCollector(_make_config(mock_mode=False))
        with pytest.raises(CollectorError, match="sign-in log"):
            collector.collect()
