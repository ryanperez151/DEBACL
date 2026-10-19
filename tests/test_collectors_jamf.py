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

    def test_mock_mode_resets_skip_count(self):
        collector = JamfCollector(_make_config(mock_mode=True))
        collector.skipped_count = 7
        collector.collect()
        assert collector.skipped_count == 0


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

    def test_skips_computers_without_ip(self, httpx_mock: HTTPXMock, caplog):
        no_ip = {"id": 99, "general": {"name": "X", "lastContactTime": "2026-03-05T08:00:00Z"}}
        httpx_mock.add_response(method="POST", url=_TOKEN_URL, json=_TOKEN_RESP)
        httpx_mock.add_response(
            method="GET",
            url=_INVENTORY_URL,
            json={"results": [no_ip], "totalCount": 1},
        )

        collector = JamfCollector(_make_config(mock_mode=False))
        assert collector.collect() == []
        assert collector.skipped_count == 1
        warnings = [record.message for record in caplog.records if record.levelname == "WARNING"]
        assert warnings == ["Jamf skipped 1 invalid or incomplete computer record(s)"]
        assert "99" not in warnings[0]

    def test_mixed_missing_invalid_and_valid_records_warn_once(self, httpx_mock: HTTPXMock, caplog):
        httpx_mock.add_response(method="POST", url=_TOKEN_URL, json=_TOKEN_RESP)
        httpx_mock.add_response(
            method="GET",
            url=_INVENTORY_URL,
            json={
                "results": [
                    {"id": 1, "general": {"lastIpAddress": None}},
                    {"id": 2, "general": {"lastIpAddress": "  "}},
                    {"id": 4, "general": {"lastIpAddress": "aa:bb:cc:dd:ee:ff"}},
                    {
                        "id": 3,
                        "general": {
                            "lastReportedIp": "2001:db8::4",
                            "lastContactTime": "2026-03-05T08:00:00Z",
                        },
                    },
                ],
                "totalCount": 4,
            },
        )

        collector = JamfCollector(_make_config(mock_mode=False))
        result = collector.collect()

        assert collector.skipped_count == 3
        assert len(result) == 1
        assert str(result[0].public_ip) == "2001:db8::4"
        warnings = [record.message for record in caplog.records if record.levelname == "WARNING"]
        assert warnings == ["Jamf skipped 3 invalid or incomplete computer record(s)"]
        assert "aa:bb:cc:dd:ee:ff" not in warnings[0]

    @pytest.mark.parametrize("bad_ip", ["aa:bb:cc:dd:ee:ff", 123])
    def test_present_invalid_ip_raises_sanitized_error(self, bad_ip):
        with pytest.raises(CollectorError, match="invalid IP address") as exc:
            JamfCollector._normalize({"id": "secret-id", "general": {"lastIpAddress": bad_ip}})
        assert str(bad_ip) not in str(exc.value)
        assert "secret-id" not in str(exc.value)

    def test_missing_ids_are_skipped_but_integer_zero_is_valid(self, httpx_mock: HTTPXMock, caplog):
        general = {"lastIpAddress": "198.51.100.20", "lastContactTime": "2026-03-05T08:00:00Z"}
        httpx_mock.add_response(method="POST", url=_TOKEN_URL, json=_TOKEN_RESP)
        httpx_mock.add_response(
            method="GET",
            url=_INVENTORY_URL,
            json={
                "results": [
                    _COMPUTER_1,
                    {"general": general},
                    {"id": "  ", "general": general},
                    {"id": 0, "general": general},
                ],
                "totalCount": 4,
            },
        )

        collector = JamfCollector(_make_config(mock_mode=False))
        result = collector.collect()

        assert collector.skipped_count == 2
        assert [(r.device_id, str(r.public_ip)) for r in result] == [
            ("1", "203.0.113.10"),
            ("0", "198.51.100.20"),
        ]
        warnings = [record.message for record in caplog.records if record.levelname == "WARNING"]
        assert warnings == ["Jamf skipped 2 invalid or incomplete computer record(s)"]
        assert "198.51.100.20" not in warnings[0]

    def test_empty_inventory_resets_skip_count(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(method="POST", url=_TOKEN_URL, json=_TOKEN_RESP)
        httpx_mock.add_response(
            method="GET",
            url=_INVENTORY_URL,
            json={"results": [], "totalCount": 0},
        )

        collector = JamfCollector(_make_config(mock_mode=False))
        collector.skipped_count = 7
        assert collector.collect() == []
        assert collector.skipped_count == 0

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

    @pytest.mark.parametrize("payload", [{}, {"results": {}}, {"results": None}])
    def test_malformed_inventory_is_fatal(self, httpx_mock: HTTPXMock, payload):
        httpx_mock.add_response(method="POST", url=_TOKEN_URL, json=_TOKEN_RESP)
        httpx_mock.add_response(method="GET", url=_INVENTORY_URL, json=payload)

        collector = JamfCollector(_make_config(mock_mode=False))
        with pytest.raises(CollectorError, match="invalid results"):
            collector.collect()

    def test_inventory_missing_declared_total_is_fatal(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(method="POST", url=_TOKEN_URL, json=_TOKEN_RESP)
        httpx_mock.add_response(method="GET", url=_INVENTORY_URL, json={"results": []})

        collector = JamfCollector(_make_config(mock_mode=False))
        with pytest.raises(CollectorError, match="invalid totalCount"):
            collector.collect()

    @pytest.mark.parametrize(
        "second_page,reason",
        [
            ({"results": [], "totalCount": 2}, "incomplete"),
            ({"results": [_COMPUTER_2], "totalCount": 3}, "inconsistent"),
        ],
    )
    def test_inventory_declared_total_mismatch_is_fatal(
        self, httpx_mock: HTTPXMock, second_page, reason
    ):
        httpx_mock.add_response(method="POST", url=_TOKEN_URL, json=_TOKEN_RESP)
        httpx_mock.add_response(
            method="GET",
            url=_INVENTORY_URL,
            json={"results": [_COMPUTER_1], "totalCount": 2},
        )
        httpx_mock.add_response(
            method="GET",
            url=_INVENTORY_URL.replace("page=0", "page=1"),
            json=second_page,
        )

        collector = JamfCollector(_make_config(mock_mode=False))
        with pytest.raises(CollectorError, match=reason):
            collector.collect()
