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

    def test_mock_mode_resets_skip_count(self):
        collector = CrowdStrikeCollector(_make_config(mock_mode=True))
        collector.skipped_count = 7
        collector.collect()
        assert collector.skipped_count == 0


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

    def test_normalization_skips_missing_external_ip(self, httpx_mock: HTTPXMock, caplog):
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
        assert collector.skipped_count == 1
        warnings = [record.message for record in caplog.records if record.levelname == "WARNING"]
        assert warnings == ["CrowdStrike skipped 1 invalid or incomplete device record(s)"]
        assert "device-003" not in warnings[0]

    def test_mixed_missing_invalid_and_valid_records_warn_once(self, httpx_mock: HTTPXMock, caplog):
        httpx_mock.add_response(
            method="POST",
            url="https://api.crowdstrike.com/oauth2/token",
            json=_TOKEN_RESP,
            status_code=201,
        )
        httpx_mock.add_response(
            method="GET",
            url="https://api.crowdstrike.com/devices/queries/devices/v1?limit=500&offset=0",
            json={
                "resources": ["device-1", "device-2", "device-3", "device-4"],
                "meta": {"pagination": {"total": 4}},
            },
        )
        httpx_mock.add_response(
            method="POST",
            url="https://api.crowdstrike.com/devices/entities/devices/v2",
            json={
                "resources": [
                    {"device_id": "device-1", "external_ip": None},
                    {"device_id": "device-2", "external_ip": "  "},
                    {"device_id": "device-4", "external_ip": "aa:bb:cc:dd:ee:ff"},
                    {
                        "device_id": "device-3",
                        "external_ip": "2001:db8::4",
                        "last_seen": "2026-03-05T08:00:00Z",
                    },
                ]
            },
        )

        collector = CrowdStrikeCollector(_make_config(mock_mode=False))
        result = collector.collect()

        assert collector.skipped_count == 3
        assert len(result) == 1
        assert str(result[0].public_ip) == "2001:db8::4"
        warnings = [record.message for record in caplog.records if record.levelname == "WARNING"]
        assert warnings == ["CrowdStrike skipped 3 invalid or incomplete device record(s)"]
        assert "device-4" not in warnings[0]
        assert "aa:bb:cc:dd:ee:ff" not in warnings[0]

    @pytest.mark.parametrize("bad_ip", ["aa:bb:cc:dd:ee:ff", 123])
    def test_present_invalid_ip_raises_sanitized_error(self, bad_ip):
        with pytest.raises(CollectorError, match="invalid external_ip") as exc:
            CrowdStrikeCollector._normalize({"external_ip": bad_ip, "device_id": "secret-id"})
        assert str(bad_ip) not in str(exc.value)
        assert "secret-id" not in str(exc.value)

    @pytest.mark.parametrize("missing_id", [None, "", "  "])
    def test_detail_without_device_id_is_skipped_not_trusted(
        self, httpx_mock: HTTPXMock, caplog, missing_id
    ):
        httpx_mock.add_response(
            method="POST",
            url="https://api.crowdstrike.com/oauth2/token",
            json=_TOKEN_RESP,
            status_code=201,
        )
        httpx_mock.add_response(
            method="GET",
            url="https://api.crowdstrike.com/devices/queries/devices/v1?limit=500&offset=0",
            json={
                "resources": ["device-valid", "device-incomplete"],
                "meta": {"pagination": {"total": 2}},
            },
        )
        httpx_mock.add_response(
            method="POST",
            url="https://api.crowdstrike.com/devices/entities/devices/v2",
            json={
                "resources": [
                    {
                        "device_id": "device-valid",
                        "external_ip": "203.0.113.10",
                        "last_seen": "2026-03-05T08:00:00Z",
                    },
                    {
                        "device_id": missing_id,
                        "external_ip": "198.51.100.20",
                        "last_seen": "2026-03-05T08:00:00Z",
                    },
                ]
            },
        )

        collector = CrowdStrikeCollector(_make_config(mock_mode=False))
        result = collector.collect()

        assert collector.skipped_count == 1
        assert [(r.device_id, str(r.public_ip)) for r in result] == [
            ("device-valid", "203.0.113.10")
        ]
        warnings = [record.message for record in caplog.records if record.levelname == "WARNING"]
        assert warnings == ["CrowdStrike skipped 1 invalid or incomplete device record(s)"]
        assert "198.51.100.20" not in warnings[0]

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

    @pytest.mark.parametrize("payload", [{}, {"resources": {}}, {"resources": None}])
    def test_malformed_device_query_is_fatal(self, httpx_mock: HTTPXMock, payload):
        httpx_mock.add_response(
            method="POST",
            url="https://api.crowdstrike.com/oauth2/token",
            json=_TOKEN_RESP,
            status_code=201,
        )
        httpx_mock.add_response(
            method="GET",
            url="https://api.crowdstrike.com/devices/queries/devices/v1?limit=500&offset=0",
            json=payload,
        )

        collector = CrowdStrikeCollector(_make_config(mock_mode=False))
        with pytest.raises(CollectorError, match="invalid resources"):
            collector.collect()

    def test_query_missing_declared_total_is_fatal(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            method="POST",
            url="https://api.crowdstrike.com/oauth2/token",
            json=_TOKEN_RESP,
            status_code=201,
        )
        httpx_mock.add_response(
            method="GET",
            url="https://api.crowdstrike.com/devices/queries/devices/v1?limit=500&offset=0",
            json={"resources": [], "meta": {"pagination": {}}},
        )

        collector = CrowdStrikeCollector(_make_config(mock_mode=False))
        with pytest.raises(CollectorError, match="invalid pagination"):
            collector.collect()

    @pytest.mark.parametrize(
        "second_page,reason",
        [
            ({"resources": [], "meta": {"pagination": {"total": 2}}}, "incomplete"),
            ({"resources": ["device-002"], "meta": {"pagination": {"total": 3}}}, "inconsistent"),
        ],
    )
    def test_query_declared_total_mismatch_is_fatal(
        self, httpx_mock: HTTPXMock, second_page, reason
    ):
        httpx_mock.add_response(
            method="POST",
            url="https://api.crowdstrike.com/oauth2/token",
            json=_TOKEN_RESP,
            status_code=201,
        )
        httpx_mock.add_response(
            method="GET",
            url="https://api.crowdstrike.com/devices/queries/devices/v1?limit=500&offset=0",
            json={"resources": ["device-001"], "meta": {"pagination": {"total": 2}}},
        )
        httpx_mock.add_response(
            method="GET",
            url="https://api.crowdstrike.com/devices/queries/devices/v1?limit=500&offset=1",
            json=second_page,
        )

        collector = CrowdStrikeCollector(_make_config(mock_mode=False))
        with pytest.raises(CollectorError, match=reason):
            collector.collect()

    @pytest.mark.parametrize("payload", [{}, {"resources": {}}, {"resources": []}])
    def test_malformed_or_incomplete_details_are_fatal(self, httpx_mock: HTTPXMock, payload):
        httpx_mock.add_response(
            method="POST",
            url="https://api.crowdstrike.com/oauth2/token",
            json=_TOKEN_RESP,
            status_code=201,
        )
        httpx_mock.add_response(
            method="GET",
            url="https://api.crowdstrike.com/devices/queries/devices/v1?limit=500&offset=0",
            json={"resources": ["device-001"], "meta": {"pagination": {"total": 1}}},
        )
        httpx_mock.add_response(
            method="POST",
            url="https://api.crowdstrike.com/devices/entities/devices/v2",
            json=payload,
        )

        collector = CrowdStrikeCollector(_make_config(mock_mode=False))
        with pytest.raises(CollectorError, match="invalid resources|incomplete"):
            collector.collect()

    def test_details_missing_one_queried_id_are_fatal(self, httpx_mock: HTTPXMock):
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
            json={"resources": [_DEVICE_DETAILS_RESP["resources"][0]]},
        )

        collector = CrowdStrikeCollector(_make_config(mock_mode=False))
        with pytest.raises(CollectorError, match="incomplete"):
            collector.collect()

    def test_details_with_unqueried_id_are_fatal(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            method="POST",
            url="https://api.crowdstrike.com/oauth2/token",
            json=_TOKEN_RESP,
            status_code=201,
        )
        httpx_mock.add_response(
            method="GET",
            url="https://api.crowdstrike.com/devices/queries/devices/v1?limit=500&offset=0",
            json={"resources": ["device-001"], "meta": {"pagination": {"total": 1}}},
        )
        httpx_mock.add_response(
            method="POST",
            url="https://api.crowdstrike.com/devices/entities/devices/v2",
            json={"resources": [{"device_id": "unexpected", "external_ip": "203.0.113.10"}]},
        )

        collector = CrowdStrikeCollector(_make_config(mock_mode=False))
        with pytest.raises(CollectorError, match="incomplete"):
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
        collector.skipped_count = 7
        result = collector.collect()
        assert result == []
        assert collector.skipped_count == 0
