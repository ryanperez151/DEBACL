"""
Tests for OktaCollector — W2-5.

@decision DEC-COLLECT-001
@title Strategy pattern — Okta adapter tests
@status accepted
@rationale Tests cover mock mode, event normalization, outcome mapping
           (ALLOW→auth_success, DENY→auth_failure), Link-header pagination,
           and CollectorError on HTTP failures. All HTTP intercepted via
           pytest-httpx.
"""

from __future__ import annotations

import pytest
from pytest_httpx import HTTPXMock

from debacl.collectors.exceptions import CollectorError
from debacl.collectors.okta import OktaCollector, OktaConfig
from debacl.models.events import ConnectionEvent


def _make_config(**kwargs) -> OktaConfig:
    return OktaConfig(
        source="okta",
        domain="https://test.okta.com",
        api_token="test-ssws-token",
        **kwargs,
    )


_LOGS_URL = (
    'https://test.okta.com/api/v1/logs'
    '?filter=eventType+eq+"user.session.start"&limit=1000'
)

_EVENT_ALLOW = {
    "published": "2026-03-05T08:00:00Z",
    "actor": {"alternateId": "alice.smith@corp.com"},
    "client": {"ipAddress": "203.0.113.10"},
    "outcome": {"result": "SUCCESS"},
}
_EVENT_DENY = {
    "published": "2026-03-05T08:01:00Z",
    "actor": {"alternateId": "bob.jones@corp.com"},
    "client": {"ipAddress": "198.51.100.20"},
    "outcome": {"result": "FAILURE"},
}


class TestOktaMockMode:
    def test_mock_mode_returns_list(self):
        collector = OktaCollector(_make_config(mock_mode=True))
        assert isinstance(collector.collect(), list)

    def test_mock_mode_returns_connection_events(self):
        collector = OktaCollector(_make_config(mock_mode=True))
        assert all(isinstance(e, ConnectionEvent) for e in collector.collect())

    def test_mock_mode_source_is_okta(self):
        collector = OktaCollector(_make_config(mock_mode=True))
        assert all(e.source == "okta" for e in collector.collect())

    def test_mock_mode_non_empty(self):
        collector = OktaCollector(_make_config(mock_mode=True))
        assert len(collector.collect()) > 0


class TestOktaLiveMode:
    def test_normalization_correct(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(method="GET", url=_LOGS_URL, json=[_EVENT_ALLOW, _EVENT_DENY])

        collector = OktaCollector(_make_config(mock_mode=False))
        result = collector.collect()

        assert len(result) == 2
        assert all(isinstance(e, ConnectionEvent) for e in result)
        assert result[0].source == "okta"
        assert str(result[0].source_ip) == "203.0.113.10"
        assert result[0].username == "alice.smith@corp.com"

    def test_outcome_allow_maps_to_auth_success(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(method="GET", url=_LOGS_URL, json=[_EVENT_ALLOW])

        collector = OktaCollector(_make_config(mock_mode=False))
        result = collector.collect()

        assert result[0].event_type == "auth_success"

    def test_outcome_deny_maps_to_auth_failure(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(method="GET", url=_LOGS_URL, json=[_EVENT_DENY])

        collector = OktaCollector(_make_config(mock_mode=False))
        result = collector.collect()

        assert result[0].event_type == "auth_failure"

    def test_link_header_pagination(self, httpx_mock: HTTPXMock):
        page2_url = "https://test.okta.com/api/v1/logs?after=abc"
        httpx_mock.add_response(
            method="GET",
            url=_LOGS_URL,
            json=[_EVENT_ALLOW],
            headers={"Link": f'<{page2_url}>; rel="next"'},
        )
        httpx_mock.add_response(
            method="GET",
            url=page2_url,
            json=[_EVENT_DENY],
        )

        collector = OktaCollector(_make_config(mock_mode=False))
        result = collector.collect()
        assert len(result) == 2

    def test_skips_events_missing_fields(self, httpx_mock: HTTPXMock):
        incomplete = {"published": "2026-03-05T08:00:00Z"}  # missing actor, client
        httpx_mock.add_response(method="GET", url=_LOGS_URL, json=[incomplete])

        collector = OktaCollector(_make_config(mock_mode=False))
        assert collector.collect() == []

    def test_http_error_raises_collector_error(self, httpx_mock: HTTPXMock):
        httpx_mock.add_response(method="GET", url=_LOGS_URL, status_code=401, text="Unauthorized")

        collector = OktaCollector(_make_config(mock_mode=False))
        with pytest.raises(CollectorError, match="System Log"):
            collector.collect()

    def test_next_link_parser(self):
        collector = OktaCollector(_make_config())
        link = (
            '<https://example.okta.com/api/v1/logs?after=abc>; rel="next", <https://x>; rel="self"'
        )
        assert collector._next_link(link) == "https://example.okta.com/api/v1/logs?after=abc"

    def test_next_link_parser_no_next(self):
        collector = OktaCollector(_make_config())
        assert collector._next_link('<https://x>; rel="self"') is None
