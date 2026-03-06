"""
Okta collector — fetches authentication events with source IPs via Okta System Log API.

@decision DEC-COLLECT-001
@title Strategy pattern — Okta adapter isolated from core logic
@status accepted
@rationale Okta uses SSWS API token auth and Link-header pagination (RFC 5988).
           This adapter encapsulates both, mapping Okta outcome strings to the
           canonical event_type Literal. mock_mode delegates to MockDataGenerator
           so no credentials are needed for tests.
"""

from __future__ import annotations

import httpx

from debacl.collectors.base import BaseCollector, CollectorConfig
from debacl.collectors.exceptions import CollectorError
from debacl.collectors.mock_data import MockDataGenerator
from debacl.models.events import ConnectionEvent


class OktaConfig(CollectorConfig):
    """Configuration for the Okta System Log collector."""

    domain: str = ""       # e.g. "https://yourorg.okta.com"
    api_token: str = ""


class OktaCollector(BaseCollector[ConnectionEvent]):
    """Collects authentication events from Okta System Log API.

    In mock_mode returns synthetic data via MockDataGenerator.
    In live mode:
      1. Issues GET /api/v1/logs filtered to user.session.start events.
      2. Follows Link: <url>; rel="next" headers until exhausted.
      3. Extracts client.ipAddress, actor.alternateId, outcome.result.
      4. Maps outcome ALLOW → auth_success, DENY/other → auth_failure.
      5. Normalises into ConnectionEvent models.

    Args:
        config: OktaConfig with domain and api_token.
    """

    _OUTCOME_MAP = {
        "SUCCESS": "auth_success",
        "ALLOW": "auth_success",
        "FAILURE": "auth_failure",
        "DENY": "auth_failure",
        "SKIPPED": "auth_failure",
        "UNKNOWN": "auth_failure",
    }

    def __init__(self, config: OktaConfig) -> None:
        super().__init__(config)
        self.config: OktaConfig = config

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"SSWS {self.config.api_token}",
            "Accept": "application/json",
        }

    def _fetch_events(self, client: httpx.Client) -> list[dict]:
        """Page through /api/v1/logs following Link rel=next headers."""
        events: list[dict] = []
        url: str | None = (
            f"{self.config.domain}/api/v1/logs"
            '?filter=eventType+eq+"user.session.start"&limit=1000'
        )
        headers = self._headers()

        while url:
            resp = client.get(url, headers=headers)
            if resp.status_code != 200:
                raise CollectorError(
                    f"Okta System Log request failed: {resp.status_code} {resp.text}"
                )
            events.extend(resp.json())
            url = self._next_link(resp.headers.get("Link", ""))

        return events

    @staticmethod
    def _next_link(link_header: str) -> str | None:
        """Parse RFC 5988 Link header and return the 'next' URL, or None."""
        for part in link_header.split(","):
            part = part.strip()
            if 'rel="next"' in part:
                url_part = part.split(";")[0].strip()
                return url_part.strip("<>")
        return None

    def _normalize(self, raw: dict) -> ConnectionEvent | None:
        """Convert a raw Okta log event to a ConnectionEvent."""
        client_ip = raw.get("client", {}).get("ipAddress")
        username = raw.get("actor", {}).get("alternateId", "")
        outcome_result = raw.get("outcome", {}).get("result", "UNKNOWN").upper()
        event_type = self._OUTCOME_MAP.get(outcome_result, "auth_failure")
        published = raw.get("published", "")

        if not client_ip or not username or not published:
            return None

        try:
            return ConnectionEvent(
                source_ip=client_ip,
                username=username,
                destination=self.config.domain or "okta",
                event_type=event_type,
                timestamp=published,
                source="okta",
                raw_data=raw,
            )
        except Exception as exc:
            raise CollectorError(f"Okta normalization error: {exc}") from exc

    # ------------------------------------------------------------------
    # BaseCollector interface
    # ------------------------------------------------------------------

    def collect(self) -> list[ConnectionEvent]:
        """Return connection events from Okta System Log.

        Uses MockDataGenerator when config.mock_mode is True.
        """
        if self.config.mock_mode:
            return MockDataGenerator().generate_connection_events("okta")

        try:
            with httpx.Client(timeout=30) as client:
                raw_events = self._fetch_events(client)
        except httpx.HTTPError as exc:
            raise CollectorError(f"Okta HTTP error: {exc}") from exc

        results: list[ConnectionEvent] = []
        for raw in raw_events:
            record = self._normalize(raw)
            if record is not None:
                results.append(record)
        return results
