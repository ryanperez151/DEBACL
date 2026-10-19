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

import logging
from ipaddress import ip_address

import httpx

from debacl.collectors.base import BaseCollector, CollectorConfig
from debacl.collectors.exceptions import CollectorError
from debacl.collectors.mock_data import MockDataGenerator
from debacl.models.events import ConnectionEvent

logger = logging.getLogger(__name__)


class OktaConfig(CollectorConfig):
    """Configuration for the Okta System Log collector."""

    domain: str = ""  # e.g. "https://yourorg.okta.com"
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
        self.skipped_count = 0

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
            f'{self.config.domain}/api/v1/logs?filter=eventType+eq+"user.session.start"&limit=1000'
        )
        headers = self._headers()

        while url:
            resp = client.get(url, headers=headers)
            if resp.status_code != 200:
                raise CollectorError(
                    f"Okta System Log request failed: {resp.status_code} {resp.text}"
                )
            try:
                page = resp.json()
            except ValueError:
                raise CollectorError("Okta System Log returned invalid JSON") from None
            if not isinstance(page, list):
                raise CollectorError("Okta System Log returned invalid event data")
            events.extend(page)
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
        if not isinstance(raw, dict):
            raise CollectorError("Okta normalization error: invalid event record")
        client = raw.get("client") or {}
        actor = raw.get("actor") or {}
        if not isinstance(client, dict) or not isinstance(actor, dict):
            raise CollectorError("Okta normalization error: invalid event record")
        client_ip = client.get("ipAddress")
        username = actor.get("alternateId", "")
        published = raw.get("published", "")

        if any(
            value is None or (isinstance(value, str) and not value.strip())
            for value in (client_ip, username, published)
        ):
            return None

        if not isinstance(client_ip, str):
            raise CollectorError("Okta normalization error: invalid client.ipAddress")
        try:
            parsed_ip = ip_address(client_ip.strip())
        except ValueError:
            raise CollectorError("Okta normalization error: invalid client.ipAddress") from None

        outcome = raw.get("outcome") or {}
        if not isinstance(outcome, dict):
            raise CollectorError("Okta normalization error: invalid event record")
        outcome_result = outcome.get("result", "UNKNOWN")
        if not isinstance(outcome_result, str):
            raise CollectorError("Okta normalization error: invalid event record")
        outcome_result = outcome_result.upper()
        event_type = self._OUTCOME_MAP.get(outcome_result, "auth_failure")
        try:
            return ConnectionEvent(
                source_ip=parsed_ip,
                username=username,
                destination=self.config.domain or "okta",
                event_type=event_type,
                timestamp=published,
                source="okta",
                raw_data=raw,
            )
        except Exception:
            raise CollectorError("Okta normalization error: invalid event record") from None

    # ------------------------------------------------------------------
    # BaseCollector interface
    # ------------------------------------------------------------------

    def collect(self) -> list[ConnectionEvent]:
        """Return connection events from Okta System Log.

        Uses MockDataGenerator when config.mock_mode is True.
        """
        self.skipped_count = 0
        if self.config.mock_mode:
            return MockDataGenerator().generate_connection_events("okta")

        try:
            with httpx.Client(timeout=30) as client:
                raw_events = self._fetch_events(client)
        except httpx.HTTPError as exc:
            raise CollectorError(f"Okta HTTP error: {exc}") from exc

        results: list[ConnectionEvent] = []
        for raw in raw_events:
            try:
                record = self._normalize(raw)
            except CollectorError:
                self.skipped_count += 1
                continue
            if record is not None:
                results.append(record)
            else:
                self.skipped_count += 1
        if self.skipped_count:
            logger.warning(
                "Okta skipped %d event(s) with missing or invalid data", self.skipped_count
            )
        return results
