"""
Microsoft Entra ID collector — fetches sign-in logs via Microsoft Graph API.

@decision DEC-COLLECT-001
@title Strategy pattern — Entra ID adapter isolated from core logic
@status accepted
@rationale Entra ID (formerly Azure AD) exposes sign-in logs through Graph
           /auditLogs/signIns. This adapter handles MSAL client-credentials
           auth and @odata.nextLink pagination transparently. errorCode=0
           indicates success; any non-zero code maps to auth_failure.
           mock_mode delegates to MockDataGenerator so no credentials are
           needed for tests.
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


class EntraConfig(CollectorConfig):
    """Configuration for the Microsoft Entra ID (Graph API) collector."""

    tenant_id: str = ""
    client_id: str = ""
    client_secret: str = ""
    graph_base_url: str = "https://graph.microsoft.com/v1.0"


class EntraCollector(BaseCollector[ConnectionEvent]):
    """Collects sign-in events from Microsoft Entra ID via Graph API.

    In mock_mode returns synthetic data via MockDataGenerator.
    In live mode:
      1. Obtains a client-credentials Bearer token from the MSAL token endpoint.
      2. Pages through GET /auditLogs/signIns following @odata.nextLink.
      3. Extracts ipAddress, userPrincipalName, status.errorCode.
      4. Maps errorCode==0 → auth_success, non-zero → auth_failure.
      5. Normalises into ConnectionEvent models.

    Args:
        config: EntraConfig with tenant, client credentials, and graph_base_url.
    """

    def __init__(self, config: EntraConfig) -> None:
        super().__init__(config)
        self.config: EntraConfig = config
        self.skipped_count = 0

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_token(self, client: httpx.Client) -> str:
        """Obtain a Bearer token via MSAL client credentials flow."""
        token_url = f"https://login.microsoftonline.com/{self.config.tenant_id}/oauth2/v2.0/token"
        resp = client.post(
            token_url,
            data={
                "grant_type": "client_credentials",
                "client_id": self.config.client_id,
                "client_secret": self.config.client_secret,
                "scope": "https://graph.microsoft.com/.default",
            },
        )
        if resp.status_code != 200:
            raise CollectorError(f"Entra MSAL token request failed: {resp.status_code} {resp.text}")
        return resp.json()["access_token"]

    def _fetch_sign_ins(self, client: httpx.Client, token: str) -> list[dict]:
        """Page through /auditLogs/signIns following @odata.nextLink."""
        sign_ins: list[dict] = []
        url: str | None = f"{self.config.graph_base_url}/auditLogs/signIns?$top=100"
        headers = {"Authorization": f"Bearer {token}"}

        while url:
            resp = client.get(url, headers=headers)
            if resp.status_code != 200:
                raise CollectorError(
                    f"Entra sign-in log request failed: {resp.status_code} {resp.text}"
                )
            try:
                body = resp.json()
            except ValueError:
                raise CollectorError("Entra sign-in log returned invalid JSON") from None
            if not isinstance(body, dict) or not isinstance(body.get("value"), list):
                raise CollectorError("Entra sign-in log returned invalid event data")
            next_link = body.get("@odata.nextLink")
            if next_link is not None and not isinstance(next_link, str):
                raise CollectorError("Entra sign-in log returned invalid pagination data")
            sign_ins.extend(body["value"])
            url = next_link

        return sign_ins

    @staticmethod
    def _normalize(raw: dict) -> ConnectionEvent | None:
        """Convert a raw Graph signIn record to a ConnectionEvent."""
        if not isinstance(raw, dict):
            raise CollectorError("Entra normalization error: invalid sign-in record")
        ip = raw.get("ipAddress")
        username = raw.get("userPrincipalName", "")
        created_at = raw.get("createdDateTime", "")

        if any(
            value is None or (isinstance(value, str) and not value.strip())
            for value in (ip, username, created_at)
        ):
            return None

        if not isinstance(ip, str):
            raise CollectorError("Entra normalization error: invalid ipAddress")
        try:
            parsed_ip = ip_address(ip.strip())
        except ValueError:
            raise CollectorError("Entra normalization error: invalid ipAddress") from None

        status = raw.get("status") or {}
        if not isinstance(status, dict):
            raise CollectorError("Entra normalization error: invalid sign-in record")
        error_code = status.get("errorCode", -1)
        event_type = "auth_success" if error_code == 0 else "auth_failure"
        try:
            return ConnectionEvent(
                source_ip=parsed_ip,
                username=username,
                destination="entra",
                event_type=event_type,
                timestamp=created_at,
                source="entra",
                raw_data=raw,
            )
        except Exception:
            raise CollectorError("Entra normalization error: invalid sign-in record") from None

    # ------------------------------------------------------------------
    # BaseCollector interface
    # ------------------------------------------------------------------

    def collect(self) -> list[ConnectionEvent]:
        """Return sign-in events from Microsoft Entra ID.

        Uses MockDataGenerator when config.mock_mode is True.
        """
        self.skipped_count = 0
        if self.config.mock_mode:
            return MockDataGenerator().generate_connection_events("entra")

        try:
            with httpx.Client(timeout=30) as client:
                token = self._get_token(client)
                raw_sign_ins = self._fetch_sign_ins(client, token)
        except httpx.HTTPError as exc:
            raise CollectorError(f"Entra HTTP error: {exc}") from exc

        results: list[ConnectionEvent] = []
        for raw in raw_sign_ins:
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
                "Entra skipped %d sign-in(s) with missing or invalid data", self.skipped_count
            )
        return results
