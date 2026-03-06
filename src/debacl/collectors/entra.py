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

import httpx

from debacl.collectors.base import BaseCollector, CollectorConfig
from debacl.collectors.exceptions import CollectorError
from debacl.collectors.mock_data import MockDataGenerator
from debacl.models.events import ConnectionEvent


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

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_token(self, client: httpx.Client) -> str:
        """Obtain a Bearer token via MSAL client credentials flow."""
        token_url = (
            f"https://login.microsoftonline.com/{self.config.tenant_id}"
            "/oauth2/v2.0/token"
        )
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
            raise CollectorError(
                f"Entra MSAL token request failed: {resp.status_code} {resp.text}"
            )
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
            body = resp.json()
            sign_ins.extend(body.get("value", []))
            url = body.get("@odata.nextLink")

        return sign_ins

    @staticmethod
    def _normalize(raw: dict) -> ConnectionEvent | None:
        """Convert a raw Graph signIn record to a ConnectionEvent."""
        ip = raw.get("ipAddress")
        username = raw.get("userPrincipalName", "")
        status = raw.get("status", {})
        error_code = status.get("errorCode", -1)
        event_type = "auth_success" if error_code == 0 else "auth_failure"
        created_at = raw.get("createdDateTime", "")

        if not ip or not username or not created_at:
            return None

        try:
            return ConnectionEvent(
                source_ip=ip,
                username=username,
                destination="entra",
                event_type=event_type,
                timestamp=created_at,
                source="entra",
                raw_data=raw,
            )
        except Exception as exc:
            raise CollectorError(f"Entra normalization error: {exc}") from exc

    # ------------------------------------------------------------------
    # BaseCollector interface
    # ------------------------------------------------------------------

    def collect(self) -> list[ConnectionEvent]:
        """Return sign-in events from Microsoft Entra ID.

        Uses MockDataGenerator when config.mock_mode is True.
        """
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
            record = self._normalize(raw)
            if record is not None:
                results.append(record)
        return results
