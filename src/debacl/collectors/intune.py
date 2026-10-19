"""
Microsoft Intune collector — fetches managed device public IPs via Microsoft Graph API.

@decision DEC-COLLECT-001
@title Strategy pattern — Intune adapter isolated from core logic
@status accepted
@rationale Intune device data is exposed through Microsoft Graph. This adapter
           handles MSAL client-credentials auth and Graph pagination (@odata.nextLink)
           transparently, presenting a clean collect() interface to the rest of the
           system. mock_mode delegates to MockDataGenerator so no credentials are
           needed for tests.
"""

from __future__ import annotations

import logging
from ipaddress import ip_address

import httpx

from debacl.collectors.base import BaseCollector, CollectorConfig
from debacl.collectors.exceptions import CollectorError
from debacl.collectors.mock_data import MockDataGenerator
from debacl.models.telemetry import EndpointTelemetry

logger = logging.getLogger(__name__)


class IntuneConfig(CollectorConfig):
    """Configuration for the Microsoft Intune (Graph API) collector."""

    tenant_id: str = ""
    client_id: str = ""
    client_secret: str = ""
    graph_base_url: str = "https://graph.microsoft.com/v1.0"


class IntuneCollector(BaseCollector[EndpointTelemetry]):
    """Collects managed device telemetry from Microsoft Intune via Graph API.

    In mock_mode returns synthetic data via MockDataGenerator.
    In live mode:
      1. Obtains a client-credentials Bearer token from the MSAL token endpoint.
      2. Pages through GET /deviceManagement/managedDevices, following @odata.nextLink.
      3. Normalises each device record into an EndpointTelemetry model.

    Args:
        config: IntuneConfig with tenant, client credentials, and graph_base_url.
    """

    def __init__(self, config: IntuneConfig) -> None:
        super().__init__(config)
        self.config: IntuneConfig = config
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
            raise CollectorError(
                f"Intune MSAL token request failed: {resp.status_code} {resp.text}"
            )
        return resp.json()["access_token"]

    def _fetch_devices(self, client: httpx.Client, token: str) -> list[dict]:
        """Page through managedDevices, following @odata.nextLink until exhausted."""
        devices: list[dict] = []
        url: str | None = f"{self.config.graph_base_url}/deviceManagement/managedDevices"
        headers = {"Authorization": f"Bearer {token}"}

        while url:
            resp = client.get(url, headers=headers)
            if resp.status_code != 200:
                raise CollectorError(
                    f"Intune Graph API request failed: {resp.status_code} {resp.text}"
                )
            try:
                body = resp.json()
            except ValueError:
                raise CollectorError("Intune Graph API returned invalid JSON") from None
            if not isinstance(body, dict) or not isinstance(body.get("value"), list):
                raise CollectorError("Intune Graph API returned invalid managedDevices data")
            next_link = body.get("@odata.nextLink")
            if next_link is not None and not isinstance(next_link, str):
                raise CollectorError("Intune Graph API returned invalid pagination data")
            devices.extend(body["value"])
            url = next_link

        return devices

    @staticmethod
    def _normalize(raw: dict) -> EndpointTelemetry | None:
        """Convert a managedDevice with an explicit public IP to telemetry.

        A MAC address identifies a network interface, not an IP address. Devices
        without ``publicIpAddress`` cannot participate in IP correlation.
        """
        if not isinstance(raw, dict):
            raise CollectorError("Intune normalization error: invalid managed device record")
        device_id = raw.get("id")
        if device_id is None or (isinstance(device_id, str) and not device_id.strip()):
            return None
        if not isinstance(device_id, str):
            raise CollectorError("Intune normalization error: invalid device id")
        public_ip = raw.get("publicIpAddress")
        if public_ip is None or (isinstance(public_ip, str) and not public_ip.strip()):
            return None

        if not isinstance(public_ip, str):
            raise CollectorError("Intune normalization error: invalid publicIpAddress")

        try:
            parsed_ip = ip_address(public_ip.strip())
        except ValueError:
            raise CollectorError("Intune normalization error: invalid publicIpAddress") from None

        try:
            return EndpointTelemetry(
                device_id=device_id.strip(),
                hostname=raw.get("deviceName", ""),
                public_ip=parsed_ip,
                source="intune",
                timestamp=raw.get("lastSyncDateTime", ""),
                health_status=raw.get("complianceState"),
                raw_data=raw,
            )
        except Exception:
            raise CollectorError(
                "Intune normalization error: invalid managed device record"
            ) from None

    # ------------------------------------------------------------------
    # BaseCollector interface
    # ------------------------------------------------------------------

    def collect(self) -> list[EndpointTelemetry]:
        """Return endpoint telemetry from Microsoft Intune.

        Uses MockDataGenerator when config.mock_mode is True.
        """
        self.skipped_count = 0
        if self.config.mock_mode:
            return MockDataGenerator().generate_endpoint_telemetry("intune")

        try:
            with httpx.Client(timeout=30) as client:
                token = self._get_token(client)
                raw_devices = self._fetch_devices(client, token)
        except httpx.HTTPError as exc:
            raise CollectorError(f"Intune HTTP error: {exc}") from exc

        results: list[EndpointTelemetry] = []
        for raw in raw_devices:
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
                "Intune skipped %d managed device(s) with missing or invalid data",
                self.skipped_count,
            )
        return results
