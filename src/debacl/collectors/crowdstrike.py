"""
CrowdStrike Falcon collector — fetches managed endpoint public IPs via Falcon API.

@decision DEC-COLLECT-001
@title Strategy pattern — CrowdStrike adapter isolated from core logic
@status accepted
@rationale The Falcon API uses a two-step query pattern: first retrieve device IDs
           via /devices/queries/devices/v1, then bulk-fetch details via
           /devices/entities/devices/v2. This adapter encapsulates that complexity
           behind the single collect() interface. In mock_mode it delegates to
           MockDataGenerator so tests never require real credentials.
"""

from __future__ import annotations

import httpx
from pydantic import BaseModel

from debacl.collectors.base import BaseCollector, CollectorConfig
from debacl.collectors.exceptions import CollectorError
from debacl.collectors.mock_data import MockDataGenerator
from debacl.models.telemetry import EndpointTelemetry


class CrowdStrikeConfig(CollectorConfig):
    """Configuration for the CrowdStrike Falcon collector."""

    client_id: str = ""
    client_secret: str = ""
    base_url: str = "https://api.crowdstrike.com"


class _TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int = 1800


class CrowdStrikeCollector(BaseCollector[EndpointTelemetry]):
    """Collects endpoint telemetry from CrowdStrike Falcon.

    In mock_mode returns synthetic data via MockDataGenerator.
    In live mode:
      1. Obtains an OAuth2 access token via POST /oauth2/token.
      2. Retrieves device IDs via GET /devices/queries/devices/v1.
      3. Fetches device details in bulk via POST /devices/entities/devices/v2.
      4. Normalises each device record into an EndpointTelemetry model.

    Args:
        config: CrowdStrikeConfig with credentials and base_url.
    """

    def __init__(self, config: CrowdStrikeConfig) -> None:
        super().__init__(config)
        self.config: CrowdStrikeConfig = config

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_token(self, client: httpx.Client) -> str:
        """Exchange client credentials for a Bearer token."""
        resp = client.post(
            f"{self.config.base_url}/oauth2/token",
            data={
                "client_id": self.config.client_id,
                "client_secret": self.config.client_secret,
                "grant_type": "client_credentials",
            },
        )
        if resp.status_code != 201:
            raise CollectorError(
                f"CrowdStrike OAuth2 token request failed: {resp.status_code} {resp.text}"
            )
        return _TokenResponse(**resp.json()).access_token

    def _get_device_ids(self, client: httpx.Client, token: str) -> list[str]:
        """Return all device IDs visible to the API token."""
        ids: list[str] = []
        offset = 0
        limit = 500
        while True:
            resp = client.get(
                f"{self.config.base_url}/devices/queries/devices/v1",
                headers={"Authorization": f"Bearer {token}"},
                params={"limit": limit, "offset": offset},
            )
            if resp.status_code != 200:
                raise CollectorError(
                    f"CrowdStrike device query failed: {resp.status_code} {resp.text}"
                )
            body = resp.json()
            page = body.get("resources", [])
            ids.extend(page)
            meta = body.get("meta", {}).get("pagination", {})
            total = meta.get("total", len(ids))
            offset += len(page)
            if offset >= total or not page:
                break
        return ids

    def _get_device_details(
        self, client: httpx.Client, token: str, device_ids: list[str]
    ) -> list[dict]:
        """Bulk-fetch device details for the given IDs (max 100 per request)."""
        details: list[dict] = []
        batch_size = 100
        for i in range(0, len(device_ids), batch_size):
            batch = device_ids[i : i + batch_size]
            resp = client.post(
                f"{self.config.base_url}/devices/entities/devices/v2",
                headers={"Authorization": f"Bearer {token}"},
                json={"ids": batch},
            )
            if resp.status_code != 200:
                raise CollectorError(
                    f"CrowdStrike device entities request failed: "
                    f"{resp.status_code} {resp.text}"
                )
            details.extend(resp.json().get("resources", []))
        return details

    @staticmethod
    def _normalize(raw: dict) -> EndpointTelemetry | None:
        """Convert a raw Falcon device record to EndpointTelemetry, or None if unusable."""
        external_ip = raw.get("external_ip")
        if not external_ip:
            return None
        try:
            return EndpointTelemetry(
                device_id=raw.get("device_id", ""),
                hostname=raw.get("hostname", ""),
                public_ip=external_ip,
                source="crowdstrike",
                timestamp=raw.get("last_seen", raw.get("modified_timestamp", "")),
                health_status=raw.get("status"),
                raw_data=raw,
            )
        except Exception as exc:
            raise CollectorError(f"CrowdStrike normalization error: {exc}") from exc

    # ------------------------------------------------------------------
    # BaseCollector interface
    # ------------------------------------------------------------------

    def collect(self) -> list[EndpointTelemetry]:
        """Return endpoint telemetry from CrowdStrike Falcon.

        Uses MockDataGenerator when config.mock_mode is True.
        """
        if self.config.mock_mode:
            return MockDataGenerator().generate_endpoint_telemetry("crowdstrike")

        try:
            with httpx.Client(timeout=30) as client:
                token = self._get_token(client)
                device_ids = self._get_device_ids(client, token)
                if not device_ids:
                    return []
                raw_devices = self._get_device_details(client, token, device_ids)
        except httpx.HTTPError as exc:
            raise CollectorError(f"CrowdStrike HTTP error: {exc}") from exc

        results: list[EndpointTelemetry] = []
        for raw in raw_devices:
            record = self._normalize(raw)
            if record is not None:
                results.append(record)
        return results
