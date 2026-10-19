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

import logging
from ipaddress import ip_address

import httpx
from pydantic import BaseModel

from debacl.collectors.base import BaseCollector, CollectorConfig
from debacl.collectors.exceptions import CollectorError
from debacl.collectors.mock_data import MockDataGenerator
from debacl.models.telemetry import EndpointTelemetry

logger = logging.getLogger(__name__)


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
        self.skipped_count = 0

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
        expected_total: int | None = None
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
            try:
                body = resp.json()
            except ValueError:
                raise CollectorError("CrowdStrike device query returned invalid JSON") from None
            if not isinstance(body, dict) or not isinstance(body.get("resources"), list):
                raise CollectorError("CrowdStrike device query returned invalid resources")
            page = body["resources"]
            if any(not isinstance(device_id, str) or not device_id.strip() for device_id in page):
                raise CollectorError("CrowdStrike device query returned invalid resources")
            ids.extend(page)
            meta = body.get("meta", {})
            if not isinstance(meta, dict):
                raise CollectorError("CrowdStrike device query returned invalid pagination")
            meta = meta.get("pagination", {})
            if not isinstance(meta, dict):
                raise CollectorError("CrowdStrike device query returned invalid pagination")
            total = meta.get("total")
            if type(total) is not int or total < 0:
                raise CollectorError("CrowdStrike device query returned invalid pagination")
            if expected_total is None:
                expected_total = total
            elif total != expected_total:
                raise CollectorError("CrowdStrike device query returned inconsistent pagination")
            offset += len(page)
            if offset > total or (not page and offset < total):
                raise CollectorError("CrowdStrike device query returned incomplete pagination")
            if offset == total:
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
                    f"CrowdStrike device entities request failed: {resp.status_code} {resp.text}"
                )
            try:
                body = resp.json()
            except ValueError:
                raise CollectorError("CrowdStrike device entities returned invalid JSON") from None
            if not isinstance(body, dict) or not isinstance(body.get("resources"), list):
                raise CollectorError("CrowdStrike device entities returned invalid resources")
            resources = body["resources"]
            if len(resources) != len(batch):
                raise CollectorError("CrowdStrike device entities response is incomplete")
            returned_ids: set[str] = set()
            for device in resources:
                if not isinstance(device, dict):
                    continue
                device_id = device.get("device_id")
                if not isinstance(device_id, str) or not device_id.strip():
                    continue
                device_id = device_id.strip()
                if device_id not in batch or device_id in returned_ids:
                    raise CollectorError("CrowdStrike device entities response is incomplete")
                returned_ids.add(device_id)
            details.extend(resources)
        return details

    @staticmethod
    def _normalize(raw: dict) -> EndpointTelemetry | None:
        """Convert a raw Falcon device record to EndpointTelemetry, or None if unusable."""
        if not isinstance(raw, dict):
            raise CollectorError("CrowdStrike normalization error: invalid device record")
        device_id = raw.get("device_id")
        if not isinstance(device_id, str) or not device_id.strip():
            return None
        external_ip = raw.get("external_ip")
        if external_ip is None or (isinstance(external_ip, str) and not external_ip.strip()):
            return None

        if not isinstance(external_ip, str):
            raise CollectorError("CrowdStrike normalization error: invalid external_ip")

        try:
            parsed_ip = ip_address(external_ip.strip())
        except ValueError:
            raise CollectorError("CrowdStrike normalization error: invalid external_ip") from None

        try:
            return EndpointTelemetry(
                device_id=device_id.strip(),
                hostname=raw.get("hostname", ""),
                public_ip=parsed_ip,
                source="crowdstrike",
                timestamp=raw.get("last_seen", raw.get("modified_timestamp", "")),
                health_status=raw.get("status"),
                raw_data=raw,
            )
        except Exception:
            raise CollectorError("CrowdStrike normalization error: invalid device record") from None

    # ------------------------------------------------------------------
    # BaseCollector interface
    # ------------------------------------------------------------------

    def collect(self) -> list[EndpointTelemetry]:
        """Return endpoint telemetry from CrowdStrike Falcon.

        Uses MockDataGenerator when config.mock_mode is True.
        """
        self.skipped_count = 0
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
            try:
                record = self._normalize(raw)
            except CollectorError:
                self.skipped_count += 1
                continue
            if record is None:
                self.skipped_count += 1
            else:
                results.append(record)
        if self.skipped_count:
            logger.warning(
                "CrowdStrike skipped %d invalid or incomplete device record(s)",
                self.skipped_count,
            )
        return results
