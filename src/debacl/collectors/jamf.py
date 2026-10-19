"""
Jamf Pro collector — fetches managed Mac/iOS device IPs via Jamf Pro API.

@decision DEC-COLLECT-001
@title Strategy pattern — Jamf adapter isolated from core logic
@status accepted
@rationale Jamf Pro uses OAuth2 client credentials for its modern API. Pagination
           is cursor-based (totalCount / pageSize). This adapter encapsulates both,
           presenting collect() to the rest of the system. mock_mode delegates to
           MockDataGenerator so no credentials are needed for tests.
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


class JamfConfig(CollectorConfig):
    """Configuration for the Jamf Pro collector."""

    base_url: str = "https://yourinstance.jamfcloud.com"
    client_id: str = ""
    client_secret: str = ""


class JamfCollector(BaseCollector[EndpointTelemetry]):
    """Collects managed device telemetry from Jamf Pro.

    In mock_mode returns synthetic data via MockDataGenerator.
    In live mode:
      1. Obtains an OAuth2 Bearer token via POST /api/oauth/token.
      2. Pages through GET /api/v1/computers-inventory, using page/size params.
      3. Normalises each inventory record into an EndpointTelemetry model.

    Args:
        config: JamfConfig with base_url and client credentials.
    """

    def __init__(self, config: JamfConfig) -> None:
        super().__init__(config)
        self.config: JamfConfig = config
        self.skipped_count = 0

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_token(self, client: httpx.Client) -> str:
        """Exchange client credentials for a Jamf Pro Bearer token."""
        resp = client.post(
            f"{self.config.base_url}/api/oauth/token",
            data={
                "grant_type": "client_credentials",
                "client_id": self.config.client_id,
                "client_secret": self.config.client_secret,
            },
        )
        if resp.status_code != 200:
            raise CollectorError(f"Jamf OAuth token request failed: {resp.status_code} {resp.text}")
        return resp.json()["access_token"]

    def _fetch_inventory(self, client: httpx.Client, token: str) -> list[dict]:
        """Page through computers-inventory until all records are retrieved."""
        computers: list[dict] = []
        page = 0
        page_size = 100
        headers = {"Authorization": f"Bearer {token}"}
        expected_total: int | None = None

        while True:
            resp = client.get(
                f"{self.config.base_url}/api/v1/computers-inventory",
                headers=headers,
                params={
                    "section": "GENERAL,HARDWARE,OPERATING_SYSTEM",
                    "page": page,
                    "page-size": page_size,
                },
            )
            if resp.status_code != 200:
                raise CollectorError(
                    f"Jamf inventory request failed: {resp.status_code} {resp.text}"
                )
            try:
                body = resp.json()
            except ValueError:
                raise CollectorError("Jamf inventory returned invalid JSON") from None
            if not isinstance(body, dict) or not isinstance(body.get("results"), list):
                raise CollectorError("Jamf inventory returned invalid results")
            results = body["results"]
            computers.extend(results)
            total_count = body.get("totalCount")
            if type(total_count) is not int or total_count < 0:
                raise CollectorError("Jamf inventory returned invalid totalCount")
            if expected_total is None:
                expected_total = total_count
            elif total_count != expected_total:
                raise CollectorError("Jamf inventory returned inconsistent totalCount")
            page += 1
            if len(computers) > total_count or (not results and len(computers) < total_count):
                raise CollectorError("Jamf inventory returned incomplete pagination")
            if len(computers) == total_count:
                break

        return computers

    @staticmethod
    def _normalize(raw: dict) -> EndpointTelemetry | None:
        """Convert a raw Jamf inventory record to EndpointTelemetry."""
        if not isinstance(raw, dict):
            raise CollectorError("Jamf normalization error: invalid inventory record")
        device_id = raw.get("id")
        if (
            isinstance(device_id, bool)
            or not isinstance(device_id, (str, int))
            or not str(device_id).strip()
        ):
            return None
        general = raw.get("general", {})
        if general is None:
            general = {}
        elif not isinstance(general, dict):
            raise CollectorError("Jamf normalization error: invalid inventory record")
        last_ip = general.get("lastIpAddress")
        if last_ip is None or (isinstance(last_ip, str) and not last_ip.strip()):
            last_ip = general.get("lastReportedIp")
        if last_ip is None or (isinstance(last_ip, str) and not last_ip.strip()):
            return None

        if not isinstance(last_ip, str):
            raise CollectorError("Jamf normalization error: invalid IP address")

        try:
            parsed_ip = ip_address(last_ip.strip())
        except ValueError:
            raise CollectorError("Jamf normalization error: invalid IP address") from None

        try:
            return EndpointTelemetry(
                device_id=str(device_id).strip(),
                hostname=general.get("name", ""),
                public_ip=parsed_ip,
                source="jamf",
                timestamp=general.get("lastContactTime", general.get("reportDate", "")),
                health_status=raw.get("operatingSystem", {}).get("version"),
                raw_data=raw,
            )
        except Exception:
            raise CollectorError("Jamf normalization error: invalid inventory record") from None

    # ------------------------------------------------------------------
    # BaseCollector interface
    # ------------------------------------------------------------------

    def collect(self) -> list[EndpointTelemetry]:
        """Return endpoint telemetry from Jamf Pro.

        Uses MockDataGenerator when config.mock_mode is True.
        """
        self.skipped_count = 0
        if self.config.mock_mode:
            return MockDataGenerator().generate_endpoint_telemetry("jamf")

        try:
            with httpx.Client(timeout=30) as client:
                token = self._get_token(client)
                raw_computers = self._fetch_inventory(client, token)
        except httpx.HTTPError as exc:
            raise CollectorError(f"Jamf HTTP error: {exc}") from exc

        results: list[EndpointTelemetry] = []
        for raw in raw_computers:
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
                "Jamf skipped %d invalid or incomplete computer record(s)",
                self.skipped_count,
            )
        return results
