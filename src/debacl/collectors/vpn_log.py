"""
VPN log collector — parses CSV or syslog VPN connection logs into ConnectionEvents.

@decision DEC-COLLECT-001
@title Strategy pattern — file-based VPN log adapter (different from API collectors)
@status accepted
@rationale VPN logs arrive as files (CSV exports or syslog streams), not HTTP APIs.
           This adapter handles both formats behind the same collect() interface.
           CSV parsing is column-based; syslog parsing uses regex for common
           Cisco AnyConnect / GlobalProtect patterns. mock_mode generates a
           synthetic CSV via MockDataGenerator then parses it, exercising the
           full parse path without requiring a real log file.
"""

from __future__ import annotations

import csv
import re
import tempfile
from datetime import UTC, datetime
from typing import Literal

from debacl.collectors.base import BaseCollector, CollectorConfig
from debacl.collectors.exceptions import CollectorError
from debacl.collectors.mock_data import MockDataGenerator
from debacl.models.events import ConnectionEvent


class VpnLogConfig(CollectorConfig):
    """Configuration for the VPN log file collector."""

    log_path: str = ""
    log_format: Literal["csv", "syslog"] = "csv"


# ---------------------------------------------------------------------------
# Syslog regex patterns
# ---------------------------------------------------------------------------

# Cisco AnyConnect: "... Group <group> User <user> IP <ip> ..."
_ANYCONNECT_RE = re.compile(
    r"User\s+<(?P<username>[^>]+)>.*?IP\s+<(?P<ip>[\d:.a-fA-F]+)>",
    re.IGNORECASE,
)

# GlobalProtect: "... user: <user> ... client-ip: <ip> ..."
_GLOBALPROTECT_RE = re.compile(
    r"user:\s*(?P<username>\S+).*?client-ip:\s*(?P<ip>[\d:.a-fA-F]+)",
    re.IGNORECASE,
)

# Generic syslog VPN: "... src=<ip> ... user=<user> ..."
_GENERIC_VPN_RE = re.compile(
    r"src=(?P<ip>[\d:.a-fA-F]+).*?user=(?P<username>\S+)",
    re.IGNORECASE,
)

_SYSLOG_PATTERNS = [_ANYCONNECT_RE, _GLOBALPROTECT_RE, _GENERIC_VPN_RE]

# Status keywords → event_type mapping
_STATUS_MAP = {
    "connected": "vpn_connect",
    "connect": "vpn_connect",
    "success": "auth_success",
    "authenticated": "auth_success",
    "failed": "auth_failure",
    "failure": "auth_failure",
    "denied": "auth_failure",
    "rejected": "auth_failure",
}


def _parse_timestamp(ts_str: str) -> datetime:
    """Best-effort timestamp parser — falls back to now() on failure."""
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S",
        "%b %d %H:%M:%S",
    ):
        try:
            dt = datetime.strptime(ts_str.strip(), fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
            return dt
        except ValueError:
            continue
    return datetime.now(tz=UTC)


def _status_to_event_type(status: str) -> Literal["vpn_connect", "auth_success", "auth_failure"]:
    return _STATUS_MAP.get(status.lower().strip(), "auth_failure")  # type: ignore[return-value]


class VpnLogCollector(BaseCollector[ConnectionEvent]):
    """Parses VPN connection logs (CSV or syslog) into ConnectionEvent models.

    In mock_mode generates a synthetic CSV via MockDataGenerator then parses it.
    In live mode:
      - CSV: expects columns timestamp, username, source_ip, destination, status.
      - Syslog: applies regex patterns for Cisco AnyConnect and GlobalProtect;
        falls back to a generic src=/user= pattern.

    Invalid or incomplete rows are skipped with no exception raised (fail-open
    for log parsing — partial data is better than no data).

    Args:
        config: VpnLogConfig with log_path and log_format.
    """

    def __init__(self, config: VpnLogConfig) -> None:
        super().__init__(config)
        self.config: VpnLogConfig = config

    # ------------------------------------------------------------------
    # CSV parsing
    # ------------------------------------------------------------------

    def _parse_csv(self, path: str) -> list[ConnectionEvent]:
        """Parse a CSV VPN log file into ConnectionEvents."""
        events: list[ConnectionEvent] = []
        try:
            with open(path, newline="", encoding="utf-8") as fh:
                reader = csv.DictReader(fh)
                for row in reader:
                    event = self._csv_row_to_event(row)
                    if event is not None:
                        events.append(event)
        except OSError as exc:
            raise CollectorError(f"VPN log CSV read error: {exc}") from exc
        return events

    @staticmethod
    def _csv_row_to_event(row: dict) -> ConnectionEvent | None:
        """Convert a single CSV row to a ConnectionEvent, or None if unusable."""
        ip = (row.get("source_ip") or "").strip()
        username = (row.get("username") or "").strip()
        ts_str = (row.get("timestamp") or "").strip()
        destination = (row.get("destination") or "corp-vpn").strip()
        status = (row.get("status") or "").strip()

        if not ip or not username or not ts_str:
            return None

        event_type = _status_to_event_type(status)
        try:
            return ConnectionEvent(
                source_ip=ip,
                username=username,
                destination=destination,
                event_type=event_type,
                timestamp=_parse_timestamp(ts_str),
                source="vpn_log",
            )
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Syslog parsing
    # ------------------------------------------------------------------

    def _parse_syslog(self, path: str) -> list[ConnectionEvent]:
        """Parse a syslog-format VPN log file into ConnectionEvents."""
        events: list[ConnectionEvent] = []
        try:
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    event = self._syslog_line_to_event(line)
                    if event is not None:
                        events.append(event)
        except OSError as exc:
            raise CollectorError(f"VPN log syslog read error: {exc}") from exc
        return events

    @staticmethod
    def _syslog_line_to_event(line: str) -> ConnectionEvent | None:
        """Apply regex patterns to a syslog line and return a ConnectionEvent."""
        for pattern in _SYSLOG_PATTERNS:
            m = pattern.search(line)
            if m:
                ip = m.group("ip").strip()
                username = m.group("username").strip()
                if not ip or not username:
                    continue
                # Determine event type from keyword presence in the line
                line_lower = line.lower()
                event_type: Literal["vpn_connect", "auth_success", "auth_failure"] = "vpn_connect"
                if any(k in line_lower for k in ("fail", "denied", "reject", "error")):
                    event_type = "auth_failure"
                elif any(k in line_lower for k in ("auth", "login", "success")):
                    event_type = "auth_success"

                try:
                    return ConnectionEvent(
                        source_ip=ip,
                        username=username,
                        destination="vpn",
                        event_type=event_type,
                        timestamp=datetime.now(tz=UTC),
                        source="vpn_log",
                    )
                except Exception:
                    continue
        return None

    # ------------------------------------------------------------------
    # BaseCollector interface
    # ------------------------------------------------------------------

    def collect(self) -> list[ConnectionEvent]:
        """Return connection events parsed from the VPN log file.

        In mock_mode generates a synthetic CSV then parses it.
        """
        if self.config.mock_mode:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".csv", delete=False, encoding="utf-8"
            ) as tmp:
                tmp_path = tmp.name
            MockDataGenerator().generate_vpn_log_file(tmp_path)
            return self._parse_csv(tmp_path)

        if not self.config.log_path:
            raise CollectorError("VpnLogConfig.log_path is required in live mode")

        if self.config.log_format == "csv":
            return self._parse_csv(self.config.log_path)
        if self.config.log_format == "syslog":
            return self._parse_syslog(self.config.log_path)

        raise CollectorError(f"Unknown log_format: {self.config.log_format!r}")
