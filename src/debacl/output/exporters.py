"""
Finding exporters — JSON, CSV, and SIEM JSON Lines output formats.

@decision DEC-MODEL-001
@title Pydantic serialization for JSON output — model_dump_json() ensures schema consistency
@status accepted
@rationale model_dump(mode="json") converts all Pydantic types (UUID, IPvXAddress, datetime)
           to JSON-safe Python types in one call, preventing manual serialization bugs.
           CSV flattens the nested Finding structure to a single row per finding, using
           the connection_event sub-fields as top-level columns for analyst readability.
           SIEM JSON Lines adds an @timestamp field (Elastic/Splunk convention) without
           mutating the canonical Finding model.
"""

import csv
import json
import os
from datetime import UTC, datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

from debacl.models.findings import Finding


class FindingExporter:
    """Export Finding objects to JSON, CSV, or SIEM JSON Lines format.

    Args:
        output_dir: Directory where exported files are written. Created on first
                    export if it does not already exist.
    """

    def __init__(self, output_dir: str = "output") -> None:
        self._output_dir = output_dir

    def _ensure_dir(self) -> None:
        """Create the output directory if it does not exist."""
        os.makedirs(self._output_dir, exist_ok=True)

    def _auto_filename(self, prefix: str, extension: str) -> str:
        """Generate a timestamped filename in the output directory."""
        ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        return os.path.join(self._output_dir, f"{prefix}_{ts}.{extension}")

    def export_json(
        self,
        findings: list[Finding],
        filename: str | None = None,
    ) -> str:
        """Write findings to a JSON array file.

        Args:
            findings: List of Finding objects to export.
            filename: Target file path. Auto-generated with timestamp if None.

        Returns:
            Absolute path of the written file.
        """
        self._ensure_dir()
        path = filename if filename is not None else self._auto_filename("findings", "json")
        rows = [f.model_dump(mode="json") for f in findings]
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(rows, fh, indent=2)
        return path

    def export_csv(
        self,
        findings: list[Finding],
        filename: str | None = None,
    ) -> str:
        """Write findings to a flat CSV file.

        Nested fields (connection_event, matched_telemetry) are flattened to
        top-level columns so the CSV is analyst-friendly without requiring JSON
        parsing.

        Columns: finding_id, finding_type, severity, source_ip, username,
                 destination, event_type, event_source, event_timestamp,
                 description, timestamp

        Args:
            findings: List of Finding objects to export.
            filename: Target file path. Auto-generated with timestamp if None.

        Returns:
            Absolute path of the written file.
        """
        self._ensure_dir()
        path = filename if filename is not None else self._auto_filename("findings", "csv")

        fieldnames = [
            "finding_id",
            "finding_type",
            "severity",
            "source_ip",
            "username",
            "destination",
            "event_type",
            "event_source",
            "event_timestamp",
            "description",
            "timestamp",
        ]

        with open(path, "w", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            for f in findings:
                writer.writerow(
                    {
                        "finding_id": str(f.finding_id),
                        "finding_type": f.finding_type,
                        "severity": f.severity,
                        "source_ip": str(f.source_ip),
                        "username": f.connection_event.username,
                        "destination": f.connection_event.destination,
                        "event_type": f.connection_event.event_type,
                        "event_source": f.connection_event.source,
                        "event_timestamp": f.connection_event.timestamp.isoformat(),
                        "description": f.description,
                        "timestamp": f.timestamp.isoformat(),
                    }
                )
        return path

    def export_siem_jsonl(
        self,
        findings: list[Finding],
        filename: str | None = None,
    ) -> str:
        """Write findings to a JSON Lines file for Splunk / Elastic ingestion.

        Each line is a self-contained JSON object (one per finding) with an
        additional ``@timestamp`` field in ISO 8601 format, following the Elastic
        Common Schema convention used by most SIEM platforms.

        Args:
            findings: List of Finding objects to export.
            filename: Target file path. Auto-generated with timestamp if None.

        Returns:
            Absolute path of the written file.
        """
        self._ensure_dir()
        path = filename if filename is not None else self._auto_filename("findings", "jsonl")
        with open(path, "w", encoding="utf-8") as fh:
            for f in findings:
                record = f.model_dump(mode="json")
                record["@timestamp"] = f.timestamp.isoformat()
                fh.write(json.dumps(record) + "\n")
        return path
