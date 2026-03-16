"""
Time-window filtering for telemetry and connection events.

@decision DEC-DATA-001
@title Polars for time-window filtering — lazy evaluation, type-safe, efficient
@status accepted
@rationale Polars DataFrames provide type-safe datetime arithmetic with native
           timezone support. Converting the list → DataFrame → filter → list pattern
           keeps the windowing logic composable and easily testable, and positions
           the system to handle larger datasets as the PoC scales up.
"""

import sys
from datetime import UTC, datetime, timedelta

import polars as pl

from debacl.models.events import ConnectionEvent
from debacl.models.telemetry import EndpointTelemetry


def _ensure_utc(dt: datetime) -> datetime:
    """Return *dt* with UTC timezone; attach UTC if naive."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


class TimeWindowFilter:
    """Filters telemetry and events to a rolling time window.

    Args:
        window_hours: Only records within this many hours of now are kept.
                      Default is 24 hours.
    """

    def __init__(self, window_hours: int = 24) -> None:
        self.window_hours = window_hours

    def _cutoff(self) -> datetime:
        """Return the oldest timestamp (UTC) that should be kept."""
        return datetime.now(UTC) - timedelta(hours=self.window_hours)

    def filter_telemetry(
        self, telemetry: list[EndpointTelemetry]
    ) -> list[EndpointTelemetry]:
        """Return only telemetry records within the time window.

        Uses Polars for the filtering step; handles both timezone-aware and
        naive timestamps by normalising everything to UTC before comparison.
        """
        if not telemetry:
            return []

        cutoff = _ensure_utc(self._cutoff())

        # Build a Polars DataFrame with epoch-second timestamps for comparison
        timestamps_utc = [_ensure_utc(t.timestamp).timestamp() for t in telemetry]
        cutoff_epoch = cutoff.timestamp()

        df = pl.DataFrame(
            {"idx": list(range(len(telemetry))), "ts_epoch": timestamps_utc}
        )
        mask_df = df.filter(pl.col("ts_epoch") >= cutoff_epoch)
        kept_indices = set(mask_df["idx"].to_list())

        filtered = [t for i, t in enumerate(telemetry) if i in kept_indices]
        dropped = len(telemetry) - len(filtered)
        if dropped:
            print(
                f"[TimeWindowFilter] telemetry: dropped {dropped}/{len(telemetry)} "
                f"records outside {self.window_hours}h window",
                file=sys.stderr,
            )
        return filtered

    def filter_events(
        self, events: list[ConnectionEvent]
    ) -> list[ConnectionEvent]:
        """Return only connection events within the time window.

        Uses Polars for the filtering step; handles both timezone-aware and
        naive timestamps by normalising everything to UTC before comparison.
        """
        if not events:
            return []

        cutoff = _ensure_utc(self._cutoff())

        timestamps_utc = [_ensure_utc(e.timestamp).timestamp() for e in events]
        cutoff_epoch = cutoff.timestamp()

        df = pl.DataFrame(
            {"idx": list(range(len(events))), "ts_epoch": timestamps_utc}
        )
        mask_df = df.filter(pl.col("ts_epoch") >= cutoff_epoch)
        kept_indices = set(mask_df["idx"].to_list())

        filtered = [e for i, e in enumerate(events) if i in kept_indices]
        dropped = len(events) - len(filtered)
        if dropped:
            print(
                f"[TimeWindowFilter] events: dropped {dropped}/{len(events)} "
                f"records outside {self.window_hours}h window",
                file=sys.stderr,
            )
        return filtered

    def apply(
        self,
        telemetry: list[EndpointTelemetry],
        events: list[ConnectionEvent],
    ) -> tuple[list[EndpointTelemetry], list[ConnectionEvent]]:
        """Apply both filters and return a (telemetry, events) tuple."""
        return self.filter_telemetry(telemetry), self.filter_events(events)
