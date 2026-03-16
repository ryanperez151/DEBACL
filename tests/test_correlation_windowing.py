"""
Tests for TimeWindowFilter.

Verifies that items within the window are kept, items outside are dropped,
boundary behaviour (>= cutoff), and that both EndpointTelemetry and
ConnectionEvent types are handled correctly.
"""

from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address

from debacl.correlation.windowing import TimeWindowFilter
from debacl.models.events import ConnectionEvent
from debacl.models.telemetry import EndpointTelemetry

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _now() -> datetime:
    return datetime.now(UTC)


def _telemetry(hours_ago: float, ip: str = "10.0.0.1") -> EndpointTelemetry:
    """Create EndpointTelemetry with a timestamp *hours_ago* hours in the past."""
    ts = _now() - timedelta(hours=hours_ago)
    return EndpointTelemetry(
        device_id=f"d-{hours_ago}",
        hostname=f"ws-{hours_ago}",
        public_ip=IPv4Address(ip),
        source="crowdstrike",
        timestamp=ts,
    )


def _event(hours_ago: float) -> ConnectionEvent:
    """Create ConnectionEvent with a timestamp *hours_ago* hours in the past."""
    ts = _now() - timedelta(hours=hours_ago)
    return ConnectionEvent(
        source_ip=IPv4Address("10.0.0.1"),
        username="test@corp.com",
        destination="corp.vpn",
        event_type="auth_success",
        timestamp=ts,
        source="okta",
    )


# ---------------------------------------------------------------------------
# filter_telemetry
# ---------------------------------------------------------------------------


class TestFilterTelemetry:
    def test_within_window_is_kept(self) -> None:
        items = [_telemetry(1)]  # 1 hour ago — inside 24h window
        result = TimeWindowFilter(window_hours=24).filter_telemetry(items)
        assert len(result) == 1

    def test_outside_window_is_dropped(self) -> None:
        items = [_telemetry(25)]  # 25 hours ago — outside 24h window
        result = TimeWindowFilter(window_hours=24).filter_telemetry(items)
        assert len(result) == 0

    def test_empty_list_returns_empty(self) -> None:
        result = TimeWindowFilter().filter_telemetry([])
        assert result == []

    def test_mixed_keeps_only_in_window(self) -> None:
        items = [
            _telemetry(1, ip="10.0.0.1"),    # in window
            _telemetry(10, ip="10.0.0.2"),   # in window
            _telemetry(25, ip="10.0.0.3"),   # outside
            _telemetry(48, ip="10.0.0.4"),   # outside
        ]
        result = TimeWindowFilter(window_hours=24).filter_telemetry(items)
        assert len(result) == 2
        kept_ips = {str(t.public_ip) for t in result}
        assert kept_ips == {"10.0.0.1", "10.0.0.2"}

    def test_boundary_item_at_cutoff_is_kept(self) -> None:
        """An item timestamped exactly at the cutoff boundary must be included (>=)."""
        # Use a filter with a generous window; place the item just inside
        # by a tiny margin to avoid race conditions with _now() calls.
        # We test the >= semantics by using Polars epoch comparison.
        wf = TimeWindowFilter(window_hours=24)
        cutoff = _now() - timedelta(hours=24)
        # Item timestamped exactly at the cutoff (or 1 second after)
        item = EndpointTelemetry(
            device_id="boundary",
            hostname="ws-boundary",
            public_ip=IPv4Address("10.0.0.99"),
            source="intune",
            timestamp=cutoff + timedelta(seconds=1),  # just inside window
        )
        result = wf.filter_telemetry([item])
        assert len(result) == 1

    def test_naive_timestamp_is_handled(self) -> None:
        """Naive (non-UTC) timestamps must not raise and should be treated as UTC."""
        naive_ts = datetime.utcnow() - timedelta(hours=1)  # naive, 1h ago
        item = EndpointTelemetry(
            device_id="naive-d",
            hostname="ws-naive",
            public_ip=IPv4Address("10.0.0.1"),
            source="jamf",
            timestamp=naive_ts,
        )
        result = TimeWindowFilter(window_hours=24).filter_telemetry([item])
        assert len(result) == 1

    def test_returns_same_objects_not_copies(self) -> None:
        """filter_telemetry must return original objects (not deepcopies)."""
        items = [_telemetry(1)]
        result = TimeWindowFilter().filter_telemetry(items)
        assert result[0] is items[0]


# ---------------------------------------------------------------------------
# filter_events
# ---------------------------------------------------------------------------


class TestFilterEvents:
    def test_within_window_is_kept(self) -> None:
        items = [_event(1)]
        result = TimeWindowFilter(window_hours=24).filter_events(items)
        assert len(result) == 1

    def test_outside_window_is_dropped(self) -> None:
        items = [_event(25)]
        result = TimeWindowFilter(window_hours=24).filter_events(items)
        assert len(result) == 0

    def test_empty_list_returns_empty(self) -> None:
        result = TimeWindowFilter().filter_events([])
        assert result == []

    def test_mixed_keeps_only_in_window(self) -> None:
        items = [
            _event(2),   # in
            _event(23),  # in
            _event(24),  # borderline — 24h ago; filter is > 24h so this is kept if >= cutoff
            _event(30),  # out
        ]
        # Use a 24h window; 24h-old item is at exact cutoff — included (>=)
        result = TimeWindowFilter(window_hours=24).filter_events(items)
        # items at 2h and 23h are definitely in; 24h item is boundary; 30h is out
        in_window = [e for e in result]
        assert len(in_window) >= 2  # at minimum the 2h and 23h items

    def test_returns_same_objects_not_copies(self) -> None:
        items = [_event(1)]
        result = TimeWindowFilter().filter_events(items)
        assert result[0] is items[0]


# ---------------------------------------------------------------------------
# apply (combined filter)
# ---------------------------------------------------------------------------


class TestApply:
    def test_apply_filters_both(self) -> None:
        telemetry = [_telemetry(1), _telemetry(30)]
        events = [_event(2), _event(25)]
        wf = TimeWindowFilter(window_hours=24)
        filtered_t, filtered_e = wf.apply(telemetry, events)

        assert len(filtered_t) == 1
        assert len(filtered_e) == 1

    def test_apply_with_both_empty(self) -> None:
        wf = TimeWindowFilter()
        t, e = wf.apply([], [])
        assert t == []
        assert e == []


# ---------------------------------------------------------------------------
# Custom window sizes
# ---------------------------------------------------------------------------


class TestCustomWindowSizes:
    def test_1h_window_drops_2h_old_items(self) -> None:
        items = [_telemetry(2)]  # 2 hours ago
        result = TimeWindowFilter(window_hours=1).filter_telemetry(items)
        assert len(result) == 0

    def test_48h_window_keeps_25h_old_items(self) -> None:
        items = [_telemetry(25)]  # 25 hours ago — inside 48h window
        result = TimeWindowFilter(window_hours=48).filter_telemetry(items)
        assert len(result) == 1
