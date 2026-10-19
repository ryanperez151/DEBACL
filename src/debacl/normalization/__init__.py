"""Normalize values shared by collection and downstream consumers."""

from datetime import UTC, datetime


def as_utc(timestamp: datetime) -> datetime:
    """Return a UTC-aware timestamp, treating naive input as UTC."""
    if timestamp.tzinfo is None:
        return timestamp.replace(tzinfo=UTC)
    return timestamp.astimezone(UTC)
