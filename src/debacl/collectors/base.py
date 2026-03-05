"""
Abstract base collector — Strategy pattern for telemetry adapters.

@decision DEC-COLLECT-001
@title Strategy pattern — each source is a pluggable adapter
@status accepted
@rationale Using ABC + Generic[T] enforces that every collector implements collect()
           and returns a typed list. Adding a new telemetry source (e.g., SentinelOne)
           requires only a new subclass — zero changes to existing adapters or core logic.
           CollectorConfig carries source identity and feature flags (mock_mode) so
           adapters can switch between live API and fixture data without code changes.
"""

from abc import ABC, abstractmethod
from typing import Generic, TypeVar

from pydantic import BaseModel

T = TypeVar("T")


class CollectorConfig(BaseModel):
    """Configuration shared by all collector adapters."""

    source: str
    enabled: bool = True
    mock_mode: bool = False


class BaseCollector(ABC, Generic[T]):
    """Abstract base for all telemetry source adapters.

    Each concrete subclass targets a single data source (CrowdStrike, Intune, etc.)
    and is responsible for:
      1. Authenticating with the upstream API (or reading fixture data in mock_mode)
      2. Fetching raw records
      3. Normalising them into canonical Pydantic models

    The generic parameter T is the canonical model type returned by collect().
    """

    def __init__(self, config: CollectorConfig) -> None:
        self.config = config

    @abstractmethod
    def collect(self) -> list[T]:
        """Collect telemetry and return a list of canonical models."""
        ...
