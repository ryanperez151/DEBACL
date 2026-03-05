"""
Tests for the abstract BaseCollector interface.

@decision DEC-COLLECT-001
@title Strategy pattern — each source is a pluggable adapter
@status accepted
@rationale Verifies that the ABC contract is enforced: direct instantiation fails,
           incomplete subclasses fail, and a properly implemented subclass works.
           This ensures new adapter authors cannot accidentally skip collect().
"""

import pytest

from debacl.collectors.base import BaseCollector, CollectorConfig

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_config(**overrides) -> CollectorConfig:
    defaults = dict(source="test_source", enabled=True, mock_mode=False)
    defaults.update(overrides)
    return CollectorConfig(**defaults)


# ---------------------------------------------------------------------------
# CollectorConfig tests
# ---------------------------------------------------------------------------


class TestCollectorConfig:
    def test_defaults(self):
        cfg = CollectorConfig(source="crowdstrike")
        assert cfg.enabled is True
        assert cfg.mock_mode is False

    def test_mock_mode_flag(self):
        cfg = CollectorConfig(source="jamf", mock_mode=True)
        assert cfg.mock_mode is True

    def test_disabled_flag(self):
        cfg = CollectorConfig(source="intune", enabled=False)
        assert cfg.enabled is False


# ---------------------------------------------------------------------------
# BaseCollector ABC enforcement
# ---------------------------------------------------------------------------


class TestBaseCollectorABC:
    def test_cannot_instantiate_directly(self):
        """BaseCollector is abstract and must not be instantiatable directly."""
        with pytest.raises(TypeError):
            BaseCollector(make_config())  # type: ignore[abstract]

    def test_incomplete_subclass_cannot_be_instantiated(self):
        """A subclass that does not implement collect() must also raise TypeError."""

        class IncompleteCollector(BaseCollector):
            pass  # missing collect()

        with pytest.raises(TypeError):
            IncompleteCollector(make_config())

    def test_concrete_subclass_works(self):
        """A properly implemented subclass can be instantiated and called."""

        class ConcreteCollector(BaseCollector[str]):
            def collect(self) -> list[str]:
                return ["item-1", "item-2"]

        cfg = make_config(source="test", mock_mode=True)
        collector = ConcreteCollector(cfg)
        assert collector.config.source == "test"
        result = collector.collect()
        assert result == ["item-1", "item-2"]

    def test_config_stored_on_instance(self):
        """Config passed to __init__ must be accessible via self.config."""

        class MinimalCollector(BaseCollector[int]):
            def collect(self) -> list[int]:
                return []

        cfg = make_config(source="intune", enabled=False)
        c = MinimalCollector(cfg)
        assert c.config.source == "intune"
        assert c.config.enabled is False

    def test_collect_returns_empty_list(self):
        """Returning an empty list is valid (no records collected)."""

        class EmptyCollector(BaseCollector[dict]):
            def collect(self) -> list[dict]:
                return []

        c = EmptyCollector(make_config())
        assert c.collect() == []
