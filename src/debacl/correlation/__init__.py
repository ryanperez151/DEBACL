"""
Correlation engine package — public re-exports.

Import from here to avoid coupling callers to internal module layout::

    from debacl.correlation import CorrelationEngine, CorrelationConfig
"""

from .engine import CorrelationConfig, CorrelationEngine
from .scoring import SeverityScorer, is_privileged
from .windowing import TimeWindowFilter

__all__ = [
    "CorrelationConfig",
    "CorrelationEngine",
    "SeverityScorer",
    "TimeWindowFilter",
    "is_privileged",
]
