"""
Collector-level exceptions.

@decision DEC-COLLECT-001
@title Strategy pattern — collector exceptions isolated per adapter domain
@status accepted
@rationale A dedicated CollectorError (not a generic RuntimeError) lets callers
           distinguish upstream API failures from internal logic bugs. Subclasses
           can be added per-source (CrowdStrikeError, etc.) if finer-grained
           handling is needed in future phases.
"""


class CollectorError(Exception):
    """Raised when a collector fails to fetch or normalise data from its source."""
