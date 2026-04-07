"""
Collector-level exceptions.

@decision DEC-COLLECT-001
@title Structured error hierarchy — distinguishes auth, rate-limit, and data errors
@status accepted
@rationale A dedicated CollectorError (not a generic RuntimeError) lets callers
           distinguish upstream API failures from internal logic bugs. Three
           specialised subclasses cover the three most common upstream failure
           modes: invalid/expired credentials (AuthenticationError), upstream
           throttling (RateLimitError with optional retry-after), and malformed
           or unexpected API payloads (DataError). This hierarchy lets callers
           implement targeted retry/alert logic without catching bare exceptions.
"""


class CollectorError(Exception):
    """Base exception for all collector failures."""


class AuthenticationError(CollectorError):
    """Raised when API credentials are invalid or expired."""


class RateLimitError(CollectorError):
    """Raised when the upstream API returns 429.

    Attributes:
        retry_after: Optional number of seconds to wait before retrying, as
                     reported by the upstream ``Retry-After`` header.  None
                     when the header was absent or could not be parsed.
    """

    def __init__(self, message: str, retry_after: int | None = None) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class DataError(CollectorError):
    """Raised when the API returns unexpected or malformed data."""
