"""
Tests for W5-2: Collector exception hierarchy.

Verifies that all collector exceptions form the correct inheritance tree,
that RateLimitError carries retry_after, and that all subclasses can be
caught as CollectorError.
"""

import pytest

from debacl.collectors.exceptions import (
    AuthenticationError,
    CollectorError,
    DataError,
    RateLimitError,
)


class TestCollectorErrorHierarchy:
    """All custom exceptions derive from CollectorError."""

    def test_authentication_error_is_collector_error(self):
        assert issubclass(AuthenticationError, CollectorError)

    def test_rate_limit_error_is_collector_error(self):
        assert issubclass(RateLimitError, CollectorError)

    def test_data_error_is_collector_error(self):
        assert issubclass(DataError, CollectorError)

    def test_collector_error_is_exception(self):
        assert issubclass(CollectorError, Exception)


class TestRaiseCatchAsCollectorError:
    """Each subclass can be raised and caught as CollectorError."""

    def test_authentication_error_caught_as_collector_error(self):
        with pytest.raises(CollectorError):
            raise AuthenticationError("invalid credentials")

    def test_rate_limit_error_caught_as_collector_error(self):
        with pytest.raises(CollectorError):
            raise RateLimitError("too many requests")

    def test_data_error_caught_as_collector_error(self):
        with pytest.raises(CollectorError):
            raise DataError("unexpected response format")


class TestRateLimitError:
    """RateLimitError carries an optional retry_after attribute."""

    def test_stores_retry_after_when_provided(self):
        err = RateLimitError("rate limited", retry_after=60)
        assert err.retry_after == 60

    def test_retry_after_defaults_to_none(self):
        err = RateLimitError("rate limited")
        assert err.retry_after is None

    def test_message_is_preserved(self):
        err = RateLimitError("too many requests", retry_after=30)
        assert "too many requests" in str(err)

    def test_retry_after_zero_is_valid(self):
        err = RateLimitError("rate limited", retry_after=0)
        assert err.retry_after == 0


class TestAuthenticationError:
    """AuthenticationError behaves as a plain exception with a message."""

    def test_message_is_preserved(self):
        err = AuthenticationError("token expired")
        assert "token expired" in str(err)

    def test_is_raised_and_caught_specifically(self):
        with pytest.raises(AuthenticationError):
            raise AuthenticationError("bad token")


class TestDataError:
    """DataError behaves as a plain exception with a message."""

    def test_message_is_preserved(self):
        err = DataError("null response body")
        assert "null response body" in str(err)

    def test_is_raised_and_caught_specifically(self):
        with pytest.raises(DataError):
            raise DataError("parse failure")
