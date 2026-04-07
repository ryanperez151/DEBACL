"""
Configuration package — public API for DEBACL settings.

Import DebacleSettings for type annotations or get_settings() for the
cached singleton in application code.
"""

from functools import lru_cache

from .settings import DebacleSettings

__all__ = ["DebacleSettings", "get_settings"]


@lru_cache(maxsize=1)
def get_settings() -> DebacleSettings:
    """Return the cached application settings instance.

    The first call constructs a DebacleSettings object (reading env vars and
    .env file).  Subsequent calls return the same cached object, so settings
    are read at most once per process lifetime.

    To force re-reading in tests, call ``get_settings.cache_clear()`` before
    setting environment variables.
    """
    return DebacleSettings()
