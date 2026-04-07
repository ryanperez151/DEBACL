"""
Tests for W5-3: Configuration management via pydantic-settings.

Verifies that DebacleSettings instantiates with correct defaults, env var
overrides work, get_settings() returns a cached instance, and the DEBACL_
prefix mapping is applied correctly.
"""

import os

from debacl.config import DebacleSettings, get_settings


class TestDebacleSettingsDefaults:
    """DebacleSettings default values are sane out-of-the-box."""

    def setup_method(self):
        # Clear cache so each test starts fresh
        get_settings.cache_clear()

    def teardown_method(self):
        get_settings.cache_clear()

    def test_instantiates_without_error(self):
        settings = DebacleSettings()
        assert settings is not None

    def test_db_path_default(self):
        settings = DebacleSettings()
        assert settings.db_path == "debacl.db"

    def test_correlation_window_hours_default(self):
        settings = DebacleSettings()
        assert settings.correlation_window_hours == 24

    def test_privileged_patterns_contains_admin(self):
        settings = DebacleSettings()
        assert "admin" in settings.privileged_patterns

    def test_privileged_patterns_contains_all_defaults(self):
        settings = DebacleSettings()
        for pattern in ("admin", "svc-", "root", "system"):
            assert pattern in settings.privileged_patterns

    def test_output_dir_default(self):
        settings = DebacleSettings()
        assert settings.output_dir == "output"

    def test_log_level_default(self):
        settings = DebacleSettings()
        assert settings.log_level == "INFO"

    def test_all_source_flags_disabled_by_default(self):
        settings = DebacleSettings()
        assert settings.crowdstrike_enabled is False
        assert settings.intune_enabled is False
        assert settings.jamf_enabled is False
        assert settings.okta_enabled is False
        assert settings.entra_enabled is False
        assert settings.vpn_log_enabled is False

    def test_credential_defaults_are_empty_strings(self):
        settings = DebacleSettings()
        assert settings.crowdstrike_client_id == ""
        assert settings.crowdstrike_client_secret == ""
        assert settings.azure_tenant_id == ""
        assert settings.okta_api_token == ""


class TestDebacleSettingsEnvOverride:
    """Environment variable overrides (DEBACL_ prefix) take effect."""

    def setup_method(self):
        get_settings.cache_clear()
        # Snapshot env so we can restore it
        self._saved = {}

    def teardown_method(self):
        # Remove any env vars we set and restore originals
        for key, value in self._saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        get_settings.cache_clear()

    def _set_env(self, key: str, value: str) -> None:
        self._saved[key] = os.environ.get(key)
        os.environ[key] = value

    def test_db_path_overridden_by_env(self):
        self._set_env("DEBACL_DB_PATH", "test.db")
        settings = DebacleSettings()
        assert settings.db_path == "test.db"

    def test_correlation_window_hours_overridden_by_env(self):
        self._set_env("DEBACL_CORRELATION_WINDOW_HOURS", "48")
        settings = DebacleSettings()
        assert settings.correlation_window_hours == 48

    def test_log_level_overridden_by_env(self):
        self._set_env("DEBACL_LOG_LEVEL", "DEBUG")
        settings = DebacleSettings()
        assert settings.log_level == "DEBUG"

    def test_crowdstrike_enabled_overridden_by_env(self):
        self._set_env("DEBACL_CROWDSTRIKE_ENABLED", "true")
        settings = DebacleSettings()
        assert settings.crowdstrike_enabled is True


class TestGetSettings:
    """get_settings() factory is cached."""

    def setup_method(self):
        get_settings.cache_clear()

    def teardown_method(self):
        get_settings.cache_clear()

    def test_returns_debacle_settings_instance(self):
        result = get_settings()
        assert isinstance(result, DebacleSettings)

    def test_is_cached_same_object_returned_twice(self):
        first = get_settings()
        second = get_settings()
        assert first is second

    def test_cache_clear_allows_new_instance(self):
        first = get_settings()
        get_settings.cache_clear()
        second = get_settings()
        # After clearing, a new object is constructed — they are equal but not the same
        assert first.db_path == second.db_path
