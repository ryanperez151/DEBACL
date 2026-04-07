"""
DEBACL configuration via pydantic-settings.

@decision DEC-PKG-001
@title Pydantic Settings for config — env vars + .env file, single source of truth
@status accepted
@rationale pydantic-settings layers environment-variable overrides on top of
           Pydantic v2 model validation, giving us: (a) type-safe config fields
           with defaults, (b) automatic DEBACL_-prefixed env var mapping so any
           field can be overridden without code changes, (c) optional .env file
           support for local development, and (d) a cached get_settings() factory
           so the settings object is constructed at most once per process. All
           collector credentials are empty strings by default so the package
           imports cleanly with no environment set up.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict


class DebacleSettings(BaseSettings):
    """Runtime configuration for the DEBACL application.

    Every field can be overridden by a DEBACL_-prefixed environment variable,
    e.g. ``DEBACL_DB_PATH=test.db`` overrides ``db_path``.  A ``.env`` file
    in the working directory is loaded automatically when present.
    """

    model_config = SettingsConfigDict(
        env_prefix="DEBACL_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ------------------------------------------------------------------
    # Database
    # ------------------------------------------------------------------
    db_path: str = "debacl.db"

    # ------------------------------------------------------------------
    # Correlation
    # ------------------------------------------------------------------
    correlation_window_hours: int = 24
    privileged_patterns: list[str] = ["admin", "svc-", "root", "system"]

    # ------------------------------------------------------------------
    # Output
    # ------------------------------------------------------------------
    output_dir: str = "output"
    log_level: str = "INFO"

    # ------------------------------------------------------------------
    # Source enable flags
    # ------------------------------------------------------------------
    crowdstrike_enabled: bool = False
    intune_enabled: bool = False
    jamf_enabled: bool = False
    okta_enabled: bool = False
    entra_enabled: bool = False
    vpn_log_enabled: bool = False

    # ------------------------------------------------------------------
    # CrowdStrike
    # ------------------------------------------------------------------
    crowdstrike_client_id: str = ""
    crowdstrike_client_secret: str = ""

    # ------------------------------------------------------------------
    # Intune / Entra (shared Azure app registration)
    # ------------------------------------------------------------------
    azure_tenant_id: str = ""
    azure_client_id: str = ""
    azure_client_secret: str = ""

    # ------------------------------------------------------------------
    # Jamf
    # ------------------------------------------------------------------
    jamf_base_url: str = ""
    jamf_client_id: str = ""
    jamf_client_secret: str = ""

    # ------------------------------------------------------------------
    # Okta
    # ------------------------------------------------------------------
    okta_domain: str = ""
    okta_api_token: str = ""

    # ------------------------------------------------------------------
    # VPN log ingestion
    # ------------------------------------------------------------------
    vpn_log_path: str = ""
    vpn_log_format: str = "csv"
