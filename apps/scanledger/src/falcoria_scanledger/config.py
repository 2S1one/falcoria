"""Environment-loaded settings, split by concern; import the getter you need."""

from enum import Enum
from functools import lru_cache

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Env(str, Enum):
    """Deployment environment."""

    LOCAL = "local"
    DEV = "dev"
    PROD = "prod"


class BaseAppSettings(BaseSettings):
    """Shared env-file location and unknown-variable policy for every settings group."""

    model_config = SettingsConfigDict(
        env_prefix="SCANLEDGER_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


class AppSettings(BaseAppSettings):
    """Process-level settings: environment, debug flag, API prefix, seed tokens.

    Attributes:
        admin_token: bearer token for the seeded ``admin`` account. Env
            ``SCANLEDGER_ADMIN_TOKEN``. Re-applied to the DB on every startup.
        tasker_token: bearer token for the seeded ``tasker`` account. Env
            ``SCANLEDGER_TASKER_TOKEN``. Must differ from ``admin_token``.
        max_report_bytes: reject a scan-report upload larger than this. Env
            ``SCANLEDGER_MAX_REPORT_BYTES``. Default 25 MiB.
    """

    env: Env = Env.LOCAL
    debug: bool = False
    api_prefix: str = "/api"
    admin_token: SecretStr
    tasker_token: SecretStr
    max_report_bytes: int = 25 * 1024 * 1024


@lru_cache
def get_app_settings() -> AppSettings:
    """Returns the process settings, read from the environment on first call."""
    # pydantic-settings fills the required token fields from the environment;
    # pyright only sees the synthesised __init__ and flags them as missing.
    return AppSettings()  # pyright: ignore[reportCallIssue]


class DatabaseSettings(BaseAppSettings):
    """PostgreSQL connection settings for the scanledger database."""

    model_config = SettingsConfigDict(env_prefix="SCANLEDGER_DB_")

    host: str
    port: int = 5432
    user: str
    password: SecretStr
    name: str
    echo: bool = False


@lru_cache
def get_db_settings() -> DatabaseSettings:
    """Returns the cached database settings, read from the environment on first call."""
    # pydantic-settings fills the required fields from the environment; pyright only
    # sees the synthesised __init__ and thinks the arguments are missing.
    return DatabaseSettings()  # pyright: ignore[reportCallIssue]
