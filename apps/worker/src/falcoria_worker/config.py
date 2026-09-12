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
        env_prefix="WORKER_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


class AppSettings(BaseAppSettings):
    """Process-level settings: environment, debug flag, scanledger client, nmap execution.

    Attributes:
        scanledger_base_url: base URL of scanledger's API. Env ``WORKER_SCANLEDGER_BASE_URL``.
        scanledger_token: bearer token for worker's own service account on scanledger —
            must match scanledger's seeded `worker` account token. Env
            ``WORKER_SCANLEDGER_TOKEN``.
        nmap_path: path to the nmap executable. Env ``WORKER_NMAP_PATH``.
        command_grace_period_seconds: how long to wait after SIGTERM before escalating
            a scan subprocess to SIGKILL. Env ``WORKER_COMMAND_GRACE_PERIOD_SECONDS``.
        heartbeat_interval_seconds: interval between activity heartbeats while a scan
            subprocess is running. Env ``WORKER_HEARTBEAT_INTERVAL_SECONDS``.
        max_concurrent_activities: Temporal worker's max concurrently-executing
            activities. Env ``WORKER_MAX_CONCURRENT_ACTIVITIES``.
        window_size: max concurrent child ScanWorkflows inside ScanBatchWorkflow.
            Env ``WORKER_WINDOW_SIZE``.
        log_level: root logger level (``DEBUG``/``INFO``/``WARNING``/...). Env
            ``WORKER_LOG_LEVEL``.
    """

    env: Env = Env.LOCAL
    debug: bool = False
    scanledger_base_url: str
    scanledger_token: SecretStr
    nmap_path: str = "nmap"
    command_grace_period_seconds: float = 5.0
    heartbeat_interval_seconds: float = 10.0
    max_concurrent_activities: int = 1
    window_size: int = 20
    log_level: str = "INFO"


@lru_cache
def get_app_settings() -> AppSettings:
    """Returns the process settings, read from the environment on first call."""
    # pydantic-settings fills the required fields from the environment; pyright
    # only sees the synthesised __init__ and flags them as missing.
    return AppSettings()  # pyright: ignore[reportCallIssue]


class TemporalSettings(BaseAppSettings):
    """Connection settings for the Temporal client."""

    model_config = SettingsConfigDict(env_prefix="WORKER_TEMPORAL_")

    address: str
    namespace: str = "default"
    tls: bool = False


@lru_cache
def get_temporal_settings() -> TemporalSettings:
    """Returns the cached Temporal settings, read from the environment on first call."""
    # pydantic-settings fills the required fields from the environment; pyright
    # only sees the synthesised __init__ and thinks the arguments are missing.
    return TemporalSettings()  # pyright: ignore[reportCallIssue]
