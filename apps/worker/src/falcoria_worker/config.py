"""Environment-loaded settings, split by concern; import the getter you need."""

from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Self

from pydantic import SecretStr, model_validator
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
        scanledger_tls_verify: whether to verify scanledger's TLS certificate;
            set to false for local insecure testing. Env
            ``WORKER_SCANLEDGER_TLS_VERIFY``.
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
    scanledger_tls_verify: bool = True
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


@lru_cache
def get_temporal_settings() -> TemporalSettings:
    """Returns the cached Temporal settings, read from the environment on first call."""
    # pydantic-settings fills the required fields from the environment; pyright
    # only sees the synthesised __init__ and thinks the arguments are missing.
    return TemporalSettings()  # pyright: ignore[reportCallIssue]


class TemporalTLSSettings(BaseAppSettings):
    """Connection TLS and mTLS certificate settings for the Temporal client.

    Attributes:
        enabled: whether TLS is enabled for the Temporal connection. Env
            ``WORKER_TEMPORAL_TLS_ENABLED``.
        client_cert_path: path to the client certificate (PEM) for mTLS. Env
            ``WORKER_TEMPORAL_TLS_CLIENT_CERT_PATH``.
        client_key_path: path to the client private key (PEM) for mTLS. Env
            ``WORKER_TEMPORAL_TLS_CLIENT_KEY_PATH``.
        server_root_ca_cert_path: path to the root CA certificate (PEM) that signed
            the server certificate. Env
            ``WORKER_TEMPORAL_TLS_SERVER_ROOT_CA_CERT_PATH``.
        domain: optional server name override for TLS SNI validation. Env
            ``WORKER_TEMPORAL_TLS_DOMAIN``.
    """

    model_config = SettingsConfigDict(env_prefix="WORKER_TEMPORAL_TLS_")

    enabled: bool = False
    client_cert_path: Path | None = None
    client_key_path: SecretStr | None = None
    server_root_ca_cert_path: Path | None = None
    domain: str | None = None

    @model_validator(mode="after")
    def _validate_certs(self) -> Self:
        has_cert = self.client_cert_path is not None
        has_key = self.client_key_path is not None
        if has_cert != has_key:
            msg = "Both client_cert_path and client_key_path must be provided for mTLS."
            raise ValueError(msg)
        if (has_cert and has_key) or self.server_root_ca_cert_path is not None:
            self.enabled = True
        return self


@lru_cache
def get_temporal_tls_settings() -> TemporalTLSSettings:
    """Returns the cached Temporal TLS settings, read from the environment on first call."""
    # pydantic-settings fills the required fields from the environment; pyright
    # only sees the synthesised __init__ and thinks the arguments are missing.
    return TemporalTLSSettings()  # pyright: ignore[reportCallIssue]
