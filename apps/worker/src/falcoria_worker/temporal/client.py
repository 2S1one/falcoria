"""Temporal client connection, using the shared pinned pydantic data converter."""

from pathlib import Path

from falcoria_temporal.converter import pydantic_data_converter
from temporalio.client import Client, TLSConfig

from falcoria_worker.config import (
    TemporalTLSSettings,
    get_temporal_settings,
    get_temporal_tls_settings,
)


def _build_tls_config(address: str, tls_settings: TemporalTLSSettings) -> bool | TLSConfig:
    """Builds a TLSConfig if TLS is configured, or returns a boolean."""
    if not tls_settings.enabled:
        return False

    ca_bytes: bytes | None = None
    if tls_settings.server_root_ca_cert_path:
        ca_path = tls_settings.server_root_ca_cert_path
        if not ca_path.is_file():
            msg = f"Temporal root CA cert file not found: {ca_path}"
            raise FileNotFoundError(msg)
        ca_bytes = ca_path.read_bytes()

    domain = tls_settings.domain or address.split(":")[0]

    if tls_settings.client_cert_path and tls_settings.client_key_path:
        cert_path = tls_settings.client_cert_path
        key_path = Path(tls_settings.client_key_path.get_secret_value())
        if not cert_path.is_file():
            msg = f"Temporal client cert file not found: {cert_path}"
            raise FileNotFoundError(msg)
        if not key_path.is_file():
            msg = f"Temporal client key file not found: {key_path}"
            raise FileNotFoundError(msg)
        return TLSConfig(
            client_cert=cert_path.read_bytes(),
            client_private_key=key_path.read_bytes(),
            server_root_ca_cert=ca_bytes,
            domain=domain,
        )

    if ca_bytes is not None or tls_settings.domain is not None:
        return TLSConfig(server_root_ca_cert=ca_bytes, domain=domain)

    return True


async def connect_temporal(identity: str) -> Client:
    """Connects to Temporal using the process's configured address/namespace/TLS."""
    settings = get_temporal_settings()
    tls_settings = get_temporal_tls_settings()
    tls = _build_tls_config(settings.address, tls_settings)
    return await Client.connect(
        settings.address,
        namespace=settings.namespace,
        data_converter=pydantic_data_converter,
        tls=tls,
        identity=identity,
    )
