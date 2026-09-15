from pathlib import Path

import pytest
from temporalio.client import TLSConfig

from falcoria_worker.config import TemporalTLSSettings
from falcoria_worker.temporal.client import _build_tls_config


def test_tls_disabled_returns_false() -> None:
    settings = TemporalTLSSettings(enabled=False)
    assert _build_tls_config("localhost:7233", settings) is False


def test_tls_enabled_without_certs_returns_true() -> None:
    settings = TemporalTLSSettings(enabled=True)
    assert _build_tls_config("localhost:7233", settings) is True


def test_builds_tls_config_with_mtls_and_ca(tmp_path: Path) -> None:
    cert_file = tmp_path / "client.crt"
    cert_file.write_bytes(b"CERT-DATA")
    key_file = tmp_path / "client.key"
    key_file.write_bytes(b"KEY-DATA")
    ca_file = tmp_path / "ca.crt"
    ca_file.write_bytes(b"CA-DATA")

    settings = TemporalTLSSettings(
        client_cert_path=cert_file,
        client_key_path=key_file,
        server_root_ca_cert_path=ca_file,
    )
    assert settings.enabled is True

    result = _build_tls_config("temporal.example.com:443", settings)
    assert isinstance(result, TLSConfig)
    assert result.client_cert == b"CERT-DATA"
    assert result.client_private_key == b"KEY-DATA"
    assert result.server_root_ca_cert == b"CA-DATA"
    assert result.domain == "temporal.example.com"


def test_domain_override_respected(tmp_path: Path) -> None:
    cert_file = tmp_path / "client.crt"
    cert_file.write_bytes(b"CERT-DATA")
    key_file = tmp_path / "client.key"
    key_file.write_bytes(b"KEY-DATA")

    settings = TemporalTLSSettings(
        client_cert_path=cert_file,
        client_key_path=key_file,
        domain="custom.domain.internal",
    )

    result = _build_tls_config("165.22.192.210:7233", settings)
    assert isinstance(result, TLSConfig)
    assert result.domain == "custom.domain.internal"


def test_raises_if_cert_file_missing(tmp_path: Path) -> None:
    missing_cert = tmp_path / "missing.crt"
    key_file = tmp_path / "client.key"
    key_file.write_bytes(b"KEY-DATA")

    settings = TemporalTLSSettings(
        client_cert_path=missing_cert,
        client_key_path=key_file,
    )

    with pytest.raises(FileNotFoundError, match="Temporal client cert file not found"):
        _build_tls_config("localhost:7233", settings)


def test_raises_if_key_file_missing(tmp_path: Path) -> None:
    cert_file = tmp_path / "client.crt"
    cert_file.write_bytes(b"CERT-DATA")
    missing_key = tmp_path / "missing.key"

    settings = TemporalTLSSettings(
        client_cert_path=cert_file,
        client_key_path=missing_key,
    )

    with pytest.raises(FileNotFoundError, match="Temporal client key file not found"):
        _build_tls_config("localhost:7233", settings)


def test_raises_if_ca_file_missing(tmp_path: Path) -> None:
    missing_ca = tmp_path / "missing-ca.crt"
    settings = TemporalTLSSettings(
        enabled=True,
        server_root_ca_cert_path=missing_ca,
    )

    with pytest.raises(FileNotFoundError, match="Temporal root CA cert file not found"):
        _build_tls_config("localhost:7233", settings)


def test_settings_validation_enforces_both_cert_and_key() -> None:
    with pytest.raises(ValueError, match="Both client_cert_path and client_key_path"):
        TemporalTLSSettings(client_cert_path=Path("/some/cert.crt"))

    with pytest.raises(ValueError, match="Both client_cert_path and client_key_path"):
        TemporalTLSSettings(client_key_path=Path("/some/key.key"))
