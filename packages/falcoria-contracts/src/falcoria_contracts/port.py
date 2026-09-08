"""The port wire model shared between the scanner, scanledger, and clients."""

from typing import Any

from pydantic import BaseModel, Field

from falcoria_contracts.enums import PortProtocol, PortState, ServiceMethod


class Port(BaseModel):
    """A single scanned port and everything nmap reported about it."""

    number: int = Field(ge=0, le=65535)
    protocol: PortProtocol = PortProtocol.TCP
    state: PortState = PortState.OPEN
    reason: str | None = Field(
        default=None, description="Why nmap assigned the state, e.g. 'syn-ack'."
    )

    service: str | None = Field(default=None, description="Service name, e.g. 'http', 'ssh'.")
    product: str | None = Field(
        default=None, description="Service product, e.g. 'nginx', 'OpenSSH'."
    )
    version: str | None = Field(default=None, description="Service version, e.g. '1.18.0'.")
    extrainfo: str | None = None
    cpe: list[str] = Field(default_factory=list, description="Detected CPEs.")
    servicefp: str | None = Field(
        default=None, description="Service fingerprint when nmap could not name the service."
    )
    service_method: ServiceMethod | None = None
    service_confidence: int | None = Field(
        default=None, ge=0, le=10, description="nmap's service-detection confidence (0-10)."
    )
    tunnel: str | None = Field(default=None, description="Tunnel wrapping the service, e.g. 'ssl'.")
    scripts: dict[str, Any] = Field(
        default_factory=dict, description="NSE script output keyed by script id."
    )
