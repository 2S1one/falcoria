"""Parse and request DTOs for the IP import pipeline."""

from collections.abc import Iterable
from ipaddress import ip_address

from pydantic import BaseModel, Field, field_validator

from falcoria_contracts.enums import PortChangeType, PortProtocol
from falcoria_contracts.port import Port

_PORT_MIN, _PORT_MAX = 0, 65535


def merge_port_ranges(pairs: Iterable[tuple[int, int]]) -> list[tuple[int, int]]:
    """Return the port ranges sorted, bounds-checked, and coalesced.

    Overlapping or touching ranges are fused, so the result is the minimal
    non-overlapping cover. Each bound must be within 0-65535.
    """
    norm = sorted((min(a, b), max(a, b)) for a, b in pairs)
    for lo, hi in norm:
        if lo < _PORT_MIN or hi > _PORT_MAX:
            raise ValueError(f"port range out of bounds: ({lo}, {hi})")
    merged: list[tuple[int, int]] = []
    for lo, hi in norm:
        if merged and lo <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
        else:
            merged.append((lo, hi))
    return merged


class IPIn(BaseModel):
    """One host from a parsed report, or one entry of a structured import.

    ``ports`` holds only ports the report gave an explicit entry for.
    ``scanned_ports`` is the merged set of ranges the scan covered; empty means
    coverage is unknown, so a REPLACE may then close only ports the report names
    as not-open.
    """

    ip: str
    status: str | None = None
    os: str | None = None
    endtime: int
    hostnames: list[str] = Field(default_factory=list)
    ports: list[Port] = Field(default_factory=list)
    scanned_ports: list[tuple[int, int]] = Field(default_factory=list)

    @field_validator("ip")
    @classmethod
    def _normalise_ip(cls, v: str) -> str:
        return str(ip_address(v))

    @field_validator("scanned_ports")
    @classmethod
    def _normalise_ranges(cls, v: list[tuple[int, int]]) -> list[tuple[int, int]]:
        return merge_port_ranges(v)


class PortChange(BaseModel):
    """One recorded change on one port — becomes an ip_port_history row.

    ``observed_state`` and ``reason`` carry the raw scanner detail and are set
    only when the change is a close (``STATE`` / ``new_value == "closed"``).
    """

    number: int
    protocol: PortProtocol
    change_type: PortChangeType
    old_value: str | None = None
    new_value: str | None = None
    observed_state: str | None = None
    reason: str | None = None
