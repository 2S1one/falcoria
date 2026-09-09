"""IP inventory, open ports, and hostnames observed during scans."""

import uuid
from typing import Any

from sqlalchemy import Column, ForeignKey, Integer, String, UniqueConstraint, Uuid
from sqlmodel import JSON, Field, SQLModel

from falcoria_contracts.enums import PortProtocol, PortState


class IPDB(SQLModel, table=True):
    """One IP address within a project, plus the OS/status the last scan reported.

    Uniqueness is ``(ip, project_id)`` — the same address in two projects is two
    rows with distinct ``id``. ``first_seen`` / ``last_seen`` are unix epoch
    seconds, taken from the scan's end time.
    """

    __tablename__ = "ips"  # pyright: ignore[reportAssignmentType]
    __table_args__ = (UniqueConstraint("ip", "project_id"),)

    id: int | None = Field(default=None, primary_key=True)
    ip: str = Field(index=True)
    status: str | None = None
    os: str | None = None
    first_seen: int
    last_seen: int

    project_id: uuid.UUID = Field(
        sa_column=Column(
            Uuid, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
        )
    )


class PortDB(SQLModel, table=True):
    """A single open port on an IP and what the scan reported about its service.

    Scope stores open ports only: a closed port is a deleted row plus a
    port-history entry. ``state`` is kept for record fidelity and for protocols
    where a port can rest in a non-open state. Uniqueness
    ``(number, protocol, ip_id)`` is scoped to the IP row, so the same port can
    exist on that address in another project.
    """

    __tablename__ = "ports"  # pyright: ignore[reportAssignmentType]
    __table_args__ = (UniqueConstraint("number", "protocol", "ip_id"),)

    id: int | None = Field(default=None, primary_key=True)
    number: int = Field(index=True)
    protocol: PortProtocol = Field(sa_column=Column(String, index=True, nullable=False))
    state: PortState = Field(default=PortState.OPEN, sa_column=Column(String, nullable=False))
    reason: str | None = None

    service: str | None = Field(default=None, index=True)
    product: str | None = Field(default=None, index=True)
    version: str | None = None
    extrainfo: str | None = None
    cpe: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    servicefp: str | None = None
    service_method: str | None = None
    service_confidence: int | None = None
    tunnel: str | None = None
    scripts: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))

    ip_id: int = Field(
        sa_column=Column(
            Integer, ForeignKey("ips.id", ondelete="CASCADE"), nullable=False, index=True
        )
    )


class ObservedHostnameDB(SQLModel, table=True):
    """A hostname a scan reported for some IP in this project.

    Scan output, not a managed target — recorded passively and deduped per
    project by ``(hostname, project_id)``. Linked to IPs through
    ``observed_hostname_ip_link``.
    """

    __tablename__ = "observed_hostnames"  # pyright: ignore[reportAssignmentType]
    __table_args__ = (UniqueConstraint("hostname", "project_id"),)

    id: int | None = Field(default=None, primary_key=True)
    hostname: str = Field(index=True)

    project_id: uuid.UUID = Field(
        sa_column=Column(
            Uuid, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
        )
    )


class ObservedHostnameIPLink(SQLModel, table=True):
    """Join row linking an observed hostname to an IP it was reported for."""

    __tablename__ = "observed_hostname_ip_link"  # pyright: ignore[reportAssignmentType]

    ip_id: int = Field(
        sa_column=Column(Integer, ForeignKey("ips.id", ondelete="CASCADE"), primary_key=True)
    )
    hostname_id: int = Field(
        sa_column=Column(
            Integer,
            ForeignKey("observed_hostnames.id", ondelete="CASCADE"),
            primary_key=True,
            index=True,
        )
    )
