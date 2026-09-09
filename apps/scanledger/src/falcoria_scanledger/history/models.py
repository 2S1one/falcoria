"""Append-only log of port changes detected during scan import."""

import uuid

from sqlalchemy import Column, ForeignKey, String, UniqueConstraint, Uuid
from sqlmodel import Field, SQLModel

from falcoria_contracts.enums import PortChangeType, PortProtocol


class IPPortHistoryDB(SQLModel, table=True):
    """One recorded change to one field of one (ip, port) pair in a project.

    Append-only. ``created_at`` is unix epoch seconds, set to the scan's end
    time, and is part of the uniqueness key, so re-importing the same scan
    writes nothing. ``old_value`` / ``new_value`` are normalised (state is only
    ever ``open`` / ``closed`` / null); ``observed_state`` and ``reason`` hold
    the raw scanner detail and are deliberately outside the key.
    """

    __tablename__ = "ip_port_history"  # pyright: ignore[reportAssignmentType]
    __table_args__ = (
        UniqueConstraint("project_id", "ip", "port", "protocol", "change_type", "created_at"),
    )

    id: int | None = Field(default=None, primary_key=True)

    project_id: uuid.UUID = Field(
        sa_column=Column(
            Uuid, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
        )
    )
    ip: str = Field(index=True)
    port: int
    protocol: PortProtocol = Field(sa_column=Column(String, nullable=False))
    change_type: PortChangeType = Field(sa_column=Column(String, nullable=False))

    old_value: str | None = None
    new_value: str | None = None
    observed_state: str | None = None
    reason: str | None = None

    created_at: int
