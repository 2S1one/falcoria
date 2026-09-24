"""Transactional outbox of IP state-change events."""

import uuid
from typing import Any

from sqlalchemy import BigInteger, Column, ForeignKey, Index, Uuid, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.types import UserDefinedType
from sqlmodel import Field, SQLModel


class Xid8(UserDefinedType[int]):
    """Postgres ``xid8``: a 64-bit transaction id that never wraps around."""

    cache_ok = True

    def get_col_spec(self, **kw: Any) -> str:
        """Returns the type name SQLAlchemy writes into CREATE TABLE."""
        return "xid8"


class OutboxEventDB(SQLModel, table=True):
    """One IP state change, written in the same transaction as the change itself.

    Append-only. ``payload`` is an ``IPChangedEvent`` dumped to JSON at write
    time and never updated. ``txid`` is filled by the database with the writing
    transaction's id; the feed orders by ``(txid, id)`` and hides rows whose
    transaction may still be running, because ``id`` follows insert order, not
    commit order. ``created_at`` is unix epoch seconds at write time.
    """

    __tablename__ = "outbox_events"  # pyright: ignore[reportAssignmentType]
    __table_args__ = (Index("ix_outbox_events_project_id_txid_id", "project_id", "txid", "id"),)

    id: int | None = Field(default=None, sa_column=Column(BigInteger, primary_key=True))
    event_id: uuid.UUID = Field(sa_column=Column(Uuid, nullable=False, unique=True))
    txid: int | None = Field(
        default=None,
        sa_column=Column(Xid8(), nullable=False, server_default=text("pg_current_xact_id()")),
    )
    project_id: uuid.UUID = Field(
        sa_column=Column(Uuid, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    )
    payload: dict[str, Any] = Field(sa_column=Column(JSONB, nullable=False))
    created_at: int
