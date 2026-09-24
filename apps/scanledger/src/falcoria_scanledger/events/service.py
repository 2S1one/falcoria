"""Writes IP state-change events to the outbox and reads them back as a feed."""

import time
from uuid import UUID

from sqlalchemy import ColumnElement, cast, func, literal, tuple_
from sqlmodel import col, select
from sqlmodel.ext.asyncio.session import AsyncSession

from falcoria_scanledger.events.models import OutboxEventDB, Xid8
from falcoria_scanledger.events.schemas import EventPage, IPChangedEvent


def write_events(session: AsyncSession, events: list[IPChangedEvent]) -> None:
    """Stages one outbox row per event in the session's transaction.

    Does not commit: the rows commit or roll back together with the change they
    describe. ``txid`` is left to its database default.
    """
    now = int(time.time())
    session.add_all(
        OutboxEventDB(**e.model_dump(), payload=e.model_dump(mode="json"), created_at=now)
        for e in events
    )


async def read_events(session: AsyncSession, project_id: UUID, after: str, limit: int) -> EventPage:
    """Returns up to `limit` of the project's events after cursor `after`, oldest first.

    ``after`` is ``"<txid>.<id>"``; ``"0.0"`` starts from the beginning. Rows
    written by a transaction that may still be running are held back until it
    ends, so a slow import's events are delayed, never skipped.
    """
    rows = (
        await session.exec(
            select(OutboxEventDB)
            .where(col(OutboxEventDB.project_id) == project_id, _after(after), _finished())
            .order_by(col(OutboxEventDB.txid), col(OutboxEventDB.id))
            .limit(limit)
        )
    ).all()
    next_cursor = f"{rows[-1].txid}.{rows[-1].id}" if rows else after
    return EventPage(
        items=[IPChangedEvent.model_validate(r.payload) for r in rows], next_cursor=next_cursor
    )


def _after(cursor: str) -> ColumnElement[bool]:
    """Rows positioned after the cursor ``"<txid>.<id>"``."""
    txid, _, row_id = cursor.partition(".")
    position = tuple_(col(OutboxEventDB.txid), col(OutboxEventDB.id))
    return position > tuple_(cast(int(txid), Xid8()), literal(int(row_id)))


def _finished() -> ColumnElement[bool]:
    """Rows whose transaction is older than every transaction still running."""
    return col(OutboxEventDB.txid) < func.pg_snapshot_xmin(func.pg_current_snapshot())
