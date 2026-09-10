"""Read and bulk-delete access to the port-change history log."""

from uuid import UUID

from sqlmodel import col, delete, select
from sqlmodel.ext.asyncio.session import AsyncSession

from falcoria_contracts.enums import PortChangeType
from falcoria_scanledger.history.models import IPPortHistoryDB
from falcoria_scanledger.history.schemas import HistoryOut


async def list_history(
    session: AsyncSession,
    project_id: UUID,
    *,
    ip: str | None = None,
    scan_id: UUID | None = None,
    change_type: PortChangeType | None = None,
    since: int | None = None,
    until: int | None = None,
    skip: int | None = None,
    limit: int | None = 100,
) -> list[HistoryOut]:
    """Return the project's port-change rows, newest first, with optional filters.

    `since` / `until` bound `created_at` inclusively; `ip`, `scan_id` and
    `change_type` match exactly. `limit` defaults to 100; pass `None` for no
    bound.
    """
    statement = select(IPPortHistoryDB).where(IPPortHistoryDB.project_id == project_id)
    if ip is not None:
        statement = statement.where(IPPortHistoryDB.ip == ip)
    if scan_id is not None:
        statement = statement.where(IPPortHistoryDB.scan_id == scan_id)
    if change_type is not None:
        statement = statement.where(IPPortHistoryDB.change_type == change_type)
    if since is not None:
        statement = statement.where(col(IPPortHistoryDB.created_at) >= since)
    if until is not None:
        statement = statement.where(col(IPPortHistoryDB.created_at) <= until)
    statement = (
        statement.order_by(col(IPPortHistoryDB.created_at).desc(), col(IPPortHistoryDB.id).desc())
        .offset(skip)
        .limit(limit)
    )
    rows = (await session.exec(statement)).all()
    return [HistoryOut.model_validate(r, from_attributes=True) for r in rows]


async def delete_history(session: AsyncSession, project_id: UUID) -> int:
    """Delete every port-change row for the project; return the deleted row count."""
    statement = delete(IPPortHistoryDB).where(col(IPPortHistoryDB.project_id) == project_id)
    connection = await session.connection()
    result = await connection.execute(statement)
    return result.rowcount
