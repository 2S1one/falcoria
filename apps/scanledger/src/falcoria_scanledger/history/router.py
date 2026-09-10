"""Port-change history endpoints.

Mounted by ``main.py`` under ``/projects/{project_id}/history``, behind
``validate_project_access``.
"""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, status
from sqlmodel.ext.asyncio.session import AsyncSession

from falcoria_contracts.enums import PortChangeType
from falcoria_scanledger.constants import Tag
from falcoria_scanledger.database import get_session
from falcoria_scanledger.exceptions import BadRequest
from falcoria_scanledger.history import service
from falcoria_scanledger.history.schemas import HistoryOut

router = APIRouter(tags=[Tag.HISTORY])

_Session = Annotated[AsyncSession, Depends(get_session)]
_Ts = Annotated[int | None, Query(ge=0, description="Unix epoch seconds, inclusive.")]


@router.get("")
async def list_history(
    project_id: UUID,
    session: _Session,
    ip: Annotated[str | None, Query()] = None,
    scan_id: Annotated[UUID | None, Query()] = None,
    change_type: Annotated[PortChangeType | None, Query()] = None,
    since: _Ts = None,
    until: _Ts = None,
    skip: Annotated[int | None, Query(ge=0)] = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
) -> list[HistoryOut]:
    """Lists recorded port changes for the project, newest first."""
    if since is not None and until is not None and since > until:
        raise BadRequest("since must not be greater than until.")
    return await service.list_history(
        session,
        project_id,
        ip=ip,
        scan_id=scan_id,
        change_type=change_type,
        since=since,
        until=until,
        skip=skip,
        limit=limit,
    )


@router.delete("", status_code=status.HTTP_204_NO_CONTENT)
async def delete_history(project_id: UUID, session: _Session) -> None:
    """Deletes all port-change history for the project."""
    await service.delete_history(session, project_id)
