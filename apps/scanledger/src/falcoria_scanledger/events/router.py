"""IP state-change event feed.

Mounted by ``main.py`` under ``/projects/{project_id}/events``, behind
``validate_project_access``.
"""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlmodel.ext.asyncio.session import AsyncSession

from falcoria_scanledger.constants import Tag
from falcoria_scanledger.database import get_session
from falcoria_scanledger.events import service
from falcoria_scanledger.events.schemas import EventPage

router = APIRouter(tags=[Tag.EVENTS])

_Session = Annotated[AsyncSession, Depends(get_session)]


@router.get("")
async def read_events(
    project_id: UUID,
    session: _Session,
    after: Annotated[
        str,
        Query(
            pattern=r"^\d+\.\d+$",
            description="`next_cursor` from the previous page; omit to start from the beginning.",
        ),
    ] = "0.0",
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
) -> EventPage:
    """Returns the project's IP change events after the cursor, oldest first.

    Delivery is at least once: store `next_cursor` only after the page is
    processed, and deduplicate on `event_id`.
    """
    return await service.read_events(session, project_id, after, limit)
