"""FastAPI dependency that loads a project and gates access to it."""

from typing import Annotated
from uuid import UUID

from fastapi import Depends
from sqlmodel.ext.asyncio.session import AsyncSession

from falcoria_scanledger.auth.dependencies import require_user
from falcoria_scanledger.auth.models import UserDB
from falcoria_scanledger.database import get_session
from falcoria_scanledger.exceptions import NotFound, PermissionDenied
from falcoria_scanledger.projects import service
from falcoria_scanledger.projects.models import ProjectDB


async def validate_project_access(
    project_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[UserDB, Depends(require_user)],
) -> ProjectDB:
    """Loads `project_id` and returns it when `user` is allowed to access it.

    An admin may reach any project; every other user must hold a membership row.

    Raises:
        NotFound: no project has that id.
        PermissionDenied: the project exists but the user is not a member.
    """
    project = await service.get_project(session, project_id)
    if project is None:
        raise NotFound(f"Project {project_id} not found.")
    if not user.is_admin and not await service.is_member(session, project_id, user.id):
        raise PermissionDenied()
    return project
