"""Project and project-membership endpoints."""

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, status
from sqlalchemy.exc import IntegrityError
from sqlmodel.ext.asyncio.session import AsyncSession

from falcoria_scanledger.auth.dependencies import require_user
from falcoria_scanledger.auth.models import UserDB
from falcoria_scanledger.constants import Tag
from falcoria_scanledger.database import get_session
from falcoria_scanledger.exceptions import Conflict, NotFound
from falcoria_scanledger.projects import members, service
from falcoria_scanledger.projects.dependencies import validate_project_access
from falcoria_scanledger.projects.models import ProjectDB
from falcoria_scanledger.projects.schemas import (
    MemberAdd,
    MemberOut,
    ProjectCreate,
    ProjectOut,
    ProjectUpdate,
)

router = APIRouter(prefix="/projects", tags=[Tag.PROJECTS])

_NOT_FOUND: dict[int | str, dict[str, Any]] = {
    status.HTTP_404_NOT_FOUND: {"description": "The project, user, or membership does not exist."}
}


@router.get("")
async def list_projects(
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[UserDB, Depends(require_user)],
) -> list[ProjectOut]:
    """Lists the projects visible to the caller (all of them for an admin)."""
    rows = await service.list_projects(session, user)
    return [ProjectOut.model_validate(row) for row in rows]


@router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    responses={status.HTTP_409_CONFLICT: {"description": "Project name already taken."}},
)
async def create_project(
    body: ProjectCreate,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[UserDB, Depends(require_user)],
) -> ProjectOut:
    """Creates a project; the caller becomes its first member."""
    try:
        project = await service.create_project(session, body, user)
    except IntegrityError as exc:
        raise Conflict(f"Project '{body.name}' already exists.") from exc
    return ProjectOut.model_validate(project)


@router.get("/{project_id}", responses=_NOT_FOUND)
async def get_project(
    project: Annotated[ProjectDB, Depends(validate_project_access)],
) -> ProjectOut:
    """Returns one project."""
    return ProjectOut.model_validate(project)


@router.put("/{project_id}", responses=_NOT_FOUND)
async def update_project(
    body: ProjectUpdate,
    session: Annotated[AsyncSession, Depends(get_session)],
    project: Annotated[ProjectDB, Depends(validate_project_access)],
) -> ProjectOut:
    """Updates a project's comment. The name cannot be changed."""
    updated = await service.update_project(session, project, body)
    return ProjectOut.model_validate(updated)


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT, responses=_NOT_FOUND)
async def delete_project(
    session: Annotated[AsyncSession, Depends(get_session)],
    project: Annotated[ProjectDB, Depends(validate_project_access)],
) -> None:
    """Deletes a project and everything scoped to it."""
    await service.delete_project(session, project)


members_router = APIRouter(tags=[Tag.PROJECTS])


@members_router.get("")
async def list_members(
    project_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> list[MemberOut]:
    """Lists the users enrolled in this project."""
    rows = await members.list_members(session, project_id)
    return [MemberOut.model_validate(row) for row in rows]


@members_router.post("", status_code=status.HTTP_204_NO_CONTENT)
async def add_member(
    project_id: UUID,
    body: MemberAdd,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> None:
    """Enrols a user in this project. Idempotent — re-adding a member is a no-op."""
    if not await members.add_member(session, project_id, body.user_id):
        raise NotFound(f"User {body.user_id} not found.")


@members_router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_member(
    project_id: UUID,
    user_id: UUID,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> None:
    """Removes a user from this project."""
    if not await members.remove_member(session, project_id, user_id):
        raise NotFound(f"User {user_id} is not a member of project {project_id}.")


router.include_router(
    members_router,
    prefix="/{project_id}/members",
    dependencies=[Depends(validate_project_access)],
    responses=_NOT_FOUND,
)
