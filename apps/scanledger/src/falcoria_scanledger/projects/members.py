"""Project-membership operations: list, add, remove."""

from collections.abc import Sequence
from uuid import UUID

from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from falcoria_scanledger.auth.models import UserDB
from falcoria_scanledger.projects.models import ProjectMemberLink


async def list_members(session: AsyncSession, project_id: UUID) -> Sequence[UserDB]:
    """Returns the users enrolled in `project_id`, ordered by username."""
    statement = (
        select(UserDB)
        .join(ProjectMemberLink)
        .where(ProjectMemberLink.project_id == project_id)
        .order_by(UserDB.username)
    )
    return (await session.exec(statement)).all()


async def add_member(session: AsyncSession, project_id: UUID, user_id: UUID) -> bool:
    """Enrols `user_id` in `project_id`; returns False when no such user exists.

    Idempotent: enrolling a user who is already a member is a no-op and still
    returns True. The caller has already verified the project exists.
    """
    if await session.get(UserDB, user_id) is None:
        return False
    if await session.get(ProjectMemberLink, (project_id, user_id)) is None:
        session.add(ProjectMemberLink(project_id=project_id, user_id=user_id))
    return True


async def remove_member(session: AsyncSession, project_id: UUID, user_id: UUID) -> bool:
    """Removes `user_id` from `project_id`; returns whether a row was removed."""
    link = await session.get(ProjectMemberLink, (project_id, user_id))
    if link is None:
        return False
    await session.delete(link)
    return True
