"""Projects service: transaction-scoped project queries and mutations."""

from collections.abc import Sequence
from uuid import UUID

from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from falcoria_scanledger.auth.models import UserDB
from falcoria_scanledger.projects.models import ProjectDB, ProjectMemberLink
from falcoria_scanledger.projects.schemas import ProjectCreate, ProjectUpdate


async def get_project(session: AsyncSession, project_id: UUID) -> ProjectDB | None:
    """Returns the project, or None when no row has that id."""
    return await session.get(ProjectDB, project_id)


async def is_member(session: AsyncSession, project_id: UUID, user_id: UUID) -> bool:
    """Returns whether `user_id` holds a membership row for `project_id`.

    Queried (not ``session.get``) so pending adds/removes in the current unit of
    work are flushed and reflected — this gates every project request.
    """
    statement = select(ProjectMemberLink).where(
        ProjectMemberLink.project_id == project_id,
        ProjectMemberLink.user_id == user_id,
    )
    return (await session.exec(statement)).first() is not None


async def list_projects(session: AsyncSession, user: UserDB) -> Sequence[ProjectDB]:
    """Returns projects visible to `user` — all of them for an admin, else own.

    Ordered by name. A non-admin sees only the projects they are a member of.
    """
    statement = select(ProjectDB).order_by(ProjectDB.name)
    if not user.is_admin:
        # ON clause is inferred from the sole projects <-> link foreign key.
        statement = statement.join(ProjectMemberLink).where(ProjectMemberLink.user_id == user.id)
    return (await session.exec(statement)).all()


async def create_project(session: AsyncSession, data: ProjectCreate, owner: UserDB) -> ProjectDB:
    """Creates a project and enrols `owner` as its first member.

    The request transaction commits. A duplicate name surfaces as
    ``sqlalchemy.exc.IntegrityError``.
    """
    project = ProjectDB(**data.model_dump())
    session.add(project)
    session.add(ProjectMemberLink(project_id=project.id, user_id=owner.id))
    # One flush for both inserts, inside the router's try/except: a duplicate
    # name raises IntegrityError here, not later at the request's commit.
    await session.flush()
    return project


async def update_project(
    session: AsyncSession, project: ProjectDB, data: ProjectUpdate
) -> ProjectDB:
    """Applies the set fields of `data` to an already-loaded `project`.

    Only fields present in the request are touched (``exclude_unset``).
    """
    for field, value in data.model_dump(exclude_unset=True).items():
        setattr(project, field, value)
    return project


async def delete_project(session: AsyncSession, project: ProjectDB) -> None:
    """Deletes an already-loaded `project`; membership rows cascade."""
    await session.delete(project)
