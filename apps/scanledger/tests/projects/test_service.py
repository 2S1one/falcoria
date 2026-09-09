import uuid

import pytest
from sqlalchemy.exc import IntegrityError
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from falcoria_scanledger.auth import service as auth_service
from falcoria_scanledger.auth.models import UserDB
from falcoria_scanledger.auth.schemas import UserCreate
from falcoria_scanledger.projects import service
from falcoria_scanledger.projects.models import ProjectMemberLink
from falcoria_scanledger.projects.schemas import ProjectCreate, ProjectUpdate

pytestmark = pytest.mark.anyio


async def _user(session: AsyncSession, username: str, *, is_admin: bool = False) -> UserDB:
    user, _ = await auth_service.create_user(
        session, UserCreate(username=username, is_admin=is_admin)
    )
    return user


async def test_create_project_enrols_owner_as_member(session: AsyncSession) -> None:
    owner = await _user(session, "owner")

    project = await service.create_project(session, ProjectCreate(name="alpha"), owner)

    assert project.id is not None
    assert project.name == "alpha"
    assert await service.is_member(session, project.id, owner.id) is True


async def test_create_project_rejects_duplicate_name(session: AsyncSession) -> None:
    owner = await _user(session, "owner")
    await service.create_project(session, ProjectCreate(name="dup"), owner)

    with pytest.raises(IntegrityError):
        await service.create_project(session, ProjectCreate(name="dup"), owner)


async def test_get_project_returns_none_for_unknown_id(session: AsyncSession) -> None:
    assert await service.get_project(session, uuid.uuid4()) is None


async def test_list_projects_non_admin_sees_only_own(session: AsyncSession) -> None:
    alice = await _user(session, "alice")
    bob = await _user(session, "bob")
    await service.create_project(session, ProjectCreate(name="a-proj"), alice)
    await service.create_project(session, ProjectCreate(name="b-proj"), bob)

    rows = await service.list_projects(session, alice)

    assert [p.name for p in rows] == ["a-proj"]


async def test_list_projects_admin_sees_all_ordered_by_name(session: AsyncSession) -> None:
    alice = await _user(session, "alice")
    admin = await _user(session, "root", is_admin=True)
    await service.create_project(session, ProjectCreate(name="zeta"), alice)
    await service.create_project(session, ProjectCreate(name="beta"), alice)

    rows = await service.list_projects(session, admin)

    assert [p.name for p in rows] == ["beta", "zeta"]


async def test_update_project_distinguishes_unset_from_explicit_null(
    session: AsyncSession,
) -> None:
    owner = await _user(session, "owner")
    project = await service.create_project(session, ProjectCreate(name="p", comment="orig"), owner)

    await service.update_project(session, project, ProjectUpdate())
    assert project.comment == "orig"

    await service.update_project(session, project, ProjectUpdate(comment="new"))
    assert project.comment == "new"

    await service.update_project(session, project, ProjectUpdate(comment=None))
    assert project.comment is None


async def test_delete_project_cascades_membership(session: AsyncSession) -> None:
    owner = await _user(session, "owner")
    project = await service.create_project(session, ProjectCreate(name="gone"), owner)
    pid = project.id

    await service.delete_project(session, project)
    await session.flush()

    assert await service.get_project(session, pid) is None
    assert (await session.exec(select(ProjectMemberLink))).all() == []
