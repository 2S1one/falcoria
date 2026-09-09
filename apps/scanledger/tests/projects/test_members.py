import uuid

import pytest
from sqlmodel.ext.asyncio.session import AsyncSession

from falcoria_scanledger.auth import service as auth_service
from falcoria_scanledger.auth.models import UserDB
from falcoria_scanledger.auth.schemas import UserCreate
from falcoria_scanledger.projects import members, service
from falcoria_scanledger.projects.schemas import ProjectCreate

pytestmark = pytest.mark.anyio


async def _user(session: AsyncSession, username: str) -> UserDB:
    user, _ = await auth_service.create_user(session, UserCreate(username=username))
    return user


async def test_add_member_enrols_a_user(session: AsyncSession) -> None:
    owner = await _user(session, "owner")
    guest = await _user(session, "guest")
    project = await service.create_project(session, ProjectCreate(name="p"), owner)

    assert await members.add_member(session, project.id, guest.id) is True
    assert await service.is_member(session, project.id, guest.id) is True


async def test_add_member_is_idempotent(session: AsyncSession) -> None:
    owner = await _user(session, "owner")
    guest = await _user(session, "guest")
    project = await service.create_project(session, ProjectCreate(name="p"), owner)

    assert await members.add_member(session, project.id, guest.id) is True
    assert await members.add_member(session, project.id, guest.id) is True

    rows = await members.list_members(session, project.id)
    assert sorted(u.username for u in rows) == ["guest", "owner"]


async def test_add_member_unknown_user_returns_false(session: AsyncSession) -> None:
    owner = await _user(session, "owner")
    project = await service.create_project(session, ProjectCreate(name="p"), owner)

    assert await members.add_member(session, project.id, uuid.uuid4()) is False


async def test_remove_member(session: AsyncSession) -> None:
    owner = await _user(session, "owner")
    guest = await _user(session, "guest")
    project = await service.create_project(session, ProjectCreate(name="p"), owner)
    await members.add_member(session, project.id, guest.id)

    assert await members.remove_member(session, project.id, guest.id) is True
    assert await service.is_member(session, project.id, guest.id) is False


async def test_remove_non_member_returns_false(session: AsyncSession) -> None:
    owner = await _user(session, "owner")
    guest = await _user(session, "guest")
    project = await service.create_project(session, ProjectCreate(name="p"), owner)

    assert await members.remove_member(session, project.id, guest.id) is False


async def test_list_members_orders_by_username(session: AsyncSession) -> None:
    owner = await _user(session, "zed")
    amy = await _user(session, "amy")
    project = await service.create_project(session, ProjectCreate(name="p"), owner)
    await members.add_member(session, project.id, amy.id)

    rows = await members.list_members(session, project.id)

    assert [u.username for u in rows] == ["amy", "zed"]
