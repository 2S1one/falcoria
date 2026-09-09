import uuid

import pytest
from sqlmodel.ext.asyncio.session import AsyncSession

from falcoria_scanledger.auth import service as auth_service
from falcoria_scanledger.auth.models import UserDB
from falcoria_scanledger.auth.schemas import UserCreate
from falcoria_scanledger.exceptions import NotFound, PermissionDenied
from falcoria_scanledger.projects import service
from falcoria_scanledger.projects.dependencies import validate_project_access
from falcoria_scanledger.projects.schemas import ProjectCreate

pytestmark = pytest.mark.anyio


async def _user(session: AsyncSession, username: str, *, is_admin: bool = False) -> UserDB:
    user, _ = await auth_service.create_user(
        session, UserCreate(username=username, is_admin=is_admin)
    )
    return user


async def test_returns_loaded_project_for_a_member(session: AsyncSession) -> None:
    owner = await _user(session, "owner")
    project = await service.create_project(session, ProjectCreate(name="p"), owner)

    loaded = await validate_project_access(project.id, session, owner)

    assert loaded.id == project.id


async def test_admin_reaches_a_project_they_are_not_in(session: AsyncSession) -> None:
    owner = await _user(session, "owner")
    admin = await _user(session, "root", is_admin=True)
    project = await service.create_project(session, ProjectCreate(name="p"), owner)

    loaded = await validate_project_access(project.id, session, admin)

    assert loaded.id == project.id


async def test_non_member_is_denied(session: AsyncSession) -> None:
    owner = await _user(session, "owner")
    outsider = await _user(session, "outsider")
    project = await service.create_project(session, ProjectCreate(name="p"), owner)

    with pytest.raises(PermissionDenied):
        await validate_project_access(project.id, session, outsider)


async def test_unknown_project_is_not_found(session: AsyncSession) -> None:
    admin = await _user(session, "root", is_admin=True)

    with pytest.raises(NotFound):
        await validate_project_access(uuid.uuid4(), session, admin)
