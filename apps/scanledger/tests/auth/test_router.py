import pytest
from httpx import AsyncClient
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from falcoria_scanledger.auth import tokens
from falcoria_scanledger.auth.models import UserDB

pytestmark = pytest.mark.anyio


async def test_create_user_returns_201_and_a_working_token(
    client: AsyncClient, session: AsyncSession
) -> None:
    resp = await client.post("/api/admin/users", json={"username": "grace"})

    assert resp.status_code == 201
    token = resp.json()["token"]
    assert len(token) == 60
    user = (await session.exec(select(UserDB).where(UserDB.username == "grace"))).one()
    assert user.hashed_token == tokens.hash_token(token)
    assert user.is_admin is False


async def test_create_user_duplicate_username_returns_409(client: AsyncClient) -> None:
    assert (await client.post("/api/admin/users", json={"username": "heidi"})).status_code == 201
    assert (await client.post("/api/admin/users", json={"username": "heidi"})).status_code == 409


async def test_create_user_rejects_invalid_username(client: AsyncClient) -> None:
    resp = await client.post("/api/admin/users", json={"username": "ab"})
    assert resp.status_code == 422


async def test_create_user_can_make_an_admin(client: AsyncClient, session: AsyncSession) -> None:
    resp = await client.post("/api/admin/users", json={"username": "ivan", "is_admin": True})

    assert resp.status_code == 201
    user = (await session.exec(select(UserDB).where(UserDB.username == "ivan"))).one()
    assert user.is_admin is True
