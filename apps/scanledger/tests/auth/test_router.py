import uuid

import pytest
from httpx import AsyncClient
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from falcoria_scanledger.auth import service, tokens
from falcoria_scanledger.auth.models import UserDB
from falcoria_scanledger.auth.schemas import UserCreate
from falcoria_scanledger.auth.security import authenticate_token

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


async def test_list_users_is_empty_initially(client: AsyncClient) -> None:
    resp = await client.get("/api/admin/users")

    assert resp.status_code == 200
    assert resp.json() == []


async def test_list_users_returns_created_users_without_token_material(
    client: AsyncClient, session: AsyncSession
) -> None:
    await service.create_user(session, UserCreate(username="amy"))
    await service.create_user(session, UserCreate(username="zoe", is_admin=True))

    resp = await client.get("/api/admin/users")

    assert resp.status_code == 200
    rows = resp.json()
    assert [r["username"] for r in rows] == ["amy", "zoe"]
    assert all("hashed_token" not in r for r in rows)
    assert {"id", "username", "is_admin", "token_expires_at"} == set(rows[0])


async def test_delete_user(client: AsyncClient, session: AsyncSession) -> None:
    user, _ = await service.create_user(session, UserCreate(username="mallory"))

    resp = await client.delete(f"/api/admin/users/{user.id}")

    assert resp.status_code == 204
    assert (await session.exec(select(UserDB).where(UserDB.id == user.id))).one_or_none() is None


async def test_delete_unknown_user_returns_404(client: AsyncClient) -> None:
    resp = await client.delete(f"/api/admin/users/{uuid.uuid4()}")
    assert resp.status_code == 404


async def test_rotate_token_issues_new_and_revokes_old(
    client: AsyncClient, session: AsyncSession
) -> None:
    user, old_token = await service.create_user(session, UserCreate(username="peggy"))

    resp = await client.put(f"/api/admin/users/{user.id}/token", json={})

    assert resp.status_code == 200
    new_token = resp.json()["token"]
    assert new_token != old_token
    assert await authenticate_token(session, old_token) is None
    authed = await authenticate_token(session, new_token)
    assert authed is not None
    assert authed.id == user.id


async def test_rotate_token_sets_expiry(client: AsyncClient, session: AsyncSession) -> None:
    user, _ = await service.create_user(session, UserCreate(username="trent"))

    resp = await client.put(f"/api/admin/users/{user.id}/token", json={"token_lifetime": 3600})

    assert resp.status_code == 200
    await session.refresh(user)
    assert user.token_expires_at is not None


async def test_rotate_token_unknown_user_returns_404(client: AsyncClient) -> None:
    resp = await client.put(f"/api/admin/users/{uuid.uuid4()}/token", json={})
    assert resp.status_code == 404
