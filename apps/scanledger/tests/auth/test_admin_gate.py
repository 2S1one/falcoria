from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlmodel.ext.asyncio.session import AsyncSession

from falcoria_scanledger.auth import service, tokens
from falcoria_scanledger.auth.models import UserDB
from falcoria_scanledger.auth.schemas import UserCreate

pytestmark = pytest.mark.anyio

_NEW_USER = {"username": "newbie"}


async def test_no_credentials_is_401_with_challenge(anon_client: AsyncClient) -> None:
    resp = await anon_client.post("/api/admin/users", json=_NEW_USER)

    assert resp.status_code == 401
    assert resp.headers["www-authenticate"] == "Bearer"


async def test_unknown_token_is_401(anon_client: AsyncClient) -> None:
    resp = await anon_client.post(
        "/api/admin/users", json=_NEW_USER, headers={"Authorization": "Bearer nope"}
    )

    assert resp.status_code == 401


async def test_non_admin_token_is_403(anon_client: AsyncClient, session: AsyncSession) -> None:
    _, token = await service.create_user(session, UserCreate(username="regular"))

    resp = await anon_client.post(
        "/api/admin/users", json=_NEW_USER, headers={"Authorization": f"Bearer {token}"}
    )

    assert resp.status_code == 403


async def test_admin_token_passes_the_gate(anon_client: AsyncClient, session: AsyncSession) -> None:
    _, token = await service.create_user(session, UserCreate(username="boss", is_admin=True))

    resp = await anon_client.post(
        "/api/admin/users", json=_NEW_USER, headers={"Authorization": f"Bearer {token}"}
    )

    assert resp.status_code == 201


async def test_expired_token_is_401(anon_client: AsyncClient, session: AsyncSession) -> None:
    past = datetime.now(UTC) - timedelta(minutes=1)
    session.add(
        UserDB(
            username="stale",
            is_admin=True,
            hashed_token=tokens.hash_token("stale-tok"),
            token_expires_at=past,
        )
    )
    await session.flush()

    resp = await anon_client.post(
        "/api/admin/users", json=_NEW_USER, headers={"Authorization": "Bearer stale-tok"}
    )

    assert resp.status_code == 401
