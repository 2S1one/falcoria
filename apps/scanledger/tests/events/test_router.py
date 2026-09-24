"""HTTP coverage for the event feed router (mounted under /projects/{id}/events).

The test session never commits, so its own events stay invisible to the feed;
feed contents are covered in test_feed.py.
"""

from uuid import uuid4

import pytest
from httpx import AsyncClient
from sqlmodel.ext.asyncio.session import AsyncSession

from falcoria_scanledger.auth import service as auth_service
from falcoria_scanledger.auth.schemas import UserCreate

pytestmark = pytest.mark.anyio


async def _headers(
    session: AsyncSession, username: str, *, is_admin: bool = True
) -> dict[str, str]:
    _, token = await auth_service.create_user(
        session, UserCreate(username=username, is_admin=is_admin)
    )
    return {"Authorization": f"Bearer {token}"}


async def _project(client: AsyncClient, headers: dict[str, str]) -> str:
    resp = await client.post("/api/projects", json={"name": "p"}, headers=headers)
    assert resp.status_code == 201
    return resp.json()["id"]


async def test_empty_feed(client: AsyncClient, session: AsyncSession) -> None:
    headers = await _headers(session, "admin")
    pid = await _project(client, headers)
    resp = await client.get(f"/api/projects/{pid}/events", headers=headers)
    assert resp.status_code == 200
    assert resp.json() == {"items": [], "next_cursor": "0.0"}


@pytest.mark.parametrize("after", ["abc", "1", "1.2.3", "-1.0", "1.x"])
async def test_malformed_cursor_is_rejected(
    client: AsyncClient, session: AsyncSession, after: str
) -> None:
    headers = await _headers(session, "admin")
    pid = await _project(client, headers)
    resp = await client.get(f"/api/projects/{pid}/events", params={"after": after}, headers=headers)
    assert resp.status_code == 422


async def test_unknown_project_is_404(client: AsyncClient, session: AsyncSession) -> None:
    headers = await _headers(session, "admin")
    resp = await client.get(f"/api/projects/{uuid4()}/events", headers=headers)
    assert resp.status_code == 404


async def test_requires_auth(anon_client: AsyncClient) -> None:
    resp = await anon_client.get(f"/api/projects/{uuid4()}/events")
    assert resp.status_code == 401
