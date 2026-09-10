import uuid

import pytest
from httpx import AsyncClient
from sqlmodel.ext.asyncio.session import AsyncSession

from falcoria_scanledger.auth import service as auth_service
from falcoria_scanledger.auth.schemas import UserCreate

pytestmark = pytest.mark.anyio

_BASE = "/api/projects"


async def _actor(
    session: AsyncSession, username: str, *, is_admin: bool = False
) -> tuple[uuid.UUID, dict[str, str]]:
    """Creates a user and returns (its id, bearer-auth headers).

    Returns the id as a plain value, not the ORM row: a later request that 4xxs
    rolls the shared session back and expires every attached object.
    """
    user, token = await auth_service.create_user(
        session, UserCreate(username=username, is_admin=is_admin)
    )
    return user.id, {"Authorization": f"Bearer {token}"}


async def test_requires_authentication(anon_client: AsyncClient) -> None:
    assert (await anon_client.get(_BASE)).status_code == 401


async def test_create_project_returns_201_and_minimal_shape(
    anon_client: AsyncClient, session: AsyncSession
) -> None:
    _, headers = await _actor(session, "alice")

    resp = await anon_client.post(_BASE, json={"name": "alpha"}, headers=headers)

    assert resp.status_code == 201
    body = resp.json()
    assert body["name"] == "alpha"
    assert set(body) == {"id", "name", "comment"}


async def test_create_duplicate_name_is_allowed(
    anon_client: AsyncClient, session: AsyncSession
) -> None:
    _, headers = await _actor(session, "alice")
    first = await anon_client.post(_BASE, json={"name": "dup"}, headers=headers)

    second = await anon_client.post(_BASE, json={"name": "dup"}, headers=headers)

    assert first.status_code == 201
    assert second.status_code == 201
    assert first.json()["id"] != second.json()["id"]


async def test_create_invalid_name_returns_422(
    anon_client: AsyncClient, session: AsyncSession
) -> None:
    _, headers = await _actor(session, "alice")

    resp = await anon_client.post(_BASE, json={"name": "bad name!"}, headers=headers)

    assert resp.status_code == 422


async def test_list_is_scoped_to_membership(
    anon_client: AsyncClient, session: AsyncSession
) -> None:
    _, alice = await _actor(session, "alice")
    _, bob = await _actor(session, "bob")
    await anon_client.post(_BASE, json={"name": "a"}, headers=alice)

    assert (await anon_client.get(_BASE, headers=bob)).json() == []


async def test_admin_sees_all_projects(anon_client: AsyncClient, session: AsyncSession) -> None:
    _, alice = await _actor(session, "alice")
    _, root = await _actor(session, "root", is_admin=True)
    await anon_client.post(_BASE, json={"name": "a"}, headers=alice)

    listed = await anon_client.get(_BASE, headers=root)

    assert [p["name"] for p in listed.json()] == ["a"]


async def test_non_member_get_returns_403(anon_client: AsyncClient, session: AsyncSession) -> None:
    _, alice = await _actor(session, "alice")
    _, bob = await _actor(session, "bob")
    created = await anon_client.post(_BASE, json={"name": "a"}, headers=alice)
    pid = created.json()["id"]

    assert (await anon_client.get(f"{_BASE}/{pid}", headers=bob)).status_code == 403


async def test_non_member_put_returns_403(anon_client: AsyncClient, session: AsyncSession) -> None:
    _, alice = await _actor(session, "alice")
    _, bob = await _actor(session, "bob")
    created = await anon_client.post(_BASE, json={"name": "a"}, headers=alice)
    pid = created.json()["id"]

    resp = await anon_client.put(f"{_BASE}/{pid}", json={"comment": "x"}, headers=bob)

    assert resp.status_code == 403


async def test_non_member_delete_returns_403(
    anon_client: AsyncClient, session: AsyncSession
) -> None:
    _, alice = await _actor(session, "alice")
    _, bob = await _actor(session, "bob")
    created = await anon_client.post(_BASE, json={"name": "a"}, headers=alice)
    pid = created.json()["id"]

    assert (await anon_client.delete(f"{_BASE}/{pid}", headers=bob)).status_code == 403


async def test_non_member_cannot_touch_members(
    anon_client: AsyncClient, session: AsyncSession
) -> None:
    _, alice = await _actor(session, "alice")
    bob_id, bob = await _actor(session, "bob")
    created = await anon_client.post(_BASE, json={"name": "a"}, headers=alice)
    pid = created.json()["id"]

    assert (await anon_client.get(f"{_BASE}/{pid}/members", headers=bob)).status_code == 403
    add = await anon_client.post(
        f"{_BASE}/{pid}/members", json={"user_id": str(bob_id)}, headers=bob
    )
    assert add.status_code == 403
    rm = await anon_client.delete(f"{_BASE}/{pid}/members/{bob_id}", headers=bob)
    assert rm.status_code == 403


async def test_unknown_project_get_returns_404(
    anon_client: AsyncClient, session: AsyncSession
) -> None:
    _, headers = await _actor(session, "alice")

    resp = await anon_client.get(f"{_BASE}/{uuid.uuid4()}", headers=headers)

    assert resp.status_code == 404


async def test_update_comment(anon_client: AsyncClient, session: AsyncSession) -> None:
    _, headers = await _actor(session, "alice")
    created = await anon_client.post(_BASE, json={"name": "a"}, headers=headers)
    pid = created.json()["id"]

    resp = await anon_client.put(f"{_BASE}/{pid}", json={"comment": "hi"}, headers=headers)

    assert resp.status_code == 200
    assert resp.json()["comment"] == "hi"


async def test_rename_project(anon_client: AsyncClient, session: AsyncSession) -> None:
    _, headers = await _actor(session, "alice")
    created = await anon_client.post(_BASE, json={"name": "old"}, headers=headers)
    pid = created.json()["id"]

    resp = await anon_client.put(f"{_BASE}/{pid}", json={"name": "new"}, headers=headers)

    assert resp.status_code == 200
    assert resp.json()["name"] == "new"


async def test_rename_invalid_name_returns_422(
    anon_client: AsyncClient, session: AsyncSession
) -> None:
    _, headers = await _actor(session, "alice")
    created = await anon_client.post(_BASE, json={"name": "old"}, headers=headers)
    pid = created.json()["id"]

    resp = await anon_client.put(f"{_BASE}/{pid}", json={"name": "bad name!"}, headers=headers)

    assert resp.status_code == 422


async def test_delete_project(anon_client: AsyncClient, session: AsyncSession) -> None:
    _, headers = await _actor(session, "alice")
    created = await anon_client.post(_BASE, json={"name": "a"}, headers=headers)
    pid = created.json()["id"]

    assert (await anon_client.delete(f"{_BASE}/{pid}", headers=headers)).status_code == 204
    assert (await anon_client.get(f"{_BASE}/{pid}", headers=headers)).status_code == 404


async def test_add_member_then_they_gain_access(
    anon_client: AsyncClient, session: AsyncSession
) -> None:
    _, owner = await _actor(session, "owner")
    guest_id, guest_headers = await _actor(session, "guest")
    created = await anon_client.post(_BASE, json={"name": "a"}, headers=owner)
    pid = created.json()["id"]
    assert (await anon_client.get(f"{_BASE}/{pid}", headers=guest_headers)).status_code == 403

    resp = await anon_client.post(
        f"{_BASE}/{pid}/members", json={"user_id": str(guest_id)}, headers=owner
    )
    assert resp.status_code == 204

    assert (await anon_client.get(f"{_BASE}/{pid}", headers=guest_headers)).status_code == 200
    listed = await anon_client.get(f"{_BASE}/{pid}/members", headers=owner)
    assert sorted(u["username"] for u in listed.json()) == ["guest", "owner"]


async def test_add_member_unknown_user_returns_404(
    anon_client: AsyncClient, session: AsyncSession
) -> None:
    _, owner = await _actor(session, "owner")
    created = await anon_client.post(_BASE, json={"name": "a"}, headers=owner)
    pid = created.json()["id"]

    resp = await anon_client.post(
        f"{_BASE}/{pid}/members", json={"user_id": str(uuid.uuid4())}, headers=owner
    )

    assert resp.status_code == 404


async def test_remove_member(anon_client: AsyncClient, session: AsyncSession) -> None:
    _, owner = await _actor(session, "owner")
    guest_id, _ = await _actor(session, "guest")
    created = await anon_client.post(_BASE, json={"name": "a"}, headers=owner)
    pid = created.json()["id"]
    await anon_client.post(f"{_BASE}/{pid}/members", json={"user_id": str(guest_id)}, headers=owner)

    resp = await anon_client.delete(f"{_BASE}/{pid}/members/{guest_id}", headers=owner)

    assert resp.status_code == 204


async def test_remove_non_member_returns_404(
    anon_client: AsyncClient, session: AsyncSession
) -> None:
    _, owner = await _actor(session, "owner")
    guest_id, _ = await _actor(session, "guest")
    created = await anon_client.post(_BASE, json={"name": "a"}, headers=owner)
    pid = created.json()["id"]

    resp = await anon_client.delete(f"{_BASE}/{pid}/members/{guest_id}", headers=owner)

    assert resp.status_code == 404
