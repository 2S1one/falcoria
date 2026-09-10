"""HTTP coverage for the history router (mounted under /projects/{id}/history)."""

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


async def _project(client: AsyncClient, headers: dict[str, str], name: str = "p") -> str:
    resp = await client.post("/api/projects", json={"name": name}, headers=headers)
    assert resp.status_code == 201
    return resp.json()["id"]


async def _import(
    client: AsyncClient,
    headers: dict[str, str],
    pid: str,
    ip: str,
    number: int,
    *,
    endtime: int = 100,
    scan_id: str | None = None,
) -> None:
    params = {"mode": "insert"}
    if scan_id is not None:
        params["scan_id"] = scan_id
    resp = await client.post(
        f"/api/projects/{pid}/ips",
        params=params,
        json=[{"ip": ip, "endtime": endtime, "ports": [{"number": number}]}],
        headers=headers,
    )
    assert resp.status_code == 201


def _hist_url(pid: str, suffix: str = "") -> str:
    return f"/api/projects/{pid}/history{suffix}"


async def test_requires_authentication(anon_client: AsyncClient, session: AsyncSession) -> None:
    headers = await _headers(session, "admin")
    pid = await _project(anon_client, headers)

    assert (await anon_client.get(_hist_url(pid))).status_code == 401


async def test_list_history_shape(anon_client: AsyncClient, session: AsyncSession) -> None:
    headers = await _headers(session, "admin")
    pid = await _project(anon_client, headers)
    await _import(anon_client, headers, pid, "1.2.3.4", 80)

    resp = await anon_client.get(_hist_url(pid), headers=headers)
    assert resp.status_code == 200
    rows = resp.json()
    assert len(rows) == 1
    row = rows[0]
    assert row["ip"] == "1.2.3.4"
    assert row["port"] == 80
    assert row["change_type"] == "state"
    assert row["new_value"] == "open"
    assert row["scan_id"] is None


async def test_scan_id_roundtrips_through_filter(
    anon_client: AsyncClient, session: AsyncSession
) -> None:
    headers = await _headers(session, "admin")
    pid = await _project(anon_client, headers)
    sid = str(uuid4())
    await _import(anon_client, headers, pid, "1.1.1.1", 80, scan_id=sid)
    await _import(anon_client, headers, pid, "2.2.2.2", 80)

    tagged = await anon_client.get(_hist_url(pid), params={"scan_id": sid}, headers=headers)
    assert [r["ip"] for r in tagged.json()] == ["1.1.1.1"]
    assert tagged.json()[0]["scan_id"] == sid

    miss = await anon_client.get(_hist_url(pid), params={"scan_id": str(uuid4())}, headers=headers)
    assert miss.json() == []


async def test_since_greater_than_until_returns_400(
    anon_client: AsyncClient, session: AsyncSession
) -> None:
    headers = await _headers(session, "admin")
    pid = await _project(anon_client, headers)

    resp = await anon_client.get(
        _hist_url(pid), params={"since": 500, "until": 100}, headers=headers
    )
    assert resp.status_code == 400


async def test_delete_clears_project_history(
    anon_client: AsyncClient, session: AsyncSession
) -> None:
    headers = await _headers(session, "admin")
    pid = await _project(anon_client, headers)
    await _import(anon_client, headers, pid, "1.1.1.1", 80)
    await _import(anon_client, headers, pid, "2.2.2.2", 443)

    assert (await anon_client.delete(_hist_url(pid), headers=headers)).status_code == 204
    assert (await anon_client.get(_hist_url(pid), headers=headers)).json() == []


async def test_non_member_is_forbidden(anon_client: AsyncClient, session: AsyncSession) -> None:
    owner = await _headers(session, "owner")
    pid = await _project(anon_client, owner)
    outsider = await _headers(session, "outsider", is_admin=False)

    assert (await anon_client.get(_hist_url(pid), headers=outsider)).status_code == 403
