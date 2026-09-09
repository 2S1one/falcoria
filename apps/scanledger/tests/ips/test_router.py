"""HTTP coverage for the ips router (mounted under /projects/{id}/ips)."""

from pathlib import Path

import pytest
from httpx import AsyncClient
from sqlmodel.ext.asyncio.session import AsyncSession

from falcoria_scanledger.auth import service as auth_service
from falcoria_scanledger.auth.schemas import UserCreate

pytestmark = pytest.mark.anyio

_FIXTURES = Path(__file__).parent.parent / "fixtures" / "nmap"


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


def _ips_url(project_id: str, suffix: str = "") -> str:
    return f"/api/projects/{project_id}/ips{suffix}"


async def test_requires_authentication(anon_client: AsyncClient, session: AsyncSession) -> None:
    headers = await _headers(session, "admin")
    pid = await _project(anon_client, headers)

    assert (await anon_client.get(_ips_url(pid))).status_code == 401


async def test_import_scan_returns_created_addresses(
    anon_client: AsyncClient, session: AsyncSession
) -> None:
    headers = await _headers(session, "admin")
    pid = await _project(anon_client, headers)
    xml = (_FIXTURES / "scanme.xml").read_bytes()

    resp = await anon_client.post(
        _ips_url(pid, "/import"),
        params={"mode": "insert"},
        files={"report": ("scan.xml", xml, "application/xml")},
        headers=headers,
    )

    assert resp.status_code == 201
    assert resp.json() == {"created": ["45.33.32.156"], "updated": [], "unchanged": []}


async def test_list_and_get_ip_shape(anon_client: AsyncClient, session: AsyncSession) -> None:
    headers = await _headers(session, "admin")
    pid = await _project(anon_client, headers)
    xml = (_FIXTURES / "scanme.xml").read_bytes()
    await anon_client.post(
        _ips_url(pid, "/import"),
        params={"mode": "insert"},
        files={"report": ("scan.xml", xml, "application/xml")},
        headers=headers,
    )

    listing = await anon_client.get(_ips_url(pid), headers=headers)
    assert listing.status_code == 200
    assert [row["ip"] for row in listing.json()] == ["45.33.32.156"]

    one = await anon_client.get(_ips_url(pid, "/45.33.32.156"), headers=headers)
    assert one.status_code == 200
    body = one.json()
    assert body["hostnames"] == ["scanme.nmap.org"]
    assert [p["number"] for p in body["ports"]] == [80]
    assert body["ports"][0]["product"] == "Apache httpd"


async def test_get_missing_ip_returns_404(anon_client: AsyncClient, session: AsyncSession) -> None:
    headers = await _headers(session, "admin")
    pid = await _project(anon_client, headers)

    resp = await anon_client.get(_ips_url(pid, "/10.0.0.1"), headers=headers)
    assert resp.status_code == 404


async def test_create_ips_structured(anon_client: AsyncClient, session: AsyncSession) -> None:
    headers = await _headers(session, "admin")
    pid = await _project(anon_client, headers)

    resp = await anon_client.post(
        _ips_url(pid),
        params={"mode": "insert"},
        json=[{"ip": "1.2.3.4", "endtime": 100, "ports": [{"number": 80, "service": "http"}]}],
        headers=headers,
    )

    assert resp.status_code == 201
    assert resp.json() == {"created": ["1.2.3.4"], "updated": [], "unchanged": []}


async def test_insert_reimport_reports_unchanged(
    anon_client: AsyncClient, session: AsyncSession
) -> None:
    headers = await _headers(session, "admin")
    pid = await _project(anon_client, headers)
    body = [{"ip": "1.2.3.4", "endtime": 100, "ports": [{"number": 80}]}]
    await anon_client.post(_ips_url(pid), params={"mode": "insert"}, json=body, headers=headers)

    resp = await anon_client.post(
        _ips_url(pid), params={"mode": "insert"}, json=body, headers=headers
    )
    assert resp.json() == {"created": [], "updated": [], "unchanged": ["1.2.3.4"]}


async def test_delete_ip_then_404(anon_client: AsyncClient, session: AsyncSession) -> None:
    headers = await _headers(session, "admin")
    pid = await _project(anon_client, headers)
    await anon_client.post(
        _ips_url(pid),
        params={"mode": "insert"},
        json=[{"ip": "1.2.3.4", "endtime": 100, "ports": [{"number": 80}]}],
        headers=headers,
    )

    assert (await anon_client.delete(_ips_url(pid, "/1.2.3.4"), headers=headers)).status_code == 204
    assert (await anon_client.get(_ips_url(pid, "/1.2.3.4"), headers=headers)).status_code == 404
    assert (await anon_client.delete(_ips_url(pid, "/1.2.3.4"), headers=headers)).status_code == 404


async def test_import_bad_xml_returns_400(anon_client: AsyncClient, session: AsyncSession) -> None:
    headers = await _headers(session, "admin")
    pid = await _project(anon_client, headers)

    resp = await anon_client.post(
        _ips_url(pid, "/import"),
        params={"mode": "insert"},
        files={"report": ("scan.xml", b"not xml at all", "application/xml")},
        headers=headers,
    )
    assert resp.status_code == 400


async def test_delete_all_ips_without_body(anon_client: AsyncClient, session: AsyncSession) -> None:
    headers = await _headers(session, "admin")
    pid = await _project(anon_client, headers)
    await anon_client.post(
        _ips_url(pid),
        params={"mode": "insert"},
        json=[
            {"ip": "1.1.1.1", "endtime": 100, "ports": [{"number": 80}]},
            {"ip": "2.2.2.2", "endtime": 100, "ports": [{"number": 80}]},
        ],
        headers=headers,
    )

    assert (await anon_client.delete(_ips_url(pid), headers=headers)).status_code == 204
    assert (await anon_client.get(_ips_url(pid), headers=headers)).json() == []


async def test_import_over_size_limit_returns_413(
    anon_client: AsyncClient, session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from falcoria_scanledger.config import get_app_settings

    monkeypatch.setattr(get_app_settings(), "max_report_bytes", 64)
    headers = await _headers(session, "admin")
    pid = await _project(anon_client, headers)

    resp = await anon_client.post(
        _ips_url(pid, "/import"),
        params={"mode": "insert"},
        files={"report": ("scan.xml", b"x" * 128, "application/xml")},
        headers=headers,
    )
    assert resp.status_code == 413


async def test_non_member_is_forbidden(anon_client: AsyncClient, session: AsyncSession) -> None:
    owner = await _headers(session, "owner")
    pid = await _project(anon_client, owner)
    outsider = await _headers(session, "outsider", is_admin=False)

    assert (await anon_client.get(_ips_url(pid), headers=outsider)).status_code == 403
