"""DB-backed coverage for ips/facets.py + service.get_facets."""

from collections.abc import Sequence
from typing import Any
from uuid import UUID

import pytest
from httpx import AsyncClient
from sqlmodel.ext.asyncio.session import AsyncSession

from falcoria_contracts.enums import PortProtocol
from falcoria_scanledger.auth import service as auth_service
from falcoria_scanledger.auth.schemas import UserCreate
from falcoria_scanledger.ips.facets import FacetsRequest, FacetsResult, FacetValue
from falcoria_scanledger.ips.models import IPDB, PortDB
from falcoria_scanledger.ips.search import IPFilter, PortClause, PortGroups
from falcoria_scanledger.ips.service import get_facets
from falcoria_scanledger.projects.models import ProjectDB

pytestmark = pytest.mark.anyio


async def _project(session: AsyncSession, name: str) -> UUID:
    project = ProjectDB(name=name)
    session.add(project)
    await session.flush()
    assert project.id is not None
    return project.id


def _p(
    number: int,
    *,
    service: str | None = None,
    product: str | None = None,
    version: str | None = None,
    tunnel: str | None = None,
) -> dict[str, Any]:
    return {
        "number": number,
        "protocol": PortProtocol.TCP,
        "service": service,
        "product": product,
        "version": version,
        "tunnel": tunnel,
    }


async def _seed_ip(
    session: AsyncSession,
    project_id: UUID,
    ip: str,
    *,
    os: str | None = None,
    ports: Sequence[dict[str, Any]] = (),
) -> None:
    session.add(
        IPDB(
            ip=ip,
            os=os,
            first_seen=100,
            last_seen=100,
            project_id=project_id,
            ports=[PortDB(**p) for p in ports],
        )
    )
    await session.flush()


def _pairs(facet: list[FacetValue]) -> list[tuple[str | None, int]]:
    return [(v.value, v.count) for v in facet]


@pytest.fixture
async def seeded(session: AsyncSession) -> tuple[UUID, UUID]:
    pid = await _project(session, "main")
    other = await _project(session, "other")

    await _seed_ip(
        session,
        pid,
        "10.0.0.1",
        os="Linux 5.15",
        ports=[
            _p(80, service="http", product="nginx"),
            _p(8080, service="http"),  # same service, same host -> counted once
            _p(22, service="ssh", product="OpenSSH"),
        ],
    )
    await _seed_ip(
        session,
        pid,
        "10.0.0.2",
        os="Linux",
        ports=[
            _p(80, service="http", product="nginx"),
            _p(443, service="https", product="nginx", tunnel="ssl"),
        ],
    )
    await _seed_ip(
        session,
        pid,
        "10.0.0.3",
        os="Windows Server 2019",
        ports=[_p(3389, service="ms-wbt-server")],
    )
    await _seed_ip(session, pid, "10.0.0.4", os="Linux")  # no open ports
    await _seed_ip(session, pid, "10.0.0.5", ports=[_p(21)])  # null service / product

    await _seed_ip(session, other, "192.0.2.9", ports=[_p(80, service="http")])
    return pid, other


async def test_overview_counts_distinct_hosts_per_value(
    session: AsyncSession, seeded: tuple[UUID, UUID]
) -> None:
    pid, _ = seeded
    result = await get_facets(session, pid, FacetsRequest())

    # http on two ports of 10.0.0.1 counts that host once.
    assert _pairs(result.service) == [
        ("http", 2),
        ("https", 1),
        ("ms-wbt-server", 1),
        ("ssh", 1),
        (None, 1),
    ]
    assert _pairs(result.port) == [
        ("80", 2),
        ("21", 1),
        ("22", 1),
        ("443", 1),
        ("3389", 1),
        ("8080", 1),
    ]
    assert _pairs(result.protocol) == [("tcp", 4)]  # 10.0.0.4 has no ports
    # 10.0.0.2 has both a null-tunnel port (80) and an ssl port (443).
    assert _pairs(result.tunnel) == [(None, 4), ("ssl", 1)]
    assert _pairs(result.version) == [(None, 4)]


async def test_a_host_lands_in_every_bucket_it_has_a_port_for(
    session: AsyncSession, seeded: tuple[UUID, UUID]
) -> None:
    pid, _ = seeded
    result = await get_facets(session, pid, FacetsRequest())

    # 10.0.0.1 has an nginx port, an OpenSSH port, and null-product ports.
    assert _pairs(result.product) == [(None, 3), ("nginx", 2), ("OpenSSH", 1)]


async def test_os_facet_includes_port_less_hosts(
    session: AsyncSession, seeded: tuple[UUID, UUID]
) -> None:
    pid, _ = seeded
    result = await get_facets(session, pid, FacetsRequest())

    # 10.0.0.4 (Linux, no ports) is counted here but nowhere port-level.
    assert _pairs(result.os) == [
        ("Linux", 2),
        ("Linux 5.15", 1),
        ("Windows Server 2019", 1),
        (None, 1),
    ]


async def test_filter_restricts_the_host_population(
    session: AsyncSession, seeded: tuple[UUID, UUID]
) -> None:
    pid, _ = seeded
    result = await get_facets(session, pid, FacetsRequest(filter=IPFilter(os_ilike="linux")))

    # Matched: 10.0.0.1, 10.0.0.2, 10.0.0.4 — no null-service host, no Windows host.
    assert _pairs(result.service) == [("http", 2), ("https", 1), ("ssh", 1)]
    assert _pairs(result.os) == [("Linux", 2), ("Linux 5.15", 1)]


async def test_matched_hosts_contribute_their_full_inventory(
    session: AsyncSession, seeded: tuple[UUID, UUID]
) -> None:
    pid, _ = seeded
    f = IPFilter(ports=PortGroups(all_of=[PortClause(service_ilike="http")]))

    result = await get_facets(session, pid, FacetsRequest(filter=f))

    # Filter picks 10.0.0.1 + 10.0.0.2 (both have an http port); the service facet
    # then also shows the ssh / https those hosts run.
    pairs = _pairs(result.service)
    assert ("http", 2) in pairs
    assert ("ssh", 1) in pairs
    assert ("https", 1) in pairs


async def test_limit_caps_each_facet(session: AsyncSession, seeded: tuple[UUID, UUID]) -> None:
    pid, _ = seeded
    result = await get_facets(session, pid, FacetsRequest(limit=2))

    assert _pairs(result.service) == [("http", 2), ("https", 1)]
    assert len(result.port) == 2


async def test_facets_are_project_scoped(session: AsyncSession, seeded: tuple[UUID, UUID]) -> None:
    _, other = seeded
    result = await get_facets(session, other, FacetsRequest())

    assert _pairs(result.service) == [("http", 1)]


async def test_empty_project_yields_empty_facets(session: AsyncSession) -> None:
    pid = await _project(session, "empty")

    result = await get_facets(session, pid, FacetsRequest())

    assert result == FacetsResult(
        port=[], protocol=[], service=[], product=[], version=[], tunnel=[], os=[]
    )


async def _headers(session: AsyncSession, username: str) -> dict[str, str]:
    _, token = await auth_service.create_user(session, UserCreate(username=username, is_admin=True))
    return {"Authorization": f"Bearer {token}"}


async def test_router_facets_shape_and_filter(
    anon_client: AsyncClient, session: AsyncSession
) -> None:
    headers = await _headers(session, "admin")
    pid = (await anon_client.post("/api/projects", json={"name": "p"}, headers=headers)).json()[
        "id"
    ]
    await _seed_ip(session, UUID(pid), "10.5.0.1", os="Linux", ports=[_p(80, service="http")])

    resp = await anon_client.post(f"/api/projects/{pid}/ips/facets", json={}, headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert set(body) == {"port", "protocol", "service", "product", "version", "tunnel", "os"}
    assert body["service"] == [{"value": "http", "count": 1}]
    assert body["port"] == [{"value": "80", "count": 1}]
    assert body["os"] == [{"value": "Linux", "count": 1}]

    filtered = await anon_client.post(
        f"/api/projects/{pid}/ips/facets",
        json={"filter": {"os_ilike": "windows"}},
        headers=headers,
    )
    assert filtered.status_code == 200
    assert filtered.json()["service"] == []
