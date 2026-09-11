"""DB-backed coverage for ips/search.py + service.search_ips."""

from collections.abc import Sequence
from typing import Any
from uuid import UUID

import pytest
from httpx import AsyncClient
from sqlmodel.ext.asyncio.session import AsyncSession

from falcoria_contracts.enums import PortProtocol
from falcoria_scanledger.auth import service as auth_service
from falcoria_scanledger.auth.schemas import UserCreate
from falcoria_scanledger.ips.models import IPDB, ObservedHostnameDB, PortDB
from falcoria_scanledger.ips.search import IPFilter, IPSearchRequest, PortClause, PortGroups
from falcoria_scanledger.ips.service import search_ips
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
    first_seen: int = 100,
    last_seen: int = 100,
    hostnames: Sequence[str] = (),
    ports: Sequence[dict[str, Any]] = (),
) -> None:
    hn = [ObservedHostnameDB(hostname=h, project_id=project_id) for h in hostnames]
    for obj in hn:
        session.add(obj)
    if hn:
        await session.flush()
    session.add(
        IPDB(
            ip=ip,
            os=os,
            first_seen=first_seen,
            last_seen=last_seen,
            project_id=project_id,
            ports=[PortDB(**p) for p in ports],
            hostnames=hn,
        )
    )
    await session.flush()


@pytest.fixture
async def seeded(session: AsyncSession) -> tuple[UUID, UUID]:
    pid = await _project(session, "main")
    other = await _project(session, "other")

    await _seed_ip(
        session,
        pid,
        "10.1.0.1",
        os="Linux 5.15",
        hostnames=["web-dev-01.corp.example.com"],
        ports=[
            _p(80, service="http", product="Apache httpd", version="2.4.49"),
            _p(443, service="https", product="nginx", tunnel="ssl"),
        ],
    )
    await _seed_ip(
        session,
        pid,
        "10.1.0.2",
        os="Windows Server 2019",
        hostnames=["dc01.corp.example.com"],
        ports=[
            _p(139, service="netbios-ssn"),
            _p(445, service="microsoft-ds"),
            _p(3389, service="ms-wbt-server"),
        ],
    )
    await _seed_ip(
        session,
        pid,
        "10.1.0.3",
        ports=[_p(22, service="ssh", product="OpenSSH", version="8.9p1")],
    )
    await _seed_ip(
        session,
        pid,
        "10.1.0.4",
        os="Linux",
        hostnames=["staging-api"],
        ports=[
            _p(22, service="ssh", product="Dropbear sshd"),
            _p(8443, service="http", product="nginx"),
        ],
    )
    await _seed_ip(
        session,
        pid,
        "10.1.0.5",
        hostnames=["prod-db-01"],
        ports=[_p(5432, service="postgresql", product="PostgreSQL"), _p(9000, service="http")],
    )
    await _seed_ip(
        session,
        pid,
        "10.1.0.6",
        os="Linux",
        ports=[_p(443, service="https", product="nginx", tunnel="ssl")],
    )
    await _seed_ip(
        session,
        pid,
        "10.1.0.7",
        ports=[_p(9999), _p(80, service="http", product="Apache httpd", version="2.4.58")],
    )
    await _seed_ip(session, pid, "10.1.0.8", ports=[_p(8080, service="http", product="lighttpd")])
    await _seed_ip(
        session, pid, "10.1.0.9", os="Linux", ports=[_p(8883, service="mqtt", tunnel="ssl")]
    )
    await _seed_ip(
        session,
        pid,
        "10.1.0.10",
        first_seen=9000,
        last_seen=9000,
        ports=[_p(80, service="http", product="nginx")],
    )
    await _seed_ip(
        session,
        pid,
        "10.2.0.1",
        os="Linux",
        hostnames=["other-net"],
        ports=[_p(80, service="http", product="nginx")],
    )

    await _seed_ip(session, other, "192.0.2.1", ports=[_p(3389, service="ms-wbt-server")])
    return pid, other


def _req(f: IPFilter, *, matched_ports_only: bool = False) -> IPSearchRequest:
    return IPSearchRequest(filter=f, matched_ports_only=matched_ports_only)


async def _ips(session: AsyncSession, pid: UUID, f: IPFilter) -> set[str]:
    result = await search_ips(session, pid, _req(f))
    return {item.ip for item in result.items}


async def test_empty_filter_returns_the_whole_project(
    session: AsyncSession, seeded: tuple[UUID, UUID]
) -> None:
    pid, _ = seeded
    result = await search_ips(session, pid, IPSearchRequest())

    assert result.total == 11
    assert len(result.items) == 11
    assert "192.0.2.1" not in {i.ip for i in result.items}


async def test_cidr(session: AsyncSession, seeded: tuple[UUID, UUID]) -> None:
    pid, _ = seeded
    got = await _ips(session, pid, IPFilter(cidr="10.1.0.0/16"))

    assert got == {f"10.1.0.{n}" for n in range(1, 11)}


async def test_cidr_is_normalised(session: AsyncSession, seeded: tuple[UUID, UUID]) -> None:
    pid, _ = seeded
    got = await _ips(session, pid, IPFilter(cidr="10.1.0.55/24"))

    assert "10.1.0.1" in got
    assert "10.2.0.1" not in got


async def test_ip_in_matches_exact_set(session: AsyncSession, seeded: tuple[UUID, UUID]) -> None:
    pid, _ = seeded
    got = await _ips(session, pid, IPFilter(ip_in=["10.1.0.1", "10.1.0.3", "10.9.9.9"]))

    assert got == {"10.1.0.1", "10.1.0.3"}


async def test_ip_in_is_project_scoped(session: AsyncSession, seeded: tuple[UUID, UUID]) -> None:
    pid, _ = seeded
    got = await _ips(session, pid, IPFilter(ip_in=["10.1.0.1", "192.0.2.1"]))

    assert got == {"10.1.0.1"}


def test_ip_in_rejects_malformed_ip() -> None:
    with pytest.raises(ValueError, match="does not appear to be"):
        IPFilter(ip_in=["not-an-ip"])


async def test_os_ilike(session: AsyncSession, seeded: tuple[UUID, UUID]) -> None:
    pid, _ = seeded
    assert await _ips(session, pid, IPFilter(os_ilike="windows")) == {"10.1.0.2"}


async def test_hostname_ilike_any(session: AsyncSession, seeded: tuple[UUID, UUID]) -> None:
    pid, _ = seeded
    got = await _ips(session, pid, IPFilter(hostname_ilike_any=["dev", "staging"]))

    assert got == {"10.1.0.1", "10.1.0.4"}


async def test_has_hostname_false(session: AsyncSession, seeded: tuple[UUID, UUID]) -> None:
    pid, _ = seeded
    got = await _ips(session, pid, IPFilter(has_hostname=False))

    assert got == {"10.1.0.3", "10.1.0.6", "10.1.0.7", "10.1.0.8", "10.1.0.9", "10.1.0.10"}


async def test_time_range(session: AsyncSession, seeded: tuple[UUID, UUID]) -> None:
    pid, _ = seeded
    assert await _ips(session, pid, IPFilter(first_seen_gte=9000)) == {"10.1.0.10"}
    assert "10.1.0.10" not in await _ips(session, pid, IPFilter(last_seen_lt=9000))


async def test_port_number_exact(session: AsyncSession, seeded: tuple[UUID, UUID]) -> None:
    pid, _ = seeded
    f = IPFilter(ports=PortGroups(all_of=[PortClause(number=3389)]))

    assert await _ips(session, pid, f) == {"10.1.0.2"}


async def test_port_number_in(session: AsyncSession, seeded: tuple[UUID, UUID]) -> None:
    pid, _ = seeded
    f = IPFilter(ports=PortGroups(all_of=[PortClause(number_in=[139, 445])]))

    assert await _ips(session, pid, f) == {"10.1.0.2"}


async def test_same_port_and_semantics(session: AsyncSession, seeded: tuple[UUID, UUID]) -> None:
    pid, _ = seeded
    f = IPFilter(
        ports=PortGroups(
            all_of=[PortClause(service_ilike="http", number_not_in=[80, 443, 8080, 8443])]
        )
    )
    got = await _ips(session, pid, f)

    # 10.1.0.5 has 9000/http. 10.1.0.7 has http on 80 AND a port 9999, but no single
    # port that is both http and non-standard -> it must not match.
    assert got == {"10.1.0.5"}


async def test_product_not_in_keeps_null_product(
    session: AsyncSession, seeded: tuple[UUID, UUID]
) -> None:
    pid, _ = seeded
    f = IPFilter(
        ports=PortGroups(
            all_of=[PortClause(service_ilike="http", product_not_in=["nginx", "Apache httpd"])]
        )
    )
    got = await _ips(session, pid, f)

    # 10.1.0.5: 9000/http with no product -> kept. 10.1.0.8: 8080/http/lighttpd -> kept.
    assert got == {"10.1.0.5", "10.1.0.8"}


async def test_product_not_ilike_excludes_match_keeps_null(
    session: AsyncSession, seeded: tuple[UUID, UUID]
) -> None:
    pid, _ = seeded
    f = IPFilter(
        ports=PortGroups(all_of=[PortClause(service_in=["ssh"], product_not_ilike="OpenSSH")])
    )
    got = await _ips(session, pid, f)

    assert got == {"10.1.0.4"}  # Dropbear, not OpenSSH


async def test_version_ilike_is_a_text_match(
    session: AsyncSession, seeded: tuple[UUID, UUID]
) -> None:
    pid, _ = seeded
    f = IPFilter(
        ports=PortGroups(all_of=[PortClause(product_in=["Apache httpd"], version_ilike="2.4.4")])
    )
    got = await _ips(session, pid, f)

    assert got == {"10.1.0.1"}  # 2.4.49 contains "2.4.4"; 2.4.58 does not


async def test_tunnel_and_number_not_in(session: AsyncSession, seeded: tuple[UUID, UUID]) -> None:
    pid, _ = seeded
    f = IPFilter(ports=PortGroups(all_of=[PortClause(tunnel="ssl", number_not_in=[443])]))

    assert await _ips(session, pid, f) == {"10.1.0.9"}  # mqtt over ssl on 8883


async def test_none_of_negated_exists(session: AsyncSession, seeded: tuple[UUID, UUID]) -> None:
    pid, _ = seeded
    f = IPFilter(
        ports=PortGroups(
            all_of=[PortClause(number=443)],
            none_of=[PortClause(number=80)],
        )
    )
    got = await _ips(session, pid, f)

    # 443 present, 80 absent: 10.1.0.6 (443 only). 10.1.0.1 has both -> excluded.
    assert got == {"10.1.0.6"}


async def test_any_of_ors_two_port_shapes(session: AsyncSession, seeded: tuple[UUID, UUID]) -> None:
    pid, _ = seeded
    f = IPFilter(
        ports=PortGroups(
            any_of=[
                PortClause(number=443, product_ilike="nginx"),
                PortClause(service_ilike="http", number_not_in=[80, 443, 8080, 8443]),
            ]
        )
    )
    got = await _ips(session, pid, f)

    # nginx-on-443: .1 .6 ; http-on-odd-port: .5 (9000)
    assert got == {"10.1.0.1", "10.1.0.6", "10.1.0.5"}


async def test_matched_ports_only_trims_the_ports(
    session: AsyncSession, seeded: tuple[UUID, UUID]
) -> None:
    pid, _ = seeded
    f = IPFilter(ports=PortGroups(all_of=[PortClause(number=443)]))

    full = await search_ips(session, pid, _req(f))
    trimmed = await search_ips(session, pid, _req(f, matched_ports_only=True))

    one = next(i for i in full.items if i.ip == "10.1.0.1")
    assert [p.number for p in one.ports] == [80, 443]

    one_trimmed = next(i for i in trimmed.items if i.ip == "10.1.0.1")
    assert [p.number for p in one_trimmed.ports] == [443]


async def test_ordering_is_numeric_not_lexical(
    session: AsyncSession, seeded: tuple[UUID, UUID]
) -> None:
    pid, _ = seeded
    result = await search_ips(session, pid, IPSearchRequest())
    order = [i.ip for i in result.items]

    assert order.index("10.1.0.2") < order.index("10.1.0.10")


async def test_pagination_and_total(session: AsyncSession, seeded: tuple[UUID, UUID]) -> None:
    pid, _ = seeded
    page = await search_ips(session, pid, IPSearchRequest(skip=2, limit=3))

    assert page.total == 11
    assert len(page.items) == 3


async def test_search_is_project_scoped(session: AsyncSession, seeded: tuple[UUID, UUID]) -> None:
    _, other = seeded
    f = IPFilter(ports=PortGroups(all_of=[PortClause(number=3389)]))

    assert await _ips(session, other, f) == {"192.0.2.1"}


async def _headers(session: AsyncSession, username: str) -> dict[str, str]:
    _, token = await auth_service.create_user(session, UserCreate(username=username, is_admin=True))
    return {"Authorization": f"Bearer {token}"}


async def test_router_search_returns_items_and_total(
    anon_client: AsyncClient, session: AsyncSession
) -> None:
    headers = await _headers(session, "admin")
    pid = (await anon_client.post("/api/projects", json={"name": "p"}, headers=headers)).json()[
        "id"
    ]
    await _seed_ip(session, UUID(pid), "10.9.0.1", ports=[_p(3389, service="ms-wbt-server")])

    resp = await anon_client.post(
        f"/api/projects/{pid}/ips/search",
        json={"filter": {"ports": {"all_of": [{"number": 3389}]}}},
        headers=headers,
    )

    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 1
    assert [i["ip"] for i in body["items"]] == ["10.9.0.1"]


async def test_router_search_rejects_bad_cidr(
    anon_client: AsyncClient, session: AsyncSession
) -> None:
    headers = await _headers(session, "admin")
    pid = (await anon_client.post("/api/projects", json={"name": "p"}, headers=headers)).json()[
        "id"
    ]

    resp = await anon_client.post(
        f"/api/projects/{pid}/ips/search",
        json={"filter": {"cidr": "not-a-cidr"}},
        headers=headers,
    )

    assert resp.status_code == 422
