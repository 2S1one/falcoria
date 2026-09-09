"""DB-backed coverage for ips/service.py — the import transaction boundary."""

from pathlib import Path
from uuid import UUID

import pytest
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from falcoria_contracts.enums import ImportMode, PortChangeType, PortProtocol, PortState
from falcoria_contracts.port import Port
from falcoria_scanledger.history.models import IPPortHistoryDB
from falcoria_scanledger.ips.models import (
    IPDB,
    ObservedHostnameDB,
    ObservedHostnameIPLink,
    PortDB,
)
from falcoria_scanledger.ips.schemas import IPIn
from falcoria_scanledger.ips.service import create_ips, import_scan
from falcoria_scanledger.projects.models import ProjectDB

pytestmark = pytest.mark.anyio

_FIXTURES = Path(__file__).parent.parent / "fixtures" / "nmap"


async def _project(session: AsyncSession, name: str = "p") -> UUID:
    project = ProjectDB(name=name)
    session.add(project)
    await session.flush()
    assert project.id is not None
    return project.id


def _port(
    number: int,
    *,
    state: PortState = PortState.OPEN,
    service: str | None = None,
    product: str | None = None,
) -> Port:
    return Port(number=number, state=state, service=service, product=product)


def _ipin(
    ip: str,
    ports: list[Port],
    *,
    endtime: int = 100,
    hostnames: list[str] | None = None,
    scanned_ports: list[tuple[int, int]] | None = None,
) -> IPIn:
    return IPIn(
        ip=ip,
        ports=ports,
        endtime=endtime,
        hostnames=hostnames or [],
        scanned_ports=scanned_ports or [],
    )


async def _ipdb(session: AsyncSession, project_id: UUID, ip: str) -> IPDB:
    return (
        await session.exec(select(IPDB).where(IPDB.project_id == project_id, IPDB.ip == ip))
    ).one()


async def _ports_of(session: AsyncSession, ip_id: int) -> dict[int, PortDB]:
    rows = (await session.exec(select(PortDB).where(PortDB.ip_id == ip_id))).all()
    return {p.number: p for p in rows}


async def _history(session: AsyncSession, project_id: UUID) -> list[IPPortHistoryDB]:
    return list(
        (
            await session.exec(
                select(IPPortHistoryDB).where(IPPortHistoryDB.project_id == project_id)
            )
        ).all()
    )


async def _hostnames_of(session: AsyncSession, ipdb: IPDB) -> set[str]:
    links = (
        await session.exec(
            select(ObservedHostnameIPLink).where(ObservedHostnameIPLink.ip_id == ipdb.id)
        )
    ).all()
    out: set[str] = set()
    for link in links:
        row = await session.get(ObservedHostnameDB, link.hostname_id)
        assert row is not None
        out.add(row.hostname)
    return out


async def test_import_scan_creates_ip_ports_hostnames_history(session: AsyncSession) -> None:
    pid = await _project(session)
    xml = (_FIXTURES / "scanme.xml").read_text(encoding="utf-8")

    changesets = await import_scan(session, pid, xml, ImportMode.INSERT)

    assert [cs.ip for cs in changesets] == ["45.33.32.156"]
    ipdb = await _ipdb(session, pid, "45.33.32.156")
    assert ipdb.id is not None
    ports = await _ports_of(session, ipdb.id)
    assert set(ports) == {80}
    assert ports[80].product == "Apache httpd"
    assert ports[80].protocol == PortProtocol.TCP
    assert await _hostnames_of(session, ipdb) == {"scanme.nmap.org"}

    hist = await _history(session, pid)
    assert {(h.port, h.change_type, h.new_value) for h in hist} == {
        (80, PortChangeType.STATE, "open")
    }


async def test_reimport_same_report_is_idempotent(session: AsyncSession) -> None:
    pid = await _project(session)
    xml = (_FIXTURES / "scanme.xml").read_text(encoding="utf-8")

    await import_scan(session, pid, xml, ImportMode.REPLACE)
    after_first = len(await _history(session, pid))
    await import_scan(session, pid, xml, ImportMode.REPLACE)

    assert len(await _history(session, pid)) == after_first
    ipdb = await _ipdb(session, pid, "45.33.32.156")
    assert ipdb.id is not None
    assert set(await _ports_of(session, ipdb.id)) == {80}


async def test_replace_closes_stale_port(session: AsyncSession) -> None:
    pid = await _project(session)
    await create_ips(
        session,
        pid,
        [_ipin("1.2.3.4", [_port(22), _port(80, service="http")], scanned_ports=[(1, 1024)])],
        ImportMode.INSERT,
    )

    await create_ips(
        session,
        pid,
        # a later scan — distinct endtime so the close history row does not
        # collide with the open row on the (…, change_type, created_at) key.
        [_ipin("1.2.3.4", [_port(80, service="http")], endtime=200, scanned_ports=[(1, 1024)])],
        ImportMode.REPLACE,
    )

    ipdb = await _ipdb(session, pid, "1.2.3.4")
    assert ipdb.id is not None
    assert set(await _ports_of(session, ipdb.id)) == {80}  # 22 deleted

    closed = [h for h in await _history(session, pid) if h.port == 22 and h.new_value == "closed"]
    assert len(closed) == 1
    assert closed[0].old_value == "open"


async def test_update_refreshes_service_field_and_records_history(session: AsyncSession) -> None:
    pid = await _project(session)
    await create_ips(
        session,
        pid,
        [_ipin("1.2.3.4", [_port(80, service="http", product="nginx")])],
        ImportMode.INSERT,
    )
    await create_ips(
        session,
        pid,
        [_ipin("1.2.3.4", [_port(80, service="http", product="Apache")])],
        ImportMode.UPDATE,
    )

    ipdb = await _ipdb(session, pid, "1.2.3.4")
    assert ipdb.id is not None
    assert (await _ports_of(session, ipdb.id))[80].product == "Apache"

    assert any(
        h.port == 80
        and h.change_type == PortChangeType.PRODUCT
        and h.old_value == "nginx"
        and h.new_value == "Apache"
        for h in await _history(session, pid)
    )


async def test_insert_existing_merges_hostnames_only(session: AsyncSession) -> None:
    pid = await _project(session)
    await create_ips(
        session, pid, [_ipin("1.2.3.4", [_port(80)], hostnames=["a"])], ImportMode.INSERT
    )
    await create_ips(
        session,
        pid,
        [_ipin("1.2.3.4", [_port(443)], hostnames=["a", "b"])],
        ImportMode.INSERT,
    )

    ipdb = await _ipdb(session, pid, "1.2.3.4")
    assert ipdb.id is not None
    assert set(await _ports_of(session, ipdb.id)) == {80}  # 443 not added
    assert await _hostnames_of(session, ipdb) == {"a", "b"}


async def test_hostname_shared_across_ips_reuses_one_row(session: AsyncSession) -> None:
    pid = await _project(session)
    await create_ips(
        session,
        pid,
        [
            _ipin("1.1.1.1", [_port(80)], hostnames=["shared.example"]),
            _ipin("2.2.2.2", [_port(80)], hostnames=["shared.example"]),
        ],
        ImportMode.INSERT,
    )

    names = (
        await session.exec(select(ObservedHostnameDB).where(ObservedHostnameDB.project_id == pid))
    ).all()
    assert len(names) == 1
    assert await _hostnames_of(session, await _ipdb(session, pid, "1.1.1.1")) == {"shared.example"}
    assert await _hostnames_of(session, await _ipdb(session, pid, "2.2.2.2")) == {"shared.example"}


async def test_track_history_false_writes_no_history(session: AsyncSession) -> None:
    pid = await _project(session)
    await create_ips(
        session,
        pid,
        [_ipin("1.2.3.4", [_port(80)])],
        ImportMode.INSERT,
        track_history=False,
    )
    assert await _history(session, pid) == []
