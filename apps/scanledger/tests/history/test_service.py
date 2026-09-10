"""DB-backed coverage for history/service.py — list filters and bulk delete."""

from uuid import UUID, uuid4

import pytest
from sqlmodel.ext.asyncio.session import AsyncSession

from falcoria_contracts.enums import ImportMode, PortChangeType
from falcoria_contracts.port import Port
from falcoria_scanledger.history.service import delete_history, list_history
from falcoria_scanledger.ips.schemas import IPIn
from falcoria_scanledger.ips.service import create_ips
from falcoria_scanledger.projects.models import ProjectDB

pytestmark = pytest.mark.anyio


async def _project(session: AsyncSession, name: str = "p") -> UUID:
    project = ProjectDB(name=name)
    session.add(project)
    await session.flush()
    assert project.id is not None
    return project.id


def _ipin(
    ip: str, numbers: list[int], *, endtime: int, services: dict[int, str] | None = None
) -> IPIn:
    services = services or {}
    ports = [Port(number=n, service=services.get(n)) for n in numbers]
    return IPIn(ip=ip, ports=ports, endtime=endtime)


async def _seed_open(
    session: AsyncSession,
    pid: UUID,
    ip: str,
    numbers: list[int],
    *,
    endtime: int,
    scan_id: UUID | None = None,
) -> None:
    await create_ips(
        session, pid, [_ipin(ip, numbers, endtime=endtime)], ImportMode.INSERT, scan_id=scan_id
    )


async def test_list_newest_first_with_skip_and_limit(session: AsyncSession) -> None:
    pid = await _project(session)
    await _seed_open(session, pid, "1.1.1.1", [80], endtime=100)
    await _seed_open(session, pid, "2.2.2.2", [80], endtime=200)
    await _seed_open(session, pid, "3.3.3.3", [80], endtime=300)

    rows = await list_history(session, pid)
    assert [r.created_at for r in rows] == [300, 200, 100]

    page = await list_history(session, pid, skip=1, limit=1)
    assert [r.created_at for r in page] == [200]


async def test_filter_by_ip(session: AsyncSession) -> None:
    pid = await _project(session)
    await _seed_open(session, pid, "1.1.1.1", [80], endtime=100)
    await _seed_open(session, pid, "2.2.2.2", [80], endtime=100)

    rows = await list_history(session, pid, ip="2.2.2.2")
    assert {r.ip for r in rows} == {"2.2.2.2"}


async def test_filter_by_scan_id(session: AsyncSession) -> None:
    pid = await _project(session)
    sid = uuid4()
    await _seed_open(session, pid, "1.1.1.1", [80], endtime=100, scan_id=sid)
    await _seed_open(session, pid, "2.2.2.2", [80], endtime=100)

    tagged = await list_history(session, pid, scan_id=sid)
    assert {r.ip for r in tagged} == {"1.1.1.1"}
    assert {r.scan_id for r in tagged} == {sid}

    untagged = [r for r in await list_history(session, pid) if r.scan_id is None]
    assert {r.ip for r in untagged} == {"2.2.2.2"}


async def test_filter_by_change_type(session: AsyncSession) -> None:
    pid = await _project(session)
    await create_ips(
        session,
        pid,
        [_ipin("1.2.3.4", [80], endtime=100, services={80: "http"})],
        ImportMode.INSERT,
    )
    await create_ips(
        session,
        pid,
        [_ipin("1.2.3.4", [80], endtime=200, services={80: "https"})],
        ImportMode.UPDATE,
    )

    states = await list_history(session, pid, change_type=PortChangeType.STATE)
    services = await list_history(session, pid, change_type=PortChangeType.SERVICE)
    assert {r.new_value for r in states} == {"open"}
    assert {(r.old_value, r.new_value) for r in services} == {("http", "https")}


async def test_filter_by_since_until(session: AsyncSession) -> None:
    pid = await _project(session)
    await _seed_open(session, pid, "1.1.1.1", [80], endtime=100)
    await _seed_open(session, pid, "2.2.2.2", [80], endtime=200)
    await _seed_open(session, pid, "3.3.3.3", [80], endtime=300)

    rows = await list_history(session, pid, since=150, until=250)
    assert [r.created_at for r in rows] == [200]


async def test_delete_history_returns_count_and_is_project_scoped(session: AsyncSession) -> None:
    pid = await _project(session, "keep-none")
    other = await _project(session, "keep-all")
    await _seed_open(session, pid, "1.2.3.4", [80, 443], endtime=100)
    await _seed_open(session, other, "9.9.9.9", [80], endtime=100)

    deleted = await delete_history(session, pid)

    assert deleted == 2
    assert await list_history(session, pid) == []
    assert len(await list_history(session, other)) == 1


async def test_reimport_with_new_scan_id_keeps_the_original_row(session: AsyncSession) -> None:
    pid = await _project(session)
    first, second = uuid4(), uuid4()
    ranges = [(1, 1024)]

    # t=100: port 80 opens, attributed to `first`.
    await create_ips(
        session,
        pid,
        [IPIn(ip="1.2.3.4", ports=[Port(number=80)], endtime=100, scanned_ports=ranges)],
        ImportMode.REPLACE,
        scan_id=first,
    )
    # t=150: port 80 closes, so a re-import at t=100 regenerates the open row.
    await create_ips(
        session,
        pid,
        [IPIn(ip="1.2.3.4", ports=[], endtime=150, scanned_ports=ranges)],
        ImportMode.REPLACE,
    )
    # t=100 re-imported under a different scan_id — same history key, ON CONFLICT DO NOTHING.
    await create_ips(
        session,
        pid,
        [IPIn(ip="1.2.3.4", ports=[Port(number=80)], endtime=100, scanned_ports=ranges)],
        ImportMode.REPLACE,
        scan_id=second,
    )

    opens = [
        r
        for r in await list_history(session, pid)
        if r.port == 80 and r.change_type == PortChangeType.STATE and r.new_value == "open"
    ]
    assert len(opens) == 1
    assert opens[0].scan_id == first
