"""DB-backed coverage for outbox writes made by the import transaction."""

from uuid import UUID, uuid4

import pytest
from sqlalchemy import text
from sqlmodel import col, select
from sqlmodel.ext.asyncio.session import AsyncSession

from falcoria_contracts.enums import ImportMode
from falcoria_contracts.port import Port
from falcoria_scanledger.events.models import OutboxEventDB
from falcoria_scanledger.events.schemas import IPChangedEvent
from falcoria_scanledger.ips.schemas import IPIn
from falcoria_scanledger.ips.service import create_ips
from falcoria_scanledger.projects.models import ProjectDB

pytestmark = pytest.mark.anyio


async def _project(session: AsyncSession) -> UUID:
    project = ProjectDB(name="p")
    session.add(project)
    await session.flush()
    assert project.id is not None
    return project.id


def _ipin(ip: str, ports: list[int], hostnames: list[str] | None = None) -> IPIn:
    return IPIn(
        ip=ip,
        ports=[Port(number=n) for n in ports],
        endtime=100,
        hostnames=hostnames or [],
        scanned_ports=[(1, 65535)],
    )


async def _events(session: AsyncSession) -> list[IPChangedEvent]:
    rows = (await session.exec(select(OutboxEventDB).order_by(col(OutboxEventDB.id)))).all()
    return [IPChangedEvent.model_validate(r.payload) for r in rows]


async def test_import_writes_one_event_per_changed_ip(session: AsyncSession) -> None:
    project_id = await _project(session)
    scan_id = uuid4()
    await create_ips(
        session,
        project_id,
        [_ipin("192.0.2.1", [80]), _ipin("192.0.2.2", [443], ["a.example"])],
        ImportMode.REPLACE,
        scan_id=scan_id,
    )
    events = await _events(session)
    assert sorted(e.ip for e in events) == ["192.0.2.1", "192.0.2.2"]
    assert all(e.project_id == project_id and e.scan_id == scan_id for e in events)


async def test_unchanged_reimport_writes_no_event(session: AsyncSession) -> None:
    project_id = await _project(session)
    await create_ips(session, project_id, [_ipin("192.0.2.1", [80])], ImportMode.REPLACE)
    await create_ips(session, project_id, [_ipin("192.0.2.1", [80])], ImportMode.REPLACE)
    assert len(await _events(session)) == 1


async def test_rescan_event_carries_old_and_new_state(session: AsyncSession) -> None:
    project_id = await _project(session)
    await create_ips(session, project_id, [_ipin("192.0.2.1", [80, 22])], ImportMode.REPLACE)
    await create_ips(session, project_id, [_ipin("192.0.2.1", [80, 443])], ImportMode.REPLACE)
    last = (await _events(session))[-1]
    assert [p.number for p in last.ports.old] == [22, 80]
    assert [p.number for p in last.ports.added] == [443]
    assert [p.number for p in last.ports.removed] == [22]


async def test_events_written_even_without_history(session: AsyncSession) -> None:
    project_id = await _project(session)
    await create_ips(
        session, project_id, [_ipin("192.0.2.1", [80])], ImportMode.REPLACE, track_history=False
    )
    assert len(await _events(session)) == 1


async def test_txid_is_filled_by_the_database(session: AsyncSession) -> None:
    project_id = await _project(session)
    await create_ips(session, project_id, [_ipin("192.0.2.1", [80])], ImportMode.REPLACE)
    connection = await session.connection()
    txids = (await connection.execute(text("SELECT txid::text FROM outbox_events"))).all()
    assert len(txids) == 1
    assert txids[0][0]
