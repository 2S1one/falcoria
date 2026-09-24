"""The event feed against real commits: cursor paging and in-flight transactions."""

from uuid import UUID

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker
from sqlmodel.ext.asyncio.session import AsyncSession

from falcoria_contracts.enums import ImportMode
from falcoria_contracts.port import Port
from falcoria_scanledger.events.service import read_events
from falcoria_scanledger.ips.schemas import IPIn
from falcoria_scanledger.ips.service import create_ips
from falcoria_scanledger.projects.models import ProjectDB

pytestmark = pytest.mark.anyio

Sessions = async_sessionmaker[AsyncSession]


async def _project(sessions: Sessions, name: str = "p") -> UUID:
    async with sessions() as s:
        project = ProjectDB(name=name)
        s.add(project)
        await s.commit()
        assert project.id is not None
        return project.id


def _ipin(ip: str, port: int = 80) -> IPIn:
    return IPIn(ip=ip, ports=[Port(number=port)], endtime=100, scanned_ports=[(1, 65535)])


async def _import(sessions: Sessions, project_id: UUID, *ips: str) -> None:
    async with sessions() as s:
        await create_ips(s, project_id, [_ipin(ip) for ip in ips], ImportMode.REPLACE)
        await s.commit()


async def _read(sessions: Sessions, project_id: UUID, after: str = "0.0", limit: int = 100):
    async with sessions() as s:
        return await read_events(s, project_id, after, limit)


async def test_empty_feed_keeps_the_cursor(committing_sessions: Sessions) -> None:
    project_id = await _project(committing_sessions)
    page = await _read(committing_sessions, project_id, after="5.7")
    assert page.items == []
    assert page.next_cursor == "5.7"


async def test_cursor_returns_each_event_once(committing_sessions: Sessions) -> None:
    project_id = await _project(committing_sessions)
    await _import(committing_sessions, project_id, "192.0.2.1", "192.0.2.2")

    first = await _read(committing_sessions, project_id)
    assert sorted(e.ip for e in first.items) == ["192.0.2.1", "192.0.2.2"]

    await _import(committing_sessions, project_id, "192.0.2.3")
    second = await _read(committing_sessions, project_id, after=first.next_cursor)
    assert [e.ip for e in second.items] == ["192.0.2.3"]

    third = await _read(committing_sessions, project_id, after=second.next_cursor)
    assert third.items == []


async def test_limit_pages_through_one_import(committing_sessions: Sessions) -> None:
    project_id = await _project(committing_sessions)
    await _import(committing_sessions, project_id, "192.0.2.1", "192.0.2.2", "192.0.2.3")

    seen: list[str] = []
    cursor = "0.0"
    for _ in range(3):
        page = await _read(committing_sessions, project_id, after=cursor, limit=1)
        assert len(page.items) == 1
        seen.append(page.items[0].ip)
        cursor = page.next_cursor
    assert sorted(seen) == ["192.0.2.1", "192.0.2.2", "192.0.2.3"]
    assert (await _read(committing_sessions, project_id, after=cursor)).items == []


async def test_feed_is_scoped_to_the_project(committing_sessions: Sessions) -> None:
    a = await _project(committing_sessions, "a")
    b = await _project(committing_sessions, "b")
    await _import(committing_sessions, a, "192.0.2.1")
    await _import(committing_sessions, b, "192.0.2.2")
    assert [e.ip for e in (await _read(committing_sessions, a)).items] == ["192.0.2.1"]


async def test_running_import_holds_back_later_commits(committing_sessions: Sessions) -> None:
    project_id = await _project(committing_sessions)

    async with committing_sessions() as slow:
        await create_ips(slow, project_id, [_ipin("192.0.2.1")], ImportMode.REPLACE)
        await _import(committing_sessions, project_id, "192.0.2.2")

        held = await _read(committing_sessions, project_id)
        assert held.items == []
        assert held.next_cursor == "0.0"

        await slow.commit()

    page = await _read(committing_sessions, project_id)
    assert [e.ip for e in page.items] == ["192.0.2.1", "192.0.2.2"]
