"""Import-pipeline transaction boundary: collect -> dedup -> reconcile -> apply."""

from uuid import UUID

from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import selectinload
from sqlmodel import col, select
from sqlmodel.ext.asyncio.session import AsyncSession

from falcoria_contracts.enums import ImportMode
from falcoria_contracts.port import Port
from falcoria_scanledger.history.models import IPPortHistoryDB
from falcoria_scanledger.ips.dedup import dedup_batch
from falcoria_scanledger.ips.models import IPDB, ObservedHostnameDB, PortDB
from falcoria_scanledger.ips.modes import apply_mode
from falcoria_scanledger.ips.nmap import parse_report
from falcoria_scanledger.ips.schemas import ChangeSet, IPIn, StoredIP


async def import_scan(
    session: AsyncSession,
    project_id: UUID,
    xml: str | bytes,
    mode: ImportMode,
    *,
    track_history: bool = True,
) -> list[ChangeSet]:
    """Parse an nmap XML report and merge it into the project under `mode`."""
    return await apply_import(
        session, project_id, parse_report(xml), mode, track_history=track_history
    )


async def create_ips(
    session: AsyncSession,
    project_id: UUID,
    entries: list[IPIn],
    mode: ImportMode,
    *,
    track_history: bool = True,
) -> list[ChangeSet]:
    """Merge a structured list of IPIn entries into the project under `mode`."""
    return await apply_import(session, project_id, entries, mode, track_history=track_history)


async def apply_import(
    session: AsyncSession,
    project_id: UUID,
    entries: list[IPIn],
    mode: ImportMode,
    *,
    track_history: bool,
) -> list[ChangeSet]:
    """Reconcile `entries` against stored state and stage every change on `session`.

    Duplicate addresses in the batch are collapsed first. The session is
    flushed, not committed — the request's unit of work owns the commit.
    Returns one ChangeSet per resulting IP.
    """
    entries = dedup_batch(entries)
    if not entries:
        return []

    stored = await _load(session, project_id, [e.ip for e in entries])
    changesets = [apply_mode(mode, _snapshot(stored.get(e.ip)), e) for e in entries]

    hostnames = await _ensure_hostnames(session, project_id, changesets)
    for cs in changesets:
        existing = stored.get(cs.ip)
        if existing is None:
            _create(session, project_id, cs, hostnames)
        else:
            _update(existing, cs, hostnames)
    if track_history:
        await _write_history(session, project_id, changesets)

    await session.flush()
    return changesets


async def _load(session: AsyncSession, project_id: UUID, addrs: list[str]) -> dict[str, IPDB]:
    # SQLModel types a Relationship attribute as its value, so pyright rejects it
    # as a loader argument; the runtime call is correct.
    loaders = (selectinload(IPDB.ports), selectinload(IPDB.hostnames))  # pyright: ignore[reportArgumentType]
    rows = (
        await session.exec(
            select(IPDB)
            .where(IPDB.project_id == project_id, col(IPDB.ip).in_(addrs))
            .options(*loaders)
        )
    ).all()
    return {r.ip: r for r in rows}


def _snapshot(ipdb: IPDB | None) -> StoredIP | None:
    """Project a loaded IPDB (ports + hostnames eager-loaded) onto StoredIP."""
    if ipdb is None:
        return None
    return StoredIP(
        ip=ipdb.ip,
        status=ipdb.status,
        os=ipdb.os,
        hostnames=sorted(h.hostname for h in ipdb.hostnames),
        open_ports=[Port.model_validate(p, from_attributes=True) for p in ipdb.ports],
    )


async def _ensure_hostnames(
    session: AsyncSession, project_id: UUID, changesets: list[ChangeSet]
) -> dict[str, ObservedHostnameDB]:
    names = {n for cs in changesets for n in (cs.hostnames if cs.created else cs.new_hostnames)}
    if not names:
        return {}
    # via the connection, matching auth.service / projects.members — SQLModel's
    # session.exec() is select-only and session.execute() warns.
    connection = await session.connection()
    await connection.execute(
        pg_insert(ObservedHostnameDB)
        .values([{"project_id": project_id, "hostname": n} for n in names])
        .on_conflict_do_nothing()
    )
    rows = (
        await session.exec(
            select(ObservedHostnameDB).where(
                ObservedHostnameDB.project_id == project_id,
                col(ObservedHostnameDB.hostname).in_(names),
            )
        )
    ).all()
    return {r.hostname: r for r in rows}


def _create(
    session: AsyncSession,
    project_id: UUID,
    cs: ChangeSet,
    hostnames: dict[str, ObservedHostnameDB],
) -> None:
    session.add(
        IPDB(
            ip=cs.ip,
            status=cs.status,
            os=cs.os,
            first_seen=cs.endtime,
            last_seen=cs.endtime,
            project_id=project_id,
            ports=[PortDB(**p.model_dump(mode="json")) for p in cs.open_ports],
            hostnames=[hostnames[n] for n in cs.hostnames],
        )
    )


def _update(ipdb: IPDB, cs: ChangeSet, hostnames: dict[str, ObservedHostnameDB]) -> None:
    ipdb.status = cs.status
    ipdb.os = cs.os
    ipdb.last_seen = cs.endtime

    target = {(p.number, p.protocol): p for p in cs.open_ports}
    stored = {(p.number, p.protocol): p for p in ipdb.ports}

    for key, port in target.items():
        row = stored.get(key)
        if row is None:
            ipdb.ports.append(PortDB(**port.model_dump(mode="json")))
        else:
            for field, value in port.model_dump(
                mode="json", exclude={"number", "protocol"}
            ).items():
                setattr(row, field, value)
    for key, row in stored.items():
        if key not in target:
            ipdb.ports.remove(row)  # delete-orphan cascade removes the row

    ipdb.hostnames.extend(hostnames[n] for n in cs.new_hostnames)


async def _write_history(
    session: AsyncSession, project_id: UUID, changesets: list[ChangeSet]
) -> None:
    rows = [
        {
            **change.model_dump(mode="json", exclude={"number"}),
            "port": change.number,
            "project_id": project_id,
            "ip": cs.ip,
            "created_at": cs.endtime,
        }
        for cs in changesets
        for change in cs.port_changes
    ]
    if rows:
        connection = await session.connection()
        await connection.execute(pg_insert(IPPortHistoryDB).values(rows).on_conflict_do_nothing())
