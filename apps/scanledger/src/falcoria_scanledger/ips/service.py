"""IP inventory reads plus the import transaction boundary.

Import path: collect -> dedup -> reconcile -> apply. Reads project IPs with
their ports and hostnames eager-loaded.
"""

from typing import Any
from uuid import UUID

from sqlalchemy import ColumnElement, cast, func
from sqlalchemy.dialects.postgresql import INET, insert as pg_insert
from sqlalchemy.orm import selectinload
from sqlmodel import col, delete, select
from sqlmodel.ext.asyncio.session import AsyncSession

from falcoria_contracts.enums import ImportMode
from falcoria_contracts.port import Port
from falcoria_scanledger.history.models import IPPortHistoryDB
from falcoria_scanledger.ips.dedup import dedup_batch
from falcoria_scanledger.ips.models import IPDB, ObservedHostnameDB, PortDB
from falcoria_scanledger.ips.modes import apply_mode
from falcoria_scanledger.ips.nmap import export_report, parse_report
from falcoria_scanledger.ips.schemas import ChangeSet, IPIn, IPOut, StoredIP
from falcoria_scanledger.ips.search import (
    IPSearchRequest,
    IPSearchResult,
    build_search_conditions,
    matched_port_filter,
)


def _loaders() -> tuple[Any, ...]:
    # SQLModel types a Relationship attribute as its value, so pyright rejects it
    # as a loader argument; the runtime call is correct.
    return (selectinload(IPDB.ports), selectinload(IPDB.hostnames))  # pyright: ignore[reportArgumentType]


async def import_scan(
    session: AsyncSession,
    project_id: UUID,
    xml: str | bytes,
    mode: ImportMode,
    *,
    track_history: bool = True,
    scan_id: UUID | None = None,
) -> list[ChangeSet]:
    """Parse an nmap XML report and merge it into the project under `mode`."""
    return await apply_import(
        session, project_id, parse_report(xml), mode, track_history=track_history, scan_id=scan_id
    )


async def create_ips(
    session: AsyncSession,
    project_id: UUID,
    entries: list[IPIn],
    mode: ImportMode,
    *,
    track_history: bool = True,
    scan_id: UUID | None = None,
) -> list[ChangeSet]:
    """Merge a structured list of IPIn entries into the project under `mode`."""
    return await apply_import(
        session, project_id, entries, mode, track_history=track_history, scan_id=scan_id
    )


async def apply_import(
    session: AsyncSession,
    project_id: UUID,
    entries: list[IPIn],
    mode: ImportMode,
    *,
    track_history: bool,
    scan_id: UUID | None = None,
) -> list[ChangeSet]:
    """Reconcile `entries` against stored state and stage every change on `session`.

    Duplicate addresses in the batch are collapsed first. The session is
    flushed, not committed — the request's unit of work owns the commit.
    Returns one ChangeSet per resulting IP. `scan_id`, if given, is stamped on
    every history row this import writes.
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
        await _write_history(session, project_id, changesets, scan_id)

    await session.flush()
    return changesets


async def _load(session: AsyncSession, project_id: UUID, addrs: list[str]) -> dict[str, IPDB]:
    rows = (
        await session.exec(
            select(IPDB)
            .where(IPDB.project_id == project_id, col(IPDB.ip).in_(addrs))
            .options(*_loaders())
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
    session: AsyncSession, project_id: UUID, changesets: list[ChangeSet], scan_id: UUID | None
) -> None:
    rows = [
        {
            **change.model_dump(mode="json", exclude={"number"}),
            "port": change.number,
            "project_id": project_id,
            "ip": cs.ip,
            "created_at": cs.endtime,
            "scan_id": scan_id,
        }
        for cs in changesets
        for change in cs.port_changes
    ]
    if rows:
        connection = await session.connection()
        await connection.execute(pg_insert(IPPortHistoryDB).values(rows).on_conflict_do_nothing())


async def list_ips(
    session: AsyncSession,
    project_id: UUID,
    *,
    skip: int | None = None,
    limit: int | None = None,
) -> list[IPOut]:
    """Return the project's IPs, ordered by address, with ports and hostnames."""
    rows = (
        await session.exec(
            select(IPDB)
            .where(IPDB.project_id == project_id)
            .order_by(col(IPDB.ip))
            .options(*_loaders())
            .offset(skip)
            .limit(limit)
        )
    ).all()
    return [_to_out(r) for r in rows]


async def get_ip(session: AsyncSession, project_id: UUID, ip: str) -> IPOut | None:
    """Return one IP with its ports and hostnames, or None when it is absent."""
    row = (
        await session.exec(
            select(IPDB).where(IPDB.project_id == project_id, IPDB.ip == ip).options(*_loaders())
        )
    ).first()
    return _to_out(row) if row is not None else None


async def download_report(session: AsyncSession, project_id: UUID) -> str:
    """Return the project's IPs, ordered by address, as an nmap XML report."""
    rows = (
        await session.exec(
            select(IPDB)
            .where(IPDB.project_id == project_id)
            .order_by(cast(col(IPDB.ip), INET), col(IPDB.id))
            .options(*_loaders())
        )
    ).all()
    return export_report([_to_out(r) for r in rows])


async def delete_ips(
    session: AsyncSession, project_id: UUID, addresses: list[str] | None = None
) -> int:
    """Delete the project's IPs (all, or the listed ones); return the row count.

    Ports and hostname links go through the database's ``ON DELETE CASCADE``.
    ``observed_hostnames`` rows are left in place — harmless, and reused on the
    next import.
    """
    # col(): sqlmodel's delete() types .where() strictly, without select()'s
    # bool-comparison shim.
    statement = delete(IPDB).where(col(IPDB.project_id) == project_id)
    if addresses is not None:
        statement = statement.where(col(IPDB.ip).in_(addresses))
    connection = await session.connection()
    result = await connection.execute(statement)
    return result.rowcount


async def search_ips(
    session: AsyncSession, project_id: UUID, request: IPSearchRequest
) -> IPSearchResult:
    """Return the project IPs matching `request.filter`, paginated, with a total.

    Two-stage: page the IP rows (hostnames eager-loaded), then load their ports
    in one query — narrowed to the matching ports when `matched_ports_only`.
    """
    conditions = build_search_conditions(project_id, request.filter)

    total = (await session.exec(select(func.count()).select_from(IPDB).where(*conditions))).one()

    rows = (
        await session.exec(
            select(IPDB)
            .where(*conditions)
            .order_by(cast(col(IPDB.ip), INET), col(IPDB.id))
            .offset(request.skip)
            .limit(request.limit)
            .options(selectinload(IPDB.hostnames))  # pyright: ignore[reportArgumentType]
        )
    ).all()

    port_filter = matched_port_filter(request.filter) if request.matched_ports_only else None
    ports_by_ip = await _load_ports(session, [r.id for r in rows if r.id is not None], port_filter)

    items = [_ip_out(r, r.hostnames, ports_by_ip.get(r.id, [])) for r in rows if r.id is not None]
    return IPSearchResult(items=items, total=total)


async def _load_ports(
    session: AsyncSession, ip_ids: list[int], port_filter: ColumnElement[bool] | None
) -> dict[int, list[PortDB]]:
    """Group open ports by ip_id for `ip_ids`, optionally narrowed by `port_filter`."""
    if not ip_ids:
        return {}
    statement = select(PortDB).where(col(PortDB.ip_id).in_(ip_ids))
    if port_filter is not None:
        statement = statement.where(port_filter)
    grouped: dict[int, list[PortDB]] = {}
    for port in (await session.exec(statement)).all():
        grouped.setdefault(port.ip_id, []).append(port)
    return grouped


def _ip_out(ipdb: IPDB, hostnames: list[ObservedHostnameDB], ports: list[PortDB]) -> IPOut:
    return IPOut(
        ip=ipdb.ip,
        status=ipdb.status,
        os=ipdb.os,
        first_seen=ipdb.first_seen,
        last_seen=ipdb.last_seen,
        hostnames=sorted(h.hostname for h in hostnames),
        ports=sorted(
            (Port.model_validate(p, from_attributes=True) for p in ports),
            key=lambda p: p.number,
        ),
    )


def _to_out(ipdb: IPDB) -> IPOut:
    return _ip_out(ipdb, ipdb.hostnames, ipdb.ports)
