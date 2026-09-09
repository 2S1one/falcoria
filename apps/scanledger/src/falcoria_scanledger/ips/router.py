"""IP inventory and scan-import endpoints.

Mounted by ``main.py`` under ``/projects/{project_id}/ips``, behind
``validate_project_access``.
"""

from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, Body, Depends, Query, status
from sqlmodel.ext.asyncio.session import AsyncSession

from falcoria_contracts.enums import ImportMode
from falcoria_scanledger.constants import Tag
from falcoria_scanledger.database import get_session
from falcoria_scanledger.exceptions import NotFound
from falcoria_scanledger.ips import service
from falcoria_scanledger.ips.schemas import IPDeleteRequest, IPImportResult, IPIn, IPOut

router = APIRouter(tags=[Tag.IPS])

_NOT_FOUND: dict[int | str, dict[str, Any]] = {
    status.HTTP_404_NOT_FOUND: {"description": "No such IP in this project."}
}

_Session = Annotated[AsyncSession, Depends(get_session)]
_Mode = Annotated[ImportMode, Query(description="How the import merges with stored state.")]
_TrackHistory = Annotated[bool, Query(description="Write port-change history rows.")]


@router.post("/import", status_code=status.HTTP_201_CREATED)
async def import_scan(
    project_id: UUID,
    session: _Session,
    mode: _Mode,
    report: Annotated[bytes, Body(media_type="application/xml")],
    track_history: _TrackHistory = True,
    scanner: Annotated[Literal["nmap"], Query(description="Report format.")] = "nmap",
) -> IPImportResult:
    """Imports a scan report, merging it into the project under `mode`."""
    changesets = await service.import_scan(
        session, project_id, report, mode, track_history=track_history
    )
    return IPImportResult.from_changesets(changesets)


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_ips(
    project_id: UUID,
    session: _Session,
    mode: _Mode,
    body: list[IPIn],
    track_history: _TrackHistory = True,
) -> IPImportResult:
    """Merges a structured list of IP entries into the project under `mode`."""
    changesets = await service.create_ips(
        session, project_id, body, mode, track_history=track_history
    )
    return IPImportResult.from_changesets(changesets)


@router.get("")
async def list_ips(
    project_id: UUID,
    session: _Session,
    skip: Annotated[int | None, Query(ge=0)] = None,
    limit: Annotated[int | None, Query(ge=1, le=1000)] = None,
) -> list[IPOut]:
    """Lists the project's IPs with their open ports and hostnames."""
    return await service.list_ips(session, project_id, skip=skip, limit=limit)


@router.get("/{ip}", responses=_NOT_FOUND)
async def get_ip(project_id: UUID, ip: str, session: _Session) -> IPOut:
    """Returns one IP with its open ports and hostnames."""
    out = await service.get_ip(session, project_id, ip)
    if out is None:
        raise NotFound(f"IP {ip} not found in project {project_id}.")
    return out


@router.delete("", status_code=status.HTTP_204_NO_CONTENT)
async def delete_ips(project_id: UUID, body: IPDeleteRequest, session: _Session) -> None:
    """Deletes the listed IPs and everything scoped to them."""
    await service.delete_ips(session, project_id, body.ip_addresses)


@router.delete("/{ip}", status_code=status.HTTP_204_NO_CONTENT, responses=_NOT_FOUND)
async def delete_ip(project_id: UUID, ip: str, session: _Session) -> None:
    """Deletes one IP and everything scoped to it."""
    if not await service.delete_ips(session, project_id, [ip]):
        raise NotFound(f"IP {ip} not found in project {project_id}.")
