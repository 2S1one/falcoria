"""IP inventory and scan-import endpoints.

Mounted by ``main.py`` under ``/projects/{project_id}/ips``, behind
``validate_project_access``.
"""

from typing import Annotated, Any
from uuid import UUID
from xml.etree.ElementTree import ParseError

from fastapi import APIRouter, Depends, File, Query, UploadFile, status
from pydantic import ValidationError
from sqlmodel.ext.asyncio.session import AsyncSession

from falcoria_contracts.enums import ImportMode
from falcoria_scanledger.config import get_app_settings
from falcoria_scanledger.constants import Tag
from falcoria_scanledger.database import get_session
from falcoria_scanledger.exceptions import BadRequest, NotFound, RequestEntityTooLarge
from falcoria_scanledger.ips import service
from falcoria_scanledger.ips.schemas import (
    IPDeleteRequest,
    IPImportResult,
    IPIn,
    IPOut,
    ScannerFormat,
)

router = APIRouter(tags=[Tag.IPS])

_NOT_FOUND: dict[int | str, dict[str, Any]] = {
    status.HTTP_404_NOT_FOUND: {"description": "No such IP in this project."}
}
_CHUNK_BYTES = 64 * 1024

_Session = Annotated[AsyncSession, Depends(get_session)]
_Mode = Annotated[ImportMode, Query(description="How the import merges with stored state.")]
_TrackHistory = Annotated[bool, Query(description="Write port-change history rows.")]
_ScanId = Annotated[
    UUID | None,
    Query(description="Scan campaign this import belongs to; omit for a manual upload."),
]


async def _read_capped(upload: UploadFile, limit: int) -> bytes:
    """Read the whole upload into memory, rejecting anything past `limit` bytes.

    ``upload.size`` (set by the multipart parser) is checked first; the streamed
    count is the real guard for transports that leave it unset.
    """
    if upload.size is not None and upload.size > limit:
        raise RequestEntityTooLarge(f"Report exceeds the {limit}-byte limit.")
    parts: list[bytes] = []
    total = 0
    while chunk := await upload.read(_CHUNK_BYTES):
        total += len(chunk)
        if total > limit:
            raise RequestEntityTooLarge(f"Report exceeds the {limit}-byte limit.")
        parts.append(chunk)
    return b"".join(parts)


@router.post(
    "/import",
    status_code=status.HTTP_201_CREATED,
    responses={
        status.HTTP_400_BAD_REQUEST: {"description": "The report could not be parsed."},
        status.HTTP_413_CONTENT_TOO_LARGE: {"description": "The report is too large."},
    },
)
async def import_scan(
    project_id: UUID,
    session: _Session,
    mode: _Mode,
    report: Annotated[UploadFile, File(description="Scan report file (nmap XML).")],
    track_history: _TrackHistory = True,
    scan_id: _ScanId = None,
    scanner: Annotated[ScannerFormat, Query(description="Report format.")] = ScannerFormat.NMAP,
) -> IPImportResult:
    """Imports a scan report file, merging it into the project under `mode`."""
    data = await _read_capped(report, get_app_settings().max_report_bytes)
    try:
        changesets = await service.import_scan(
            session, project_id, data, mode, track_history=track_history, scan_id=scan_id
        )
    except (ParseError, ValidationError) as exc:
        raise BadRequest(f"Could not parse the {scanner.value} report: {exc}") from exc
    return IPImportResult.from_changesets(changesets)


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_ips(
    project_id: UUID,
    session: _Session,
    mode: _Mode,
    body: list[IPIn],
    track_history: _TrackHistory = True,
    scan_id: _ScanId = None,
) -> IPImportResult:
    """Merges a structured list of IP entries into the project under `mode`."""
    changesets = await service.create_ips(
        session, project_id, body, mode, track_history=track_history, scan_id=scan_id
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
async def delete_ips(
    project_id: UUID, session: _Session, body: IPDeleteRequest | None = None
) -> None:
    """Deletes the project's IPs — all of them, or only `ip_addresses` when a body is given."""
    addresses = body.ip_addresses if body is not None else None
    await service.delete_ips(session, project_id, addresses)


@router.delete("/{ip}", status_code=status.HTTP_204_NO_CONTENT, responses=_NOT_FOUND)
async def delete_ip(project_id: UUID, ip: str, session: _Session) -> None:
    """Deletes one IP and everything scoped to it."""
    if not await service.delete_ips(session, project_id, [ip]):
        raise NotFound(f"IP {ip} not found in project {project_id}.")
