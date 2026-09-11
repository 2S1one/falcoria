"""IP inventory and scan-import endpoints.

Mounted by ``main.py`` under ``/projects/{project_id}/ips``, behind
``validate_project_access``.
"""

from typing import Annotated, Any
from uuid import UUID
from xml.etree.ElementTree import ParseError

from fastapi import APIRouter, Body, Depends, File, Query, Response, UploadFile, status
from pydantic import ValidationError
from sqlmodel.ext.asyncio.session import AsyncSession

from falcoria_contracts.enums import ImportMode, ScannerFormat
from falcoria_scanledger.config import get_app_settings
from falcoria_scanledger.constants import Tag
from falcoria_scanledger.database import get_session
from falcoria_scanledger.exceptions import BadRequest, NotFound, RequestEntityTooLarge
from falcoria_scanledger.ips import service
from falcoria_scanledger.ips.facets import FACET_EXAMPLES, FacetsRequest, FacetsResult
from falcoria_scanledger.ips.schemas import (
    IPDeleteRequest,
    IPImportResult,
    IPIn,
    IPOut,
)
from falcoria_scanledger.ips.search import SEARCH_EXAMPLES, IPSearchRequest, IPSearchResult
from falcoria_scanledger.projects.dependencies import validate_project_access
from falcoria_scanledger.projects.models import ProjectDB

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
_Project = Annotated[ProjectDB, Depends(validate_project_access)]


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


@router.post("/search", summary="Search IPs")
async def search_ips(
    project_id: UUID,
    session: _Session,
    body: Annotated[IPSearchRequest, Body(openapi_examples=SEARCH_EXAMPLES)],
) -> IPSearchResult:
    """Search the project's IPs by host and port attributes.

    The body is a host-level filter (its set fields AND-ed) plus port-scoped
    groups: ``all_of`` (a port matching every clause), ``any_of`` (a port
    matching at least one), ``none_of`` (no port matching any). Within a clause,
    every condition must hold on the same port row. ``matched_ports_only`` trims
    each result's ports to those matching the ``all_of`` / ``any_of`` clauses.
    Results are ordered by IP address; ``total`` is the match count before
    ``skip`` / ``limit``.
    """
    return await service.search_ips(session, project_id, body)


@router.post("/facets", summary="IP facets")
async def get_facets(
    project_id: UUID,
    session: _Session,
    body: Annotated[FacetsRequest, Body(openapi_examples=FACET_EXAMPLES)],
) -> FacetsResult:
    """Value counts per dimension over the project's IPs matching the filter.

    The filter has the same shape as POST /ips/search. Each facet lists its top
    `limit` values by descending host count; `service`, `product`, `version`,
    `tunnel` and `os` include a null bucket. An empty body facets the whole
    project.
    """
    return await service.get_facets(session, project_id, body)


@router.get("")
async def list_ips(
    project_id: UUID,
    session: _Session,
    skip: Annotated[int | None, Query(ge=0)] = None,
    limit: Annotated[int | None, Query(ge=1, le=1000)] = None,
) -> list[IPOut]:
    """Lists the project's IPs with their open ports and hostnames."""
    return await service.list_ips(session, project_id, skip=skip, limit=limit)


@router.get("/download", response_class=Response)
async def download_report(project_id: UUID, session: _Session, project: _Project) -> Response:
    """Downloads the project's open-port inventory as an nmap-format XML report."""
    xml = await service.download_report(session, project_id)
    return Response(
        content=xml,
        media_type="text/xml",
        headers={"Content-Disposition": f'attachment; filename="{project.name}.xml"'},
    )


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
