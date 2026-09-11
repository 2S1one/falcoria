"""Scan-orchestration endpoints: start, inspect, and cancel scan campaigns."""

from typing import Any
from uuid import UUID

from fastapi import APIRouter, status

from falcoria_tasker.constants import Tag
from falcoria_tasker.exceptions import NotFound
from falcoria_tasker.scans import service
from falcoria_tasker.scans.schemas import (
    CancelScanRequest,
    CancelScanResponse,
    RunScanRequest,
    RunScanResponse,
    ScanListResponse,
    ScanStatusResponse,
)

router = APIRouter(tags=[Tag.SCANS])

_SCAN_NOT_FOUND: dict[int | str, dict[str, Any]] = {
    status.HTTP_404_NOT_FOUND: {"description": "No batch was ever started for this scan_id."}
}


@router.post("", status_code=status.HTTP_201_CREATED)
async def run_scan(project_id: UUID, request: RunScanRequest) -> RunScanResponse:
    """Starts a scan campaign for the project's hosts."""
    return await service.run_scan(project_id, request)


@router.get("")
async def list_running_scans(project_id: UUID) -> ScanListResponse:
    """Lists the project's currently running scans."""
    return await service.list_running_scans(project_id)


@router.get("/{scan_id}", responses=_SCAN_NOT_FOUND)
async def get_scan_status(project_id: UUID, scan_id: str) -> ScanStatusResponse:
    """Returns one scan's task-completion counts and currently running targets."""
    result = await service.get_scan_status(project_id, scan_id)
    if result is None:
        raise NotFound(f"No batch was ever started for scan {scan_id}.")
    return result


@router.post("/cancel")
async def cancel_scan(project_id: UUID, request: CancelScanRequest) -> CancelScanResponse:
    """Cancels a scan by scan_id, by ips, or - both omitted - every running scan."""
    return await service.cancel_scan(project_id, request)
