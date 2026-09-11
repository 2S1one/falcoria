"""Scan-orchestration endpoints: start, inspect, and cancel scan campaigns."""

from uuid import UUID

from fastapi import APIRouter, status

from falcoria_tasker.constants import Tag
from falcoria_tasker.scans import service
from falcoria_tasker.scans.schemas import RunScanRequest, RunScanResponse

router = APIRouter(tags=[Tag.SCANS])


@router.post("", status_code=status.HTTP_201_CREATED)
async def run_scan(project_id: UUID, request: RunScanRequest) -> RunScanResponse:
    """Starts a scan campaign for the project's hosts."""
    return await service.run_scan(project_id, request)
