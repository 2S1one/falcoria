"""Tests for scans/router.py."""

from uuid import UUID, uuid4

import pytest
from httpx import ASGITransport, AsyncClient

from falcoria_tasker.main import app
from falcoria_tasker.scans.schemas import (
    NotScannedDetails,
    RunScanRequest,
    RunScanResponse,
    ScanSummary,
)

pytestmark = pytest.mark.anyio

_BODY = {
    "hosts": ["1.1.1.1"],
    "open_ports_opts": {"ports": ["22"]},
    "service_opts": {},
    "timeout": 30,
    "include_services": False,
    "mode": "insert",
}


def _response() -> RunScanResponse:
    return RunScanResponse(
        scan_id="scan-1",
        summary=ScanSummary(provided=1, duplicates_removed=0, resolved_ips=1, started=1),
        not_scanned=NotScannedDetails(),
    )


async def test_run_scan_delegates_to_service_and_returns_201(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[UUID, RunScanRequest]] = []

    async def fake_run_scan(project_id: UUID, request: RunScanRequest) -> RunScanResponse:
        calls.append((project_id, request))
        return _response()

    monkeypatch.setattr("falcoria_tasker.scans.router.service.run_scan", fake_run_scan)
    project_id = uuid4()

    response = await client.post(f"/api/projects/{project_id}/scans", json=_BODY)

    assert response.status_code == 201
    assert response.json()["scan_id"] == "scan-1"
    assert calls[0][0] == project_id
    assert calls[0][1].hosts == ["1.1.1.1"]


async def test_run_scan_requires_a_bearer_token() -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as anon:
        response = await anon.post(f"/api/projects/{uuid4()}/scans", json=_BODY)

    assert response.status_code == 401
