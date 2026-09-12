"""Tests for scans/router.py."""

from uuid import UUID, uuid4

import pytest
from httpx import ASGITransport, AsyncClient

from falcoria_tasker.main import app
from falcoria_tasker.scans.schemas import (
    NotScannedDetails,
    RunScanRequest,
    RunScanResponse,
    ScanListResponse,
    ScanState,
    ScanStatusResponse,
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
        summary=ScanSummary(provided=1, duplicates_removed=0, target_ips=1, started=1),
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


async def test_list_running_scans_delegates_to_service(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def fake_list_running_scans(project_id: UUID) -> ScanListResponse:
        return ScanListResponse(running=1, scan_ids=["scan-1"])

    monkeypatch.setattr(
        "falcoria_tasker.scans.router.service.list_running_scans", fake_list_running_scans
    )

    response = await client.get(f"/api/projects/{uuid4()}/scans")

    assert response.status_code == 200
    assert response.json() == {"running": 1, "scan_ids": ["scan-1"]}


async def test_get_scan_status_delegates_to_service(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def fake_get_scan_status(project_id: UUID, scan_id: str) -> ScanStatusResponse:
        return ScanStatusResponse(total=1, completed=0, failed=0, state=ScanState.RUNNING)

    monkeypatch.setattr(
        "falcoria_tasker.scans.router.service.get_scan_status", fake_get_scan_status
    )

    response = await client.get(f"/api/projects/{uuid4()}/scans/scan-1")

    assert response.status_code == 200
    assert response.json()["total"] == 1


async def test_get_scan_status_returns_404_for_unknown_scan(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def fake_get_scan_status(project_id: UUID, scan_id: str) -> ScanStatusResponse | None:
        return None

    monkeypatch.setattr(
        "falcoria_tasker.scans.router.service.get_scan_status", fake_get_scan_status
    )

    response = await client.get(f"/api/projects/{uuid4()}/scans/unknown")

    assert response.status_code == 404


async def test_cancel_scan_by_id_delegates_to_service(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[UUID, str | None]] = []

    async def fake_cancel_batches(project_id: UUID, scan_id: str | None) -> None:
        calls.append((project_id, scan_id))

    monkeypatch.setattr("falcoria_tasker.scans.router.service.cancel_batches", fake_cancel_batches)
    project_id = uuid4()

    response = await client.post(f"/api/projects/{project_id}/scans/scan-1/cancel")

    assert response.status_code == 200
    assert response.json() == {"success": True}
    assert calls == [(project_id, "scan-1")]


async def test_cancel_all_scans_delegates_to_service(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[UUID, str | None]] = []

    async def fake_cancel_batches(project_id: UUID, scan_id: str | None) -> None:
        calls.append((project_id, scan_id))

    monkeypatch.setattr("falcoria_tasker.scans.router.service.cancel_batches", fake_cancel_batches)
    project_id = uuid4()

    response = await client.post(f"/api/projects/{project_id}/scans/cancel")

    assert response.status_code == 200
    assert response.json() == {"success": True}
    assert calls == [(project_id, None)]


async def test_cancel_scan_by_ips_delegates_to_service(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[UUID, list[str]]] = []

    async def fake_cancel_by_ips(project_id: UUID, ips: list[str]) -> None:
        calls.append((project_id, ips))

    monkeypatch.setattr("falcoria_tasker.scans.router.service.cancel_by_ips", fake_cancel_by_ips)
    project_id = uuid4()

    response = await client.post(
        f"/api/projects/{project_id}/scans/cancel-ips", json={"ips": ["10.0.0.1"]}
    )

    assert response.status_code == 200
    assert response.json() == {"success": True}
    assert calls == [(project_id, ["10.0.0.1"])]


async def test_cancel_scan_by_ips_rejects_empty_ips(client: AsyncClient) -> None:
    response = await client.post(f"/api/projects/{uuid4()}/scans/cancel-ips", json={"ips": []})

    assert response.status_code == 422
