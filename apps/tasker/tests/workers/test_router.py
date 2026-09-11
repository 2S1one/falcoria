"""Tests for workers/router.py."""

from datetime import UTC, datetime

import pytest
from httpx import ASGITransport, AsyncClient

from falcoria_tasker.main import app
from falcoria_tasker.workers.schemas import WorkerInfo, WorkersResponse

pytestmark = pytest.mark.anyio


def _response() -> WorkersResponse:
    return WorkersResponse(
        workers=[
            WorkerInfo(
                identity="host-1:10.0.0.1",
                external_ip="10.0.0.1",
                last_access_time=datetime.now(UTC),
                last_seen_seconds=1,
                task_queue="port-scanner-pool",
                poller_types=["activity", "workflow"],
            )
        ],
        available_workers=1,
    )


async def test_get_workers_delegates_to_service(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def fake_get_workers() -> WorkersResponse:
        return _response()

    monkeypatch.setattr("falcoria_tasker.workers.router.service.get_workers", fake_get_workers)

    response = await client.get("/api/workers")

    assert response.status_code == 200
    body = response.json()
    assert body["available_workers"] == 1
    assert body["workers"][0]["identity"] == "host-1:10.0.0.1"


async def test_get_workers_requires_a_bearer_token() -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as anon:
        response = await anon.get("/api/workers")

    assert response.status_code == 401
