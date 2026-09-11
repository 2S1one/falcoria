import json
from typing import Any
from uuid import uuid4

import httpx
import pytest

from falcoria_contracts.enums import ImportMode
from falcoria_tasker.scanledger import _SEARCH_CHUNK_SIZE, AccessResult, ScanledgerClient

pytestmark = pytest.mark.anyio


def _client(handler: Any) -> ScanledgerClient:
    return ScanledgerClient(
        "http://scanledger.test/api", "svc-token", transport=httpx.MockTransport(handler)
    )


async def test_check_access_ok_without_project() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/projects"
        assert request.headers["authorization"] == "Bearer tok"
        return httpx.Response(200, json=[])

    client = _client(handler)
    assert await client.check_access("tok") is AccessResult.OK


async def test_check_access_ok_with_project() -> None:
    project_id = uuid4()

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == f"/api/projects/{project_id}"
        return httpx.Response(200, json={})

    client = _client(handler)
    assert await client.check_access("tok", project_id) is AccessResult.OK


@pytest.mark.parametrize(
    ("status_code", "expected"),
    [
        (401, AccessResult.UNAUTHORIZED),
        (403, AccessResult.FORBIDDEN),
        (404, AccessResult.NOT_FOUND),
    ],
)
async def test_check_access_maps_error_statuses(status_code: int, expected: AccessResult) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code)

    client = _client(handler)
    assert await client.check_access("tok") is expected


async def test_check_access_raises_on_unexpected_status() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500)

    client = _client(handler)
    with pytest.raises(httpx.HTTPStatusError):
        await client.check_access("tok")


async def test_search_ips_returns_known_subset() -> None:
    project_id = uuid4()
    candidates = ["203.0.113.5", "203.0.113.6", "203.0.113.7"]

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == f"/api/projects/{project_id}/ips/search"
        assert request.headers["authorization"] == "Bearer svc-token"
        return httpx.Response(
            200,
            json={
                "items": [
                    {
                        "ip": "203.0.113.5",
                        "first_seen": 0,
                        "last_seen": 0,
                        "hostnames": [],
                        "ports": [],
                    }
                ],
                "total": 1,
            },
        )

    client = _client(handler)
    known = await client.search_ips(project_id, candidates)
    assert known == {"203.0.113.5"}


async def test_search_ips_chunks_at_limit() -> None:
    project_id = uuid4()
    candidates = [f"10.0.{i // 256}.{i % 256}" for i in range(_SEARCH_CHUNK_SIZE + 1)]
    seen_chunk_sizes: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        seen_chunk_sizes.append(len(body["filter"]["ip_in"]))
        assert body["limit"] == len(body["filter"]["ip_in"])
        return httpx.Response(200, json={"items": [], "total": 0})

    client = _client(handler)
    known = await client.search_ips(project_id, candidates)
    assert known == set()
    assert seen_chunk_sizes == [_SEARCH_CHUNK_SIZE, 1]


async def test_create_ips_posts_items_under_mode() -> None:
    project_id = uuid4()
    items = [{"ip": "203.0.113.5", "hostnames": ["host.example"], "endtime": 1_700_000_000}]

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == f"/api/projects/{project_id}/ips"
        assert request.url.params["mode"] == "insert"
        assert request.headers["authorization"] == "Bearer svc-token"
        assert json.loads(request.content) == items
        return httpx.Response(201, json={"created": [], "updated": [], "unchanged": []})

    client = _client(handler)
    await client.create_ips(project_id, items, ImportMode.INSERT)


async def test_create_ips_empty_items_no_ops() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("no HTTP call expected for an empty items list")

    client = _client(handler)
    await client.create_ips(uuid4(), [], ImportMode.INSERT)
