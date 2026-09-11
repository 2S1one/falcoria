from uuid import uuid4

import httpx
import pytest

from falcoria_tasker.scanledger import AccessResult, ScanledgerClient

pytestmark = pytest.mark.anyio


async def test_check_access_ok_without_project() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/projects"
        assert request.headers["authorization"] == "Bearer tok"
        return httpx.Response(200, json=[])

    client = ScanledgerClient("http://scanledger.test", transport=httpx.MockTransport(handler))
    assert await client.check_access("tok") is AccessResult.OK


async def test_check_access_ok_with_project() -> None:
    project_id = uuid4()

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == f"/api/projects/{project_id}"
        return httpx.Response(200, json={})

    client = ScanledgerClient("http://scanledger.test", transport=httpx.MockTransport(handler))
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

    client = ScanledgerClient("http://scanledger.test", transport=httpx.MockTransport(handler))
    assert await client.check_access("tok") is expected


async def test_check_access_raises_on_unexpected_status() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500)

    client = ScanledgerClient("http://scanledger.test", transport=httpx.MockTransport(handler))
    with pytest.raises(httpx.HTTPStatusError):
        await client.check_access("tok")
