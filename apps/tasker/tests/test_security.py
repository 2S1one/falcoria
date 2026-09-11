from collections.abc import Callable
from uuid import uuid4

import httpx
import pytest
from fastapi.security import HTTPAuthorizationCredentials

from falcoria_tasker.exceptions import NotFound, PermissionDenied, ServiceUnavailable, Unauthorized
from falcoria_tasker.scanledger import ScanledgerClient
from falcoria_tasker.security import clear_access_cache, require_project_access, require_token

pytestmark = pytest.mark.anyio


@pytest.fixture(autouse=True)
def _clear_cache() -> None:
    clear_access_cache()


def _creds(token: str = "tok") -> HTTPAuthorizationCredentials:  # noqa: S107 -- test fixture, not a real credential
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)


def _patch_client(
    monkeypatch: pytest.MonkeyPatch, handler: Callable[[httpx.Request], httpx.Response]
) -> list[httpx.Request]:
    """Points security.py's client getter at a mock-transport client; returns recorded calls."""
    calls: list[httpx.Request] = []

    def record(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return handler(request)

    client = ScanledgerClient("http://scanledger.test", transport=httpx.MockTransport(record))
    monkeypatch.setattr("falcoria_tasker.security.get_scanledger_client", lambda: client)
    return calls


async def test_require_token_missing_credentials_is_unauthorized() -> None:
    with pytest.raises(Unauthorized):
        await require_token(None)


async def test_require_token_valid(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_client(monkeypatch, lambda request: httpx.Response(200, json=[]))
    await require_token(_creds())


async def test_require_token_invalid_is_unauthorized(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_client(monkeypatch, lambda request: httpx.Response(401))
    with pytest.raises(Unauthorized):
        await require_token(_creds())


async def test_require_project_access_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_client(monkeypatch, lambda request: httpx.Response(200, json={}))
    await require_project_access(uuid4(), _creds())


async def test_require_project_access_forbidden(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_client(monkeypatch, lambda request: httpx.Response(403))
    with pytest.raises(PermissionDenied):
        await require_project_access(uuid4(), _creds())


async def test_require_project_access_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_client(monkeypatch, lambda request: httpx.Response(404))
    with pytest.raises(NotFound):
        await require_project_access(uuid4(), _creds())


async def test_access_result_is_cached(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _patch_client(monkeypatch, lambda request: httpx.Response(200, json=[]))
    await require_token(_creds())
    await require_token(_creds())
    assert len(calls) == 1


async def test_scanledger_unreachable_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom", request=request)

    _patch_client(monkeypatch, handler)
    with pytest.raises(ServiceUnavailable):
        await require_token(_creds())
