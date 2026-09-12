import httpx
import pytest
from falcoria_http.transport import RetryingTransport

pytestmark = pytest.mark.anyio


class _FakeTransport(httpx.AsyncBaseTransport):
    """Replays a fixed sequence of responses/exceptions, one per call."""

    def __init__(self, results: list[httpx.Response | Exception]) -> None:
        self._results = results
        self.calls = 0
        self.closed = False

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        result = self._results[self.calls]
        self.calls += 1
        if isinstance(result, Exception):
            raise result
        return result

    async def aclose(self) -> None:
        self.closed = True


def _request() -> httpx.Request:
    return httpx.Request("GET", "http://test/")


async def test_succeeds_without_retry() -> None:
    fake = _FakeTransport([httpx.Response(200)])
    transport = RetryingTransport(wrapped=fake, retries=3, backoff_base=0)

    response = await transport.handle_async_request(_request())

    assert response.status_code == 200
    assert fake.calls == 1


async def test_retries_on_transport_error_then_succeeds() -> None:
    fake = _FakeTransport(
        [httpx.ConnectError("boom"), httpx.ConnectError("boom"), httpx.Response(200)]
    )
    transport = RetryingTransport(wrapped=fake, retries=3, backoff_base=0)

    response = await transport.handle_async_request(_request())

    assert response.status_code == 200
    assert fake.calls == 3


async def test_raises_after_exhausting_retries() -> None:
    fake = _FakeTransport([httpx.ConnectError("boom")] * 4)
    transport = RetryingTransport(wrapped=fake, retries=3, backoff_base=0)

    with pytest.raises(httpx.ConnectError):
        await transport.handle_async_request(_request())

    assert fake.calls == 4


async def test_does_not_retry_on_error_status() -> None:
    fake = _FakeTransport([httpx.Response(500)])
    transport = RetryingTransport(wrapped=fake, retries=3, backoff_base=0)

    response = await transport.handle_async_request(_request())

    assert response.status_code == 500
    assert fake.calls == 1


async def test_aclose_delegates_to_wrapped() -> None:
    fake = _FakeTransport([])
    transport = RetryingTransport(wrapped=fake)

    await transport.aclose()

    assert fake.closed
