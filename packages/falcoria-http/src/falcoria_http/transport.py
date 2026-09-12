"""A retrying async httpx transport for transient network failures."""

import asyncio

import httpx

_DEFAULT_RETRIES = 3
_DEFAULT_BACKOFF_BASE = 0.1


class RetryingTransport(httpx.AsyncBaseTransport):
    """Retries a request on transport-level failure, with exponential backoff.

    Retries only `httpx.TransportError` (no response at all); a 4xx/5xx
    response is returned unchanged for callers' existing `raise_for_status()`.
    """

    def __init__(
        self,
        wrapped: httpx.AsyncBaseTransport | None = None,
        retries: int = _DEFAULT_RETRIES,
        backoff_base: float = _DEFAULT_BACKOFF_BASE,
    ) -> None:
        self._wrapped = wrapped if wrapped is not None else httpx.AsyncHTTPTransport()
        self._retries = retries
        self._backoff_base = backoff_base

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        """Sends `request`, retrying on `httpx.TransportError` up to `retries` times."""
        attempt = 0
        while True:
            try:
                return await self._wrapped.handle_async_request(request)
            except httpx.TransportError:
                if attempt >= self._retries:
                    raise
                await asyncio.sleep(self._backoff_base * (2**attempt))
                attempt += 1

    async def aclose(self) -> None:
        """Closes the wrapped transport's connection pool."""
        await self._wrapped.aclose()
