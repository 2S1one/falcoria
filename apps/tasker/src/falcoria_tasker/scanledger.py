"""HTTP client for scanledger's API — the access checks tasker delegates to it."""

from enum import Enum, auto
from functools import lru_cache
from uuid import UUID

import httpx

from falcoria_tasker.config import get_app_settings


class AccessResult(Enum):
    """Outcome of a scanledger access check."""

    OK = auto()
    UNAUTHORIZED = auto()
    FORBIDDEN = auto()
    NOT_FOUND = auto()


class ScanledgerClient:
    """Thin wrapper over the subset of scanledger's API tasker calls."""

    def __init__(self, base_url: str, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self._client = httpx.AsyncClient(base_url=base_url, transport=transport)

    async def aclose(self) -> None:
        """Closes the underlying HTTP connection pool."""
        await self._client.aclose()

    async def check_access(self, token: str, project_id: UUID | None = None) -> AccessResult:
        """Checks whether `token` is valid and, if given, a member of `project_id`.

        Relays `token` as-is to scanledger's own project endpoints — scanledger's
        existing auth gating is the source of truth, so there is no separate
        introspection surface to keep in sync. `project_id=None` checks only that
        the token is valid, for a route with no project scope.
        """
        path = f"/projects/{project_id}" if project_id is not None else "/projects"
        response = await self._client.get(path, headers={"Authorization": f"Bearer {token}"})
        if response.status_code == httpx.codes.OK:
            return AccessResult.OK
        if response.status_code == httpx.codes.UNAUTHORIZED:
            return AccessResult.UNAUTHORIZED
        if response.status_code == httpx.codes.FORBIDDEN:
            return AccessResult.FORBIDDEN
        if response.status_code == httpx.codes.NOT_FOUND:
            return AccessResult.NOT_FOUND
        response.raise_for_status()
        msg = f"Unexpected scanledger response: {response.status_code}."
        raise httpx.HTTPStatusError(msg, request=response.request, response=response)


@lru_cache
def get_scanledger_client() -> ScanledgerClient:
    """Returns the process-wide scanledger HTTP client, built on first use."""
    return ScanledgerClient(get_app_settings().scanledger_base_url)


async def dispose_scanledger_client() -> None:
    """Closes the client's connection pool; called on application shutdown."""
    if get_scanledger_client.cache_info().currsize:
        await get_scanledger_client().aclose()
