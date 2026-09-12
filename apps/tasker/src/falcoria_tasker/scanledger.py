"""HTTP client for scanledger's API.

Covers the access checks tasker delegates to it, plus the INSERT-mode dedup
calls tasker makes under its own service account.
"""

from enum import Enum, auto
from functools import lru_cache
from typing import Any
from uuid import UUID

import httpx
from falcoria_http.transport import RetryingTransport

from falcoria_contracts.enums import ImportMode
from falcoria_tasker.config import get_app_settings

_SEARCH_CHUNK_SIZE = 1000  # scanledger's IPSearchRequest.limit cap


class AccessResult(Enum):
    """Outcome of a scanledger access check."""

    OK = auto()
    UNAUTHORIZED = auto()
    FORBIDDEN = auto()
    NOT_FOUND = auto()


class ScanledgerClient:
    """Thin wrapper over the subset of scanledger's API tasker calls."""

    def __init__(
        self,
        base_url: str,
        service_token: str,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._client = httpx.AsyncClient(
            base_url=base_url, transport=transport if transport is not None else RetryingTransport()
        )
        self._service_token = service_token

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

    def _auth_headers(self) -> dict[str, str]:
        """Bearer header for tasker's own service-account calls, not the caller's token."""
        return {"Authorization": f"Bearer {self._service_token}"}

    async def search_ips(self, project_id: UUID, ips: list[str]) -> set[str]:
        """Returns the subset of `ips` scanledger already knows for `project_id`.

        Chunks the membership check at scanledger's IPSearchRequest.limit cap
        (1000) so an arbitrarily large candidate set still round-trips.
        """
        known: set[str] = set()
        for i in range(0, len(ips), _SEARCH_CHUNK_SIZE):
            chunk = ips[i : i + _SEARCH_CHUNK_SIZE]
            response = await self._client.post(
                f"/projects/{project_id}/ips/search",
                json={"filter": {"ip_in": chunk}, "limit": len(chunk)},
                headers=self._auth_headers(),
            )
            response.raise_for_status()
            known.update(item["ip"] for item in response.json()["items"])
        return known

    async def create_ips(
        self, project_id: UUID, items: list[dict[str, Any]], mode: ImportMode
    ) -> None:
        """Merges `items` (IPIn-shaped bodies) into `project_id` under `mode`.

        A thin mirror of scanledger's POST /ips; no-ops on an empty `items` so
        callers don't need to guard a possibly-empty dedup result themselves.
        """
        if not items:
            return
        response = await self._client.post(
            f"/projects/{project_id}/ips",
            params={"mode": mode.value},
            json=items,
            headers=self._auth_headers(),
        )
        response.raise_for_status()


@lru_cache
def get_scanledger_client() -> ScanledgerClient:
    """Returns the process-wide scanledger HTTP client, built on first use."""
    settings = get_app_settings()
    return ScanledgerClient(
        settings.scanledger_base_url, settings.scanledger_token.get_secret_value()
    )


async def dispose_scanledger_client() -> None:
    """Closes the client's connection pool; called on application shutdown."""
    if get_scanledger_client.cache_info().currsize:
        await get_scanledger_client().aclose()
