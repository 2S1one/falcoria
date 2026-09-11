"""FastAPI dependencies that gate requests via a scanledger access check."""

import hashlib
import time
from typing import Annotated
from uuid import UUID

import httpx
from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from falcoria_tasker.exceptions import NotFound, PermissionDenied, ServiceUnavailable, Unauthorized
from falcoria_tasker.scanledger import AccessResult, get_scanledger_client

bearer_scheme = HTTPBearer(auto_error=False)

_BEARER_CHALLENGE = {"WWW-Authenticate": "Bearer"}
_CACHE_TTL_SECONDS = 45.0

# (sha256(token), project_id) -> (result, expires_at). project_id is None for a
# token-only check. Process-local; a cold start or restart just re-checks.
_cache: dict[tuple[str, UUID | None], tuple[AccessResult, float]] = {}


def clear_access_cache() -> None:
    """Clears the cached access-check results. For tests only."""
    _cache.clear()


async def _check_access(token: str, project_id: UUID | None) -> AccessResult:
    """Returns the cached or freshly-checked access result for `token`/`project_id`.

    Raises:
        ServiceUnavailable: scanledger did not respond (network error, timeout, or
            an unexpected status) — fails closed rather than granting access.
    """
    key = (hashlib.sha256(token.encode("utf-8")).hexdigest(), project_id)
    now = time.monotonic()
    cached = _cache.get(key)
    if cached is not None and cached[1] > now:
        return cached[0]
    try:
        result = await get_scanledger_client().check_access(token, project_id)
    except httpx.HTTPError as exc:
        raise ServiceUnavailable("scanledger is unreachable.") from exc
    _cache[key] = (result, now + _CACHE_TTL_SECONDS)
    return result


def _raise_unless_ok(result: AccessResult) -> None:
    if result is AccessResult.UNAUTHORIZED:
        raise Unauthorized(headers=_BEARER_CHALLENGE)
    if result is AccessResult.FORBIDDEN:
        raise PermissionDenied()
    if result is AccessResult.NOT_FOUND:
        raise NotFound()


async def require_token(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
) -> None:
    """Gates a route on a valid bearer token, with no project scoping."""
    if credentials is None:
        raise Unauthorized(headers=_BEARER_CHALLENGE)
    _raise_unless_ok(await _check_access(credentials.credentials, None))


async def require_project_access(
    project_id: UUID,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
) -> None:
    """Gates a route on a valid bearer token that is a member of `project_id`."""
    if credentials is None:
        raise Unauthorized(headers=_BEARER_CHALLENGE)
    _raise_unless_ok(await _check_access(credentials.credentials, project_id))
