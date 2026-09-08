"""FastAPI dependencies that resolve and gate the current user."""

from typing import Annotated

from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials
from sqlmodel.ext.asyncio.session import AsyncSession

from falcoria_scanledger.auth.models import UserDB
from falcoria_scanledger.auth.security import authenticate_token, bearer_scheme
from falcoria_scanledger.database import get_session
from falcoria_scanledger.exceptions import PermissionDenied, Unauthorized

_BEARER_CHALLENGE = {"WWW-Authenticate": "Bearer"}


async def get_current_user(
    session: Annotated[AsyncSession, Depends(get_session)],
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
) -> UserDB | None:
    """Returns the authenticated user, or None when no valid bearer token is present."""
    if credentials is None:
        return None
    return await authenticate_token(session, credentials.credentials)


async def require_user(user: Annotated[UserDB | None, Depends(get_current_user)]) -> UserDB:
    """Returns the current user; raises 401 when the request is not authenticated."""
    if user is None:
        raise Unauthorized(headers=_BEARER_CHALLENGE)
    return user


async def require_admin(user: Annotated[UserDB, Depends(require_user)]) -> UserDB:
    """Returns the current user; raises 403 when that user is not an admin."""
    if not user.is_admin:
        raise PermissionDenied()
    return user
