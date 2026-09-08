"""Bearer-scheme wiring and token-to-user resolution."""

from fastapi.security import HTTPBearer
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from falcoria_scanledger.auth import tokens
from falcoria_scanledger.auth.models import UserDB

bearer_scheme = HTTPBearer(auto_error=False)


async def authenticate_token(session: AsyncSession, raw_token: str) -> UserDB | None:
    """Returns the user a bearer token belongs to, or None if it is unknown or expired.

    Raises nothing — the caller decides whether a missing user is a 401. Runs one
    indexed lookup on ``users.hashed_token``.
    """
    digest = tokens.hash_token(raw_token)
    result = await session.exec(select(UserDB).where(UserDB.hashed_token == digest))
    user = result.one_or_none()
    if user is None or tokens.is_expired(user.token_expires_at):
        return None
    return user
