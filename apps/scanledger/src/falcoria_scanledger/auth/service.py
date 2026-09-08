"""Identity service: transaction-scoped user and token operations."""

from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from falcoria_scanledger.auth import tokens
from falcoria_scanledger.auth.models import UserDB
from falcoria_scanledger.auth.schemas import UserCreate


async def create_user(session: AsyncSession, data: UserCreate) -> tuple[UserDB, str]:
    """Creates a user and returns the row plus its plaintext token (shown once).

    Flushes so the caller sees the generated id; the surrounding request
    transaction commits. Only the token hash is stored. A duplicate username
    surfaces as ``sqlalchemy.exc.IntegrityError`` on flush.
    """
    plaintext = tokens.generate_token()
    user = UserDB(
        **data.model_dump(exclude={"token_lifetime"}),
        hashed_token=tokens.hash_token(plaintext),
        token_expires_at=tokens.expiry_from(data.token_lifetime),
    )
    session.add(user)
    await session.flush()
    return user, plaintext


async def _ensure_admin_account(session: AsyncSession, username: str, token: str) -> None:
    """Adds an admin account with `username` if it does not already exist."""
    existing = await session.exec(select(UserDB.id).where(UserDB.username == username))
    if existing.first() is None:
        session.add(UserDB(username=username, is_admin=True, hashed_token=tokens.hash_token(token)))


async def ensure_primary_users(
    session: AsyncSession, *, admin_token: str, tasker_token: str
) -> None:
    """Seeds the `admin` and `tasker` accounts when absent; a no-op otherwise.

    Idempotent — safe on every startup. Both are admin accounts with
    non-expiring tokens taken from configuration.
    """
    await _ensure_admin_account(session, "admin", admin_token)
    await _ensure_admin_account(session, "tasker", tasker_token)
    await session.flush()
