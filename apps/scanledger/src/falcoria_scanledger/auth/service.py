"""Identity service: transaction-scoped user and token operations."""

import uuid
from collections.abc import Sequence

from sqlalchemy.dialects.postgresql import insert as pg_insert
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


async def list_users(session: AsyncSession) -> Sequence[UserDB]:
    """Returns every user, ordered by username."""
    return (await session.exec(select(UserDB).order_by(UserDB.username))).all()


async def delete_user(session: AsyncSession, user_id: uuid.UUID) -> bool:
    """Deletes `user_id`; returns whether a row was removed."""
    user = await session.get(UserDB, user_id)
    if user is None:
        return False
    await session.delete(user)
    await session.flush()
    return True


async def rotate_token(
    session: AsyncSession, user_id: uuid.UUID, lifetime_seconds: int | None
) -> str | None:
    """Issues a fresh token for `user_id` and returns the plaintext, or None if unknown.

    The previous token is revoked — its hash is overwritten. Flushes; the
    surrounding request transaction commits.
    """
    user = await session.get(UserDB, user_id)
    if user is None:
        return None
    plaintext = tokens.generate_token()
    user.hashed_token = tokens.hash_token(plaintext)
    user.token_expires_at = tokens.expiry_from(lifetime_seconds)
    await session.flush()
    return plaintext


async def _upsert_primary_user(session: AsyncSession, username: str, token: str) -> None:
    """Inserts an admin account or re-syncs it to a non-expiring config-owned token."""
    digest = tokens.hash_token(token)
    # token_expires_at is forced back to NULL: a prior API rotation may have set a
    # finite expiry, and these accounts are non-expiring by contract.
    statement = (
        pg_insert(UserDB)
        .values(username=username, is_admin=True, hashed_token=digest, token_expires_at=None)
        .on_conflict_do_update(
            index_elements=["username"],
            set_={"hashed_token": digest, "is_admin": True, "token_expires_at": None},
        )
    )
    connection = await session.connection()
    await connection.execute(statement)


async def ensure_primary_users(
    session: AsyncSession,
    *,
    admin_token: str,
    tasker_token: str,
    worker_token: str,
    asm_token: str | None = None,
) -> None:
    """Creates or re-syncs the config-seeded `admin`, `tasker`, `worker`, `asm` accounts.

    Runs on every startup: concurrency-safe (atomic ``INSERT ... ON CONFLICT DO
    UPDATE`` keyed on username) and it overwrites each account's stored token
    hash with the configured value, so rotating a token in the environment takes
    effect on the next boot. ``asm`` is seeded only when ``asm_token`` is
    non-empty; unsetting it later leaves an already-seeded account in place.

    Raises:
        ValueError: any two of the configured tokens are equal.
    """
    accounts = {"admin": admin_token, "tasker": tasker_token, "worker": worker_token}
    if asm_token:
        accounts["asm"] = asm_token
    if len(set(accounts.values())) != len(accounts):
        raise ValueError(f"{', '.join(accounts)} tokens must all differ")
    for username, token in accounts.items():
        await _upsert_primary_user(session, username, token)
