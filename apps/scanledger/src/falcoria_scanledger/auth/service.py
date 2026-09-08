"""Identity service: transaction-scoped user and token operations."""

from sqlalchemy.dialects.postgresql import insert as pg_insert
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


async def _upsert_primary_user(session: AsyncSession, username: str, token: str) -> None:
    """Inserts an admin account or re-syncs its token hash to the given value."""
    digest = tokens.hash_token(token)
    statement = (
        pg_insert(UserDB)
        .values(username=username, is_admin=True, hashed_token=digest)
        .on_conflict_do_update(
            index_elements=["username"],
            set_={"hashed_token": digest, "is_admin": True},
        )
    )
    connection = await session.connection()
    await connection.execute(statement)


async def ensure_primary_users(
    session: AsyncSession, *, admin_token: str, tasker_token: str
) -> None:
    """Creates or re-syncs the `admin` and `tasker` accounts from configuration.

    Runs on every startup: concurrency-safe (atomic ``INSERT ... ON CONFLICT DO
    UPDATE`` keyed on username) and it overwrites each account's stored token
    hash with the configured value, so rotating a token in the environment takes
    effect on the next boot.

    Raises:
        ValueError: `admin_token` and `tasker_token` are equal.
    """
    if admin_token == tasker_token:
        raise ValueError("admin and tasker tokens must differ")
    await _upsert_primary_user(session, "admin", admin_token)
    await _upsert_primary_user(session, "tasker", tasker_token)
