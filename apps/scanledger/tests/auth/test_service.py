import pytest
from sqlalchemy.exc import IntegrityError
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from falcoria_scanledger.auth import service, tokens
from falcoria_scanledger.auth.models import UserDB
from falcoria_scanledger.auth.schemas import UserCreate

pytestmark = pytest.mark.anyio


async def test_create_user_returns_row_and_plaintext_token(session: AsyncSession) -> None:
    user, plaintext = await service.create_user(session, UserCreate(username="alice"))

    assert user.id is not None
    assert user.is_admin is False
    assert user.token_expires_at is None
    assert len(plaintext) == 60
    assert user.hashed_token == tokens.hash_token(plaintext)


async def test_create_user_sets_expiry_from_lifetime(session: AsyncSession) -> None:
    user, _ = await service.create_user(session, UserCreate(username="bob", token_lifetime=3600))

    assert user.token_expires_at is not None


async def test_create_user_rejects_duplicate_username(session: AsyncSession) -> None:
    await service.create_user(session, UserCreate(username="carol"))

    with pytest.raises(IntegrityError):
        await service.create_user(session, UserCreate(username="carol"))


async def test_ensure_primary_users_seeds_admin_and_tasker(session: AsyncSession) -> None:
    await service.ensure_primary_users(session, admin_token="a-tok", tasker_token="t-tok")

    rows = (await session.exec(select(UserDB).order_by(UserDB.username))).all()
    assert [u.username for u in rows] == ["admin", "tasker"]
    assert all(u.is_admin for u in rows)
    assert all(u.token_expires_at is None for u in rows)
    assert {u.hashed_token for u in rows} == {
        tokens.hash_token("a-tok"),
        tokens.hash_token("t-tok"),
    }


async def test_ensure_primary_users_is_idempotent(session: AsyncSession) -> None:
    await service.ensure_primary_users(session, admin_token="a-tok", tasker_token="t-tok")
    await service.ensure_primary_users(session, admin_token="other", tasker_token="other")

    rows = (await session.exec(select(UserDB))).all()
    assert len(rows) == 2
    assert {u.hashed_token for u in rows} == {
        tokens.hash_token("a-tok"),
        tokens.hash_token("t-tok"),
    }
