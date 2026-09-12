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


async def _primary_users(session: AsyncSession) -> list[UserDB]:
    return list((await session.exec(select(UserDB).order_by(UserDB.username))).all())


async def test_ensure_primary_users_seeds_admin_tasker_and_worker(session: AsyncSession) -> None:
    await service.ensure_primary_users(
        session, admin_token="a-tok", tasker_token="t-tok", worker_token="w-tok"
    )

    rows = await _primary_users(session)
    assert [u.username for u in rows] == ["admin", "tasker", "worker"]
    assert all(u.is_admin for u in rows)
    assert all(u.token_expires_at is None for u in rows)
    assert {u.hashed_token for u in rows} == {
        tokens.hash_token("a-tok"),
        tokens.hash_token("t-tok"),
        tokens.hash_token("w-tok"),
    }


async def test_ensure_primary_users_rerun_with_same_tokens_is_stable(session: AsyncSession) -> None:
    await service.ensure_primary_users(
        session, admin_token="a-tok", tasker_token="t-tok", worker_token="w-tok"
    )
    await service.ensure_primary_users(
        session, admin_token="a-tok", tasker_token="t-tok", worker_token="w-tok"
    )

    rows = await _primary_users(session)
    assert [u.username for u in rows] == ["admin", "tasker", "worker"]


async def test_ensure_primary_users_rerun_resyncs_rotated_tokens(session: AsyncSession) -> None:
    await service.ensure_primary_users(
        session, admin_token="old-a", tasker_token="old-t", worker_token="old-w"
    )
    await service.ensure_primary_users(
        session, admin_token="new-a", tasker_token="new-t", worker_token="new-w"
    )

    rows = await _primary_users(session)
    assert len(rows) == 3
    assert {u.hashed_token for u in rows} == {
        tokens.hash_token("new-a"),
        tokens.hash_token("new-t"),
        tokens.hash_token("new-w"),
    }


@pytest.mark.parametrize(
    ("admin_token", "tasker_token", "worker_token"),
    [
        ("same", "same", "w-tok"),
        ("same", "t-tok", "same"),
        ("a-tok", "same", "same"),
    ],
)
async def test_ensure_primary_users_rejects_any_equal_pair(
    session: AsyncSession, admin_token: str, tasker_token: str, worker_token: str
) -> None:
    with pytest.raises(ValueError, match="must all differ"):
        await service.ensure_primary_users(
            session, admin_token=admin_token, tasker_token=tasker_token, worker_token=worker_token
        )
