from datetime import UTC, datetime, timedelta

import pytest
from sqlmodel.ext.asyncio.session import AsyncSession

from falcoria_scanledger.auth import service, tokens
from falcoria_scanledger.auth.models import UserDB
from falcoria_scanledger.auth.schemas import UserCreate
from falcoria_scanledger.auth.security import authenticate_token

pytestmark = pytest.mark.anyio


async def test_authenticate_token_returns_the_owner(session: AsyncSession) -> None:
    user, plaintext = await service.create_user(session, UserCreate(username="dana"))

    found = await authenticate_token(session, plaintext)

    assert found is not None
    assert found.id == user.id


async def test_authenticate_token_unknown_token_returns_none(session: AsyncSession) -> None:
    await service.create_user(session, UserCreate(username="erin"))

    assert await authenticate_token(session, "not-a-real-token") is None


async def test_authenticate_token_expired_token_returns_none(session: AsyncSession) -> None:
    past = datetime.now(UTC) - timedelta(hours=1)
    session.add(
        UserDB(username="frank", hashed_token=tokens.hash_token("frank-tok"), token_expires_at=past)
    )
    await session.flush()

    assert await authenticate_token(session, "frank-tok") is None
