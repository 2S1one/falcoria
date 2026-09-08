import pytest
from sqlalchemy import text
from sqlmodel.ext.asyncio.session import AsyncSession

pytestmark = pytest.mark.anyio


async def test_session_fixture_executes(session: AsyncSession) -> None:
    connection = await session.connection()
    result = await connection.execute(text("SELECT 1"))
    assert result.scalar_one() == 1
