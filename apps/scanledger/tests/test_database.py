"""The process-wide engine's per-connection server settings."""

import os

import pytest
from sqlalchemy import URL, text

from falcoria_scanledger import database

pytestmark = [pytest.mark.anyio, pytest.mark.postgres]


def _test_url() -> URL:
    return URL.create(
        "postgresql+asyncpg",
        username=os.environ.get("SCANLEDGER_DB_USER", "scanledger"),
        password=os.environ.get("SCANLEDGER_DB_PASSWORD", "scanledger"),
        host=os.environ.get("SCANLEDGER_DB_HOST", "localhost"),
        port=int(os.environ.get("SCANLEDGER_DB_PORT", "5433")),
        database="scanledger",
    )


async def test_engine_ends_sessions_idle_in_transaction(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(database, "_database_url", _test_url)
    database.get_engine.cache_clear()
    try:
        async with database.get_engine().connect() as conn:
            value = (await conn.execute(text("SHOW idle_in_transaction_session_timeout"))).scalar()
        assert value == "1min"
    finally:
        await database.dispose_engine()
        database.get_engine.cache_clear()
