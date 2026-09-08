"""Database fixtures for the scanledger test suite.

A local Postgres must be reachable (``docker compose up -d postgres``). The suite
owns a separate ``scanledger_test`` database: `_schema` drops and recreates it
once per session, and `session` gives each test a transaction that is rolled back
at the end, so tests never see each other's writes.
"""

import asyncio
import os
from collections.abc import AsyncIterator

import pytest
from sqlalchemy import URL, text
from sqlalchemy.ext.asyncio import create_async_engine
from sqlmodel import SQLModel
from sqlmodel.ext.asyncio.session import AsyncSession

# Import each package's models module here so SQLModel.metadata is complete
# before create_all(). Added as packages land: projects, ips, history.
from falcoria_scanledger.auth import models  # noqa: F401  # registers UserDB on SQLModel.metadata

_MAINTENANCE_DB = "scanledger"
_TEST_DB = "scanledger_test"


def _pg_url(database: str) -> URL:
    return URL.create(
        "postgresql+asyncpg",
        username=os.environ.get("SCANLEDGER_DB_USER", "scanledger"),
        password=os.environ.get("SCANLEDGER_DB_PASSWORD", "scanledger"),
        host=os.environ.get("SCANLEDGER_DB_HOST", "localhost"),
        port=int(os.environ.get("SCANLEDGER_DB_PORT", "5433")),
        database=database,
    )


async def _build_schema() -> None:
    """Recreate the test database and apply the current SQLModel schema."""
    maintenance = create_async_engine(_pg_url(_MAINTENANCE_DB), isolation_level="AUTOCOMMIT")
    try:
        async with maintenance.connect() as conn:
            await conn.execute(text(f'DROP DATABASE IF EXISTS "{_TEST_DB}" WITH (FORCE)'))
            await conn.execute(text(f'CREATE DATABASE "{_TEST_DB}"'))
    finally:
        await maintenance.dispose()

    engine = create_async_engine(_pg_url(_TEST_DB))
    try:
        async with engine.begin() as conn:
            await conn.run_sync(SQLModel.metadata.create_all)
    finally:
        await engine.dispose()


@pytest.fixture(scope="session")
def _schema() -> None:
    """Build a fresh scanledger_test schema once for the whole test session.

    Sync on purpose: it runs its own event loop to completion so no asyncpg
    connection outlives it. The per-test `session` fixture opens its own
    loop-local engine.
    """
    asyncio.run(_build_schema())


@pytest.fixture
async def session(_schema: None) -> AsyncIterator[AsyncSession]:
    """Yields a session inside a transaction that is rolled back after the test.

    A ``commit()`` in the code under test lands on a savepoint (SQLAlchemy opens
    one because the bound connection is already in a transaction), so committing
    services still observe their writes while nothing persists between tests.
    """
    engine = create_async_engine(_pg_url(_TEST_DB))
    connection = await engine.connect()
    transaction = await connection.begin()
    try:
        async with AsyncSession(bind=connection, expire_on_commit=False) as s:
            yield s
    finally:
        # A failed flush (e.g. an IntegrityError the test asserts on) already
        # rolls the transaction back; only roll back one that is still open.
        if transaction.is_active:
            await transaction.rollback()
        await connection.close()
        await engine.dispose()
