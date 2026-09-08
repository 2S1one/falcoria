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
from httpx import ASGITransport, AsyncClient
from sqlalchemy import URL, text
from sqlalchemy.ext.asyncio import create_async_engine
from sqlmodel import SQLModel
from sqlmodel.ext.asyncio.session import AsyncSession

# `auth.models` is imported for its side effect: it registers UserDB on
# SQLModel.metadata so `_build_schema`'s create_all() sees the table. Add each
# new package's models module here as it lands (projects, ips, history).
from falcoria_scanledger.auth import models  # noqa: F401
from falcoria_scanledger.auth.dependencies import require_admin
from falcoria_scanledger.auth.models import UserDB
from falcoria_scanledger.database import get_session
from falcoria_scanledger.main import create_app

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


@pytest.fixture
async def client(session: AsyncSession) -> AsyncIterator[AsyncClient]:
    """HTTP client for the app; the DB session and the admin gate are overridden.

    `get_session` yields the test's rolled-back `session` and mirrors the real
    dependency's commit/rollback; `require_admin` is stubbed so router tests
    exercise endpoint logic, not the auth chain (that is `test_admin_gate.py`).
    """

    async def _session_override() -> AsyncIterator[AsyncSession]:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise

    app = create_app()
    app.dependency_overrides[get_session] = _session_override
    app.dependency_overrides[require_admin] = lambda: UserDB(username="test-admin", is_admin=True)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as http_client:
        yield http_client
