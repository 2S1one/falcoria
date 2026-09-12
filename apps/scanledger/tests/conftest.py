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
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import URL, text
from sqlalchemy.ext.asyncio import create_async_engine
from sqlmodel import SQLModel
from sqlmodel.ext.asyncio.session import AsyncSession

# The `models` modules (`auth.models`, `projects.models`, ...) are imported for
# their side effect: registering their tables on SQLModel.metadata so
# `_build_schema`'s create_all() sees them. Add each new package's models module
# to this file as it lands (ips, history).
from falcoria_scanledger.auth import models  # noqa: F401
from falcoria_scanledger.auth.dependencies import require_admin
from falcoria_scanledger.auth.models import UserDB
from falcoria_scanledger.database import get_session
from falcoria_scanledger.history import models as history_models  # noqa: F401
from falcoria_scanledger.ips import models as ips_models  # noqa: F401
from falcoria_scanledger.main import create_app
from falcoria_scanledger.projects import models as projects_models  # noqa: F401

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


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Marks every test that (directly or via `client`) uses the `session` fixture as `postgres`.

    A marker added from inside a fixture (`request.node.add_marker(...)`) runs too late to
    affect `-m` deselection, which happens at collection time before any fixture executes —
    this hook is the fixture-agnostic way to do it correctly. `item.fixturenames` already
    includes `session` for any test using `client` too, since pytest resolves the full
    transitive fixture closure before collection.
    """
    for item in items:
        if isinstance(item, pytest.Function) and "session" in item.fixturenames:
            item.add_marker(pytest.mark.postgres)


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

    ``create_savepoint`` mode means every ``commit()`` / ``rollback()`` in the code
    under test acts on a SAVEPOINT, never the outer transaction — so committing
    services observe their writes while nothing persists between tests.
    """
    engine = create_async_engine(_pg_url(_TEST_DB))
    connection = await engine.connect()
    transaction = await connection.begin()
    try:
        async with AsyncSession(
            bind=connection, expire_on_commit=False, join_transaction_mode="create_savepoint"
        ) as s:
            yield s
    finally:
        # A failed flush (e.g. an IntegrityError the test asserts on) already
        # rolls the transaction back; only roll back one that is still open.
        if transaction.is_active:
            await transaction.rollback()
        await connection.close()
        await engine.dispose()


def _app_with_test_session(session: AsyncSession, *, stub_admin: bool) -> FastAPI:
    """Builds an app whose `get_session` yields `session` (mirroring commit/rollback).

    With `stub_admin` the `require_admin` gate is replaced by a synthetic admin so
    router tests exercise endpoint logic; without it the real auth chain runs.
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
    if stub_admin:
        app.dependency_overrides[require_admin] = lambda: UserDB(
            username="test-admin", is_admin=True
        )
    return app


@pytest.fixture
async def client(session: AsyncSession) -> AsyncIterator[AsyncClient]:
    """HTTP client with the DB session and the admin gate both overridden."""
    app = _app_with_test_session(session, stub_admin=True)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as http_client:
        yield http_client


@pytest.fixture
async def anon_client(session: AsyncSession) -> AsyncIterator[AsyncClient]:
    """HTTP client with only the DB session overridden — the real auth chain runs."""
    app = _app_with_test_session(session, stub_admin=False)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as http_client:
        yield http_client
