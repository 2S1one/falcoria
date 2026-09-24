"""Async database engine, session factory, and the request-scoped session dependency."""

from collections.abc import AsyncGenerator
from functools import lru_cache

from sqlalchemy import URL
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine
from sqlmodel.ext.asyncio.session import AsyncSession

from falcoria_scanledger.config import get_db_settings


def _database_url() -> URL:
    """Builds the asyncpg connection URL from settings, escaping credentials safely."""
    s = get_db_settings()
    return URL.create(
        drivername="postgresql+asyncpg",
        username=s.user,
        password=s.password.get_secret_value(),
        host=s.host,
        port=s.port,
        database=s.name,
    )


@lru_cache
def get_engine() -> AsyncEngine:
    """Returns the process-wide async engine, created on first use."""
    return create_async_engine(
        _database_url(),
        echo=get_db_settings().echo,
        pool_pre_ping=True,
        # An open transaction holds back the event feed for every project, so a
        # session left idle inside one is ended by the server after 60 s.
        connect_args={"server_settings": {"idle_in_transaction_session_timeout": "60000"}},
    )


@lru_cache
def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    """Returns the process-wide session factory bound to the engine."""
    return async_sessionmaker(get_engine(), class_=AsyncSession, expire_on_commit=False)


async def dispose_engine() -> None:
    """Disposes the engine's connection pool; called on application shutdown."""
    if get_engine.cache_info().currsize:
        await get_engine().dispose()


async def get_session() -> AsyncGenerator[AsyncSession]:
    """Yields a request-scoped session; commits on success, rolls back on any error.

    One unit of work per request. Services and repositories receive this session
    and never commit, roll back or close it themselves — a service may `flush()`
    when it needs a generated id, and may `commit()` explicitly when it must act
    on the committed state (the dependency's own commit is then a no-op).
    """
    factory = get_sessionmaker()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
