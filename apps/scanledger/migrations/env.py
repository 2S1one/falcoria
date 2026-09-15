"""Alembic migration environment for falcoria-scanledger.

The database URL comes from the app settings (``SCANLEDGER_DB_*``), never from
``alembic.ini``. Every package's ``models`` module is imported so its tables are
registered on ``SQLModel.metadata`` before autogenerate compares.
"""

import asyncio
from logging.config import fileConfig
from typing import Any, Literal

from alembic import context
from alembic.autogenerate.api import AutogenContext
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import create_async_engine
from sqlmodel import SQLModel
from sqlmodel.sql.sqltypes import AutoString

from falcoria_scanledger.auth import models as auth_models  # noqa: F401
from falcoria_scanledger.database import _database_url
from falcoria_scanledger.history import models as history_models  # noqa: F401
from falcoria_scanledger.ips import models as ips_models  # noqa: F401
from falcoria_scanledger.port_prevalence import models as port_prevalence_models  # noqa: F401
from falcoria_scanledger.projects import models as projects_models  # noqa: F401

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = SQLModel.metadata


def _render_item(type_: str, obj: Any, autogen_context: AutogenContext) -> str | Literal[False]:
    """Render SQLModel's ``AutoString`` as plain ``sa.String()`` in revisions.

    Keeps generated migrations free of a ``sqlmodel`` import. The models never
    set a string length, so no argument is lost.
    """
    if type_ == "type" and isinstance(obj, AutoString):
        return "sa.String()"
    return False


def run_migrations_offline() -> None:
    """Emit SQL to stdout using a URL only, without opening a DB connection."""
    context.configure(
        url=_database_url().render_as_string(hide_password=False),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_item=_render_item,
    )
    with context.begin_transaction():
        context.run_migrations()


def _run_migrations(connection: Connection) -> None:
    context.configure(
        connection=connection, target_metadata=target_metadata, render_item=_render_item
    )
    with context.begin_transaction():
        context.run_migrations()


async def _run_async_migrations() -> None:
    engine = create_async_engine(_database_url(), poolclass=pool.NullPool)
    try:
        async with engine.connect() as connection:
            await connection.run_sync(_run_migrations)
    finally:
        await engine.dispose()


def run_migrations_online() -> None:
    """Open an async engine from the app settings and run migrations on it."""
    asyncio.run(_run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
