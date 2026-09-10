"""FastAPI application factory and ASGI entry point."""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI

from falcoria_scanledger.auth.dependencies import require_admin, require_user
from falcoria_scanledger.auth.router import router as auth_router
from falcoria_scanledger.auth.service import ensure_primary_users
from falcoria_scanledger.config import get_app_settings
from falcoria_scanledger.constants import AUTH_RESPONSES, Tag
from falcoria_scanledger.database import dispose_engine, get_sessionmaker
from falcoria_scanledger.exceptions import register_exception_handlers
from falcoria_scanledger.history.router import router as history_router
from falcoria_scanledger.ips.router import router as ips_router
from falcoria_scanledger.projects.dependencies import validate_project_access
from falcoria_scanledger.projects.router import router as projects_router


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
    """Seeds the service accounts on startup, disposes the engine on exit.

    The schema is owned by Alembic — run ``alembic upgrade head`` before starting
    the process; the app never issues DDL.
    """
    settings = get_app_settings()
    async with get_sessionmaker()() as session:
        await ensure_primary_users(
            session,
            admin_token=settings.admin_token.get_secret_value(),
            tasker_token=settings.tasker_token.get_secret_value(),
        )
        await session.commit()
    yield
    await dispose_engine()


def create_app() -> FastAPI:
    """Builds the scanledger FastAPI application."""
    settings = get_app_settings()
    app = FastAPI(title="scanledger", debug=settings.debug, lifespan=lifespan)
    register_exception_handlers(app)

    app.include_router(
        auth_router,
        prefix=settings.api_prefix,
        dependencies=[Depends(require_admin)],
        responses=AUTH_RESPONSES,
    )
    app.include_router(
        projects_router,
        prefix=settings.api_prefix,
        dependencies=[Depends(require_user)],
        responses=AUTH_RESPONSES,
    )
    # ips is its own package, not a subpackage of projects; project_id in the
    # path only scopes it. validate_project_access already requires a user.
    app.include_router(
        ips_router,
        prefix=f"{settings.api_prefix}/projects/{{project_id}}/ips",
        dependencies=[Depends(validate_project_access)],
        responses=AUTH_RESPONSES,
    )
    app.include_router(
        history_router,
        prefix=f"{settings.api_prefix}/projects/{{project_id}}/history",
        dependencies=[Depends(validate_project_access)],
        responses=AUTH_RESPONSES,
    )

    @app.get("/health", tags=[Tag.META])
    async def health() -> dict[str, str]:
        """Reports that the process is up. Runs no dependency checks."""
        return {"status": "ok"}

    return app


app = create_app()
