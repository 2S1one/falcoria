"""FastAPI application factory and ASGI entry point."""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI

from falcoria_scanledger.auth.dependencies import require_admin
from falcoria_scanledger.auth.router import router as auth_router
from falcoria_scanledger.config import get_app_settings
from falcoria_scanledger.constants import Tag
from falcoria_scanledger.database import dispose_engine
from falcoria_scanledger.exceptions import register_exception_handlers


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
    """Disposes the database engine on shutdown; nothing else to wire yet."""
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
    )

    @app.get("/health", tags=[Tag.META])
    async def health() -> dict[str, str]:
        """Reports that the process is up. Runs no dependency checks."""
        return {"status": "ok"}

    return app


app = create_app()
