"""FastAPI application factory and ASGI entry point."""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI

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

    # routers included here under settings.api_prefix  -- added with the first router

    @app.get("/health", tags=[Tag.META])
    async def health() -> dict[str, str]:
        """Reports that the process is up. Runs no dependency checks."""
        return {"status": "ok"}

    return app


app = create_app()
