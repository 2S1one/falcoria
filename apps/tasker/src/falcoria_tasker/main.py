"""FastAPI application factory and ASGI entry point."""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from falcoria_tasker.config import Env, get_app_settings
from falcoria_tasker.constants import Tag
from falcoria_tasker.dns import dispose_dns_resolver, init_dns_resolver
from falcoria_tasker.exceptions import register_exception_handlers
from falcoria_tasker.scanledger import dispose_scanledger_client
from falcoria_tasker.temporal.client import connect_temporal, dispose_temporal


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
    """Connects Temporal and primes the DNS resolver on startup; disposes both in reverse."""
    await connect_temporal()
    init_dns_resolver()
    yield
    await dispose_dns_resolver()
    await dispose_temporal()
    await dispose_scanledger_client()


def create_app() -> FastAPI:
    """Builds the tasker FastAPI application."""
    settings = get_app_settings()
    hide_docs = settings.env is Env.PROD
    app = FastAPI(
        title="tasker",
        debug=settings.debug,
        lifespan=lifespan,
        docs_url=None if hide_docs else "/docs",
        redoc_url=None if hide_docs else "/redoc",
        openapi_url=None if hide_docs else "/openapi.json",
    )
    register_exception_handlers(app)

    @app.get("/health", tags=[Tag.META])
    async def health() -> dict[str, str]:
        """Reports that the process is up. Runs no dependency checks."""
        return {"status": "ok"}

    return app


app = create_app()
