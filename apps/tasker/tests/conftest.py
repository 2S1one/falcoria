"""Shared fixtures for tasker's route-level tests."""

from collections.abc import AsyncIterator

import pytest
from httpx import ASGITransport, AsyncClient

from falcoria_tasker.main import app
from falcoria_tasker.security import require_project_access, require_token


@pytest.fixture
async def client() -> AsyncIterator[AsyncClient]:
    """An HTTP client against the app with auth stubbed out (always allowed)."""
    app.dependency_overrides[require_project_access] = lambda: None
    app.dependency_overrides[require_token] = lambda: None
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as http_client:
        yield http_client
    app.dependency_overrides.clear()
