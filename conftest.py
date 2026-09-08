import pytest


@pytest.fixture(scope="session")
def anyio_backend() -> str:
    """Pin anyio-marked async tests to the asyncio backend (no trio in this stack)."""
    return "asyncio"
