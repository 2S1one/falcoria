import os

import pytest

# scanledger's AppSettings has required token fields; set deterministic dummies before
# any test imports the app (this root conftest loads before the package one). Real env
# vars still win via setdefault.
os.environ.setdefault("SCANLEDGER_ADMIN_TOKEN", "test-admin-token")
os.environ.setdefault("SCANLEDGER_TASKER_TOKEN", "test-tasker-token")


@pytest.fixture(scope="session")
def anyio_backend() -> str:
    """Pin anyio-marked async tests to the asyncio backend (no trio in this stack)."""
    return "asyncio"
