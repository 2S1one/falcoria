import os

import pytest

# Both apps' AppSettings have required fields; set deterministic dummies before any
# test imports either app (this root conftest loads before the package ones). Real
# env vars still win via setdefault.
os.environ.setdefault("SCANLEDGER_ADMIN_TOKEN", "test-admin-token")
os.environ.setdefault("SCANLEDGER_TASKER_TOKEN", "test-tasker-token")
os.environ.setdefault("TASKER_SCANLEDGER_BASE_URL", "http://scanledger.test/api")
os.environ.setdefault("TASKER_SCANLEDGER_TOKEN", "test-tasker-token")


@pytest.fixture(scope="session")
def anyio_backend() -> str:
    """Pin anyio-marked async tests to the asyncio backend (no trio in this stack)."""
    return "asyncio"
