import os

import pytest

# Both apps' AppSettings have required fields; set deterministic dummies before any
# test imports either app (this root conftest loads before the package ones). Real
# env vars still win via setdefault.
os.environ.setdefault("SCANLEDGER_ADMIN_TOKEN", "test-admin-token")
os.environ.setdefault("SCANLEDGER_TASKER_TOKEN", "test-tasker-token")
os.environ.setdefault("TASKER_SCANLEDGER_BASE_URL", "http://scanledger.test/api")
os.environ.setdefault("TASKER_SCANLEDGER_TOKEN", "test-tasker-token")
os.environ.setdefault("WORKER_SCANLEDGER_BASE_URL", "http://scanledger.test/api")
os.environ.setdefault("WORKER_SCANLEDGER_TOKEN", "test-worker-token")
# ScanBatchWorkflow reads this once at import time (workflow sandbox forbids the
# file I/O a run()-time settings read would need) — must be set before any test
# imports falcoria_worker.temporal.workflows, not via a per-test fixture.
os.environ.setdefault("WORKER_WINDOW_SIZE", "2")


@pytest.fixture(scope="session")
def anyio_backend() -> str:
    """Pin anyio-marked async tests to the asyncio backend (no trio in this stack)."""
    return "asyncio"
