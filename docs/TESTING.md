# Testing

Basic run commands are in `MAP.md`. This file covers what's non-obvious: marker-gated
external services, fixture patterns, and import-order constraints specific to this repo.

## Markers and what they need running

- `postgres` — needs `docker compose -f compose.dev.yaml up -d postgres` (or an equivalent
  Postgres reachable at `SCANLEDGER_DB_*`/port `5433` by default in dev).
- `temporal` — needs a real Temporal cluster (`docker compose -f compose.dev.yaml up -d
  temporal temporal-ui`).
- Default `uv run pytest` runs everything, including marked tests, and will fail without
  those services. `uv run pytest -m "not postgres and not temporal"` is the fast path used in
  CI's `test` job (`.github/workflows/ci.yml`).

## Root `conftest.py` — env vars before import

The workspace-root `conftest.py` sets `os.environ.setdefault(...)` for every cross-service
token (`SCANLEDGER_ADMIN_TOKEN`, `SCANLEDGER_TASKER_TOKEN`, `SCANLEDGER_WORKER_TOKEN`,
`TASKER_SCANLEDGER_*`, `WORKER_SCANLEDGER_*`) and `WORKER_WINDOW_SIZE`, *before* any test
module imports either app. This exists because this root conftest loads before any package's
own conftest, and `falcoria_worker.temporal.workflows` reads `WORKER_WINDOW_SIZE` at import
time — inside the Temporal workflow sandbox, a runtime settings read would trigger blocked
file I/O (see `INVARIANTS.md`). A test that imports `falcoria_worker.temporal.workflows`
before this conftest has run (e.g. via an unusual `--import-mode` or a script outside
pytest) will fail or read stale defaults.

## scanledger DB fixtures (`apps/scanledger/tests/conftest.py`)

- Session-scoped `_schema` fixture drops and recreates a dedicated `scanledger_test`
  database once per test session, then runs `SQLModel.metadata.create_all()` — schema comes
  from the SQLModel models directly, not from Alembic, so a test-only schema can drift from
  what `alembic upgrade head` produces if a migration and its model definition disagree.
- Each test gets its own DB transaction via the `session` fixture, rolled back at the end —
  tests never see each other's writes, and no per-test cleanup code is needed.
  `_MAINTENANCE_DB`/`_TEST_DB` are the two database names involved.
- Every submodule's `models` module (`auth.models`, `projects.models`, `ips.models`,
  `history.models`, `port_prevalence.models`) is imported at the top of this conftest for the
  side effect of registering its tables on `SQLModel.metadata` (`# noqa: F401`) — a new
  submodule's models file must be added to this import list or its tables won't exist in the
  test schema.

## anyio

Async tests use `pytestmark = pytest.mark.anyio` at the top of the file. The `anyio_backend`
fixture (root `conftest.py`) pins every anyio-marked test to `asyncio` — there is no trio
backend in this stack, so a test that needs a different backend needs its own override, not
a change to the shared fixture.

## Docker-build verification (not pytest)

`docker-build-check` in CI (`.github/workflows/ci.yml`) does `docker build -f
apps/<app>/Dockerfile .` for whichever app's dependency set changed, per the `changes` job's
path filters — this is a build-succeeds check, not a test run. See `INTEGRATIONS.md` for the
filter-list-must-match-pyproject.toml invariant.
