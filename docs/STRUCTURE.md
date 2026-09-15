# Structure

What lives where. Ownership only — for "where do I start to do X," see `NAVIGATION.md`.

## Repository root

```
falcoria/
  apps/                 three deployable services (scanledger, tasker, worker) + falcli (not built)
  packages/              four workspace-shared libraries
  deploy/ansible/         multi-node deployment automation (Zero-Trust mTLS)
  scripts/                 dev-environment shell scripts (Temporal namespace init, .env generation)
  dynamicconfig/            Temporal dev-cluster dynamic config, mounted into the dev compose stack
  refactor/                gitignored: rebuild planning notes, decision log, session handoffs
  compose.dev.yaml         local dev stack: Postgres + Temporal (+ UI), no app containers
  compose.prod.yaml        production stack: all services, zero-trust networking
  conftest.py             workspace-root pytest fixtures (shared env-var defaults, anyio backend)
  pyproject.toml           uv workspace root: ruff/pyright/pytest/commitizen config
```

## Top-level directories

| Path | Purpose |
|---|---|
| `apps/scanledger/` | System of record: projects, IP/port inventory, change history, auth. FastAPI + SQLModel + asyncpg + Alembic. |
| `apps/tasker/` | API server + Temporal client: starts/tracks/cancels scans, reports worker-fleet status. No Temporal worker runs here. |
| `apps/worker/` | Temporal worker: runs nmap as a subprocess, uploads XML results to scanledger. No HTTP server. |
| `apps/falcli/` | Console client. Not created yet. |
| `packages/falcoria-contracts/` | Shared pydantic DTOs, enums, and plain constants (scan I/O, Temporal names, worker identity). Pydantic + stdlib only, no `temporalio`. |
| `packages/falcoria-http/` | One shared class: `RetryingTransport`, a retrying async httpx transport for tasker/worker service calls. |
| `packages/falcoria-logging/` | One shared function: `configure_logging`, stdout-only process logging (JSON outside `local` env). Stdlib only. |
| `packages/falcoria-temporal/` | Temporal SDK glue that needs `temporalio`: pinned pydantic data converter, pre-built search-attribute keys. |
| `deploy/ansible/` | Ansible playbooks/roles for the two-tier (control-plane / workers) production deployment. See `deploy/ansible/AGENTS.md`. |
| `scripts/` | `init-temporal.sh` (registers the `default` namespace on `docker compose up`), `generate-env.sh`. |
| `dynamicconfig/` | `development-sql.yaml`, mounted into the dev Temporal container. |

## Package internals (src-layout)

Every member follows `<member>/src/<import_name>/`, mirrored by `<member>/tests/`.

```
apps/scanledger/src/falcoria_scanledger/
  main.py              FastAPI app factory + lifespan
  config.py             AppSettings / DatabaseSettings (env prefix SCANLEDGER_)
  database.py            async engine/session-factory, get_session() unit-of-work dependency
  constants.py            OpenAPI Tag enum, AUTH_RESPONSES
  exceptions.py            DetailedHTTPException hierarchy + handler registration
  auth/                    users, bearer tokens, admin user-management API, require_user/require_admin
  projects/                 projects + project membership
  ips/                       IP/port inventory: models, nmap-XML import pipeline, search, facets, router
  history/                    append-only port-change log (read + bulk-delete), written by ips/
apps/scanledger/migrations/  Alembic: env.py, versions/, script.py.mako

apps/tasker/src/falcoria_tasker/
  main.py              FastAPI app factory + lifespan (Temporal client, DNS resolver)
  config.py             AppSettings / TemporalSettings (env prefix TASKER_)
  security.py            require_token / require_project_access (delegate to scanledger, 45s cache)
  scanledger.py           ScanledgerClient: tasker's HTTP client to scanledger
  dns.py                   process-wide aiodns.DNSResolver lifecycle
  concurrency.py            bounded_gather() semaphore helper
  scans/                    scan-orchestration vertical slice (router, service, schemas, resolve, scanner_args, sharding, targets)
  temporal/                  Temporal client-side ops (start/query/cancel) — no @workflow.defn here
  workers/                    worker-fleet visibility (distinct from apps/worker): router, service, schemas

apps/worker/src/falcoria_worker/
  main.py              Temporal worker process entrypoint
  config.py             AppSettings / TemporalSettings / TemporalTLSSettings (env prefix WORKER_)
  scanledger.py           ScanledgerClient: uploads nmap XML reports
  exceptions.py            WorkerError hierarchy (CommandExecutionError, CommandTimeoutError, ScanUploadError)
  nmap/                    AsyncCommandExecutor (subprocess lifecycle), scanner.py (two-phase scan orchestration), xml.py (pure XML parse/merge)
  temporal/                 @workflow.defn / @activity.defn definitions live here (ScanBatchWorkflow, ScanWorkflow, ScanActivities)

packages/falcoria-contracts/src/falcoria_contracts/   enums.py, port.py, scan_io.py, temporal_names.py, worker_identity.py
packages/falcoria-http/src/falcoria_http/              transport.py (RetryingTransport)
packages/falcoria-logging/src/falcoria_logging/         configure.py (configure_logging)
packages/falcoria-temporal/src/falcoria_temporal/        converter.py, search_attributes.py
```

Test directories mirror source 1:1 under each member's `tests/` (e.g.
`apps/scanledger/tests/ips/test_facets.py` for `apps/scanledger/src/falcoria_scanledger/ips/facets.py`)
and are skipped from this table's row purpose per the output contract.
