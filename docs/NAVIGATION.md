# Navigation

## Task-oriented routing

| Task | Start at | Then check |
|---|---|---|
| Add a scanledger HTTP route | the relevant `apps/scanledger/src/falcoria_scanledger/<area>/router.py` | matching `service.py` for logic, `schemas.py` for request/response DTOs, `main.py` for auth-dependency mounting (see `ARCHITECTURE.md` entrypoints) |
| Add a tasker HTTP route | `apps/tasker/src/falcoria_tasker/scans/router.py` or `workers/router.py` | `scans/service.py` for orchestration, `main.py` for router mounting/auth dependency |
| Change what a scan does (nmap args, ports, timeout) | `apps/tasker/src/falcoria_tasker/scans/scanner_args.py` and `sharding.py` (pure, build the `ScanTask`) | `packages/falcoria-contracts/src/falcoria_contracts/scan_io.py` (`ScanTask` field contract) if the shape changes — ask first, it's a cross-service contract |
| Change the Temporal workflow shape (fan-out, retries, timeouts) | `apps/worker/src/falcoria_worker/temporal/workflows.py` (`ScanBatchWorkflow`, `ScanWorkflow`) | `apps/worker/tests/temporal/test_workflows.py`; `apps/tasker/src/falcoria_tasker/temporal/workflows.py` if the query/cancel client contract changes |
| Change how nmap is invoked or its output parsed | `apps/worker/src/falcoria_worker/nmap/scanner.py` (argv construction, two-phase logic) and `nmap/xml.py` (parse/merge) | `apps/worker/tests/nmap/`; the security invariant that argv stays list-form (see `INVARIANTS.md`) |
| Add/change a DB table or column | the relevant `<area>/models.py` under `apps/scanledger/src/falcoria_scanledger/` | generate a migration — see `TESTING.md`/`MAP.md` verification block; ask first per `AGENTS.md` (DB schema changes need sign-off) |
| Add/change a shared contract type (`falcoria-contracts`) | `packages/falcoria-contracts/src/falcoria_contracts/` | every consumer: `apps/scanledger`, `apps/tasker`, `apps/worker` — ask first, this is a cross-service contract change per `AGENTS.md` |
| Add a workspace dependency to one member | `uv add --package <dist-name> <pkg>` from repo root | if the member is an `apps/*` Docker image, update `.github/workflows/ci.yml`'s `changes` job filter for that app (see `INTEGRATIONS.md`) — ask first |
| Change auth / token issuance | `apps/scanledger/src/falcoria_scanledger/auth/` (`tokens.py`, `service.py`, `dependencies.py`) | `apps/tasker/src/falcoria_tasker/security.py` (relays tokens, doesn't reimplement checks) |
| Change TLS / mTLS between worker and Temporal | `apps/worker/src/falcoria_worker/temporal/client.py` (`_build_tls_config`) and `config.py` (`TemporalTLSSettings`) | `deploy/ansible/AGENTS.md` PKI section; `apps/worker/tests/temporal/test_tls.py` |
| Change deployment topology or ports | `deploy/ansible/roles/control_plane/` or `roles/worker/` | `deploy/ansible/AGENTS.md` invariants (zero-trust ports, `network_mode: host` for workers) — this area has its own AGENTS.md, follow it strictly |
| Add a test | mirror the source path under the member's `tests/` | `conftest.py` (root, sets cross-app token env defaults) and the member's own `tests/conftest.py` |

## Symbol index (non-entrypoint, on a runtime-flow path)

Format: `path#symbol — what it does, when to open it`. Entrypoints (`create_app`, `main`,
router handler functions) are in `ARCHITECTURE.md`'s entrypoints table and flow diagrams —
not repeated here.

### scanledger

- `apps/scanledger/src/falcoria_scanledger/database.py#get_session` — request-scoped unit-of-work dependency; commits on success, rolls back on exception. Open when touching any DB-writing service function to understand who owns the transaction.
- `apps/scanledger/src/falcoria_scanledger/auth/tokens.py#generate_token` / `#hash_token` — 60-char base62 token generation and unsalted SHA-256 hashing. Open when changing token format or lookup.
- `apps/scanledger/src/falcoria_scanledger/auth/service.py#ensure_primary_users` — upserts the `admin`/`tasker`/`worker` (and optional `asm`) seed accounts on every startup. Open when changing how service-account tokens are provisioned.
- `apps/scanledger/src/falcoria_scanledger/projects/dependencies.py#validate_project_access` — the single membership/admin gate mounted on `ips_router`, `history_router` and `events_router`. Open when changing project-level authorization.
- `apps/scanledger/src/falcoria_scanledger/ips/reconcile.py#close_stale_port` — REPLACE-mode close-rule logic (absent-but-out-of-range ports stay open). Open when changing import-mode merge semantics.
- `apps/scanledger/src/falcoria_scanledger/ips/nmap.py` (`NmapReport`/`NmapHost`/`NmapPort`/`NmapService`) — parse-only models for inbound nmap XML, never serialized to clients. Open when the import pipeline needs a new nmap XML field.
- `apps/scanledger/src/falcoria_scanledger/history/models.py#IPPortHistoryDB` — append-only log; uniqueness key makes re-importing the same scan a no-op. Open when changing what counts as a "change."
- `apps/scanledger/src/falcoria_scanledger/events/build.py#build_event` — pure: stored snapshot + `ChangeSet` -> `IPChangedEvent` or None (the emission rule lives here). Open when changing what produces an event or what it carries.
- `apps/scanledger/src/falcoria_scanledger/events/schemas.py#IPChangedEvent` — the published event contract; `PortDelta`/`HostnameDelta` validators enforce `current == old + added - removed`. Open before changing anything a consumer reads.
- `apps/scanledger/src/falcoria_scanledger/events/service.py#write_events` / `#read_events` — stage outbox rows in the import's transaction; read the feed by `(txid, id)` cursor. Open when changing delivery or cursor semantics.
- `apps/scanledger/migrations/env.py` — Alembic environment; imports every submodule's `models` so autogenerate sees the full `SQLModel.metadata`. Open when a new model file needs to be picked up by autogenerate.
- `apps/scanledger/src/falcoria_scanledger/port_prevalence/parser.py#parse_nmap_services` — turns `nmap-services`-format lines into `ParsedPortPrevalence(number, protocol, score)`, skipping comments/blanks and protocols outside `PortProtocol` (e.g. `sctp`). Open when the source file's format needs re-parsing logic.
- `apps/scanledger/src/falcoria_scanledger/port_prevalence/sync.py#sync_port_prevalence` — delete-all-then-bulk-insert of `port_prevalence` from parsed entries, one transaction; raises on an empty entry list rather than emptying the table. Open when changing how the reference table gets (re)populated.

### tasker

- `apps/tasker/src/falcoria_tasker/scans/service.py#run_scan` — the orchestration pipeline: dedupe → resolve → (INSERT-mode dedup against scanledger + Temporal) → shard → start workflows. Open when changing what happens before a scan is submitted to Temporal.
- `apps/tasker/src/falcoria_tasker/scans/targets.py` — pure dedup/partition of hosts (IP-literal vs hostname vs private), no I/O. Open when changing target classification rules.
- `apps/tasker/src/falcoria_tasker/scans/resolve.py#resolve_targets` — concurrent aiodns hostname resolution with retries. Open when changing DNS resolution behavior.
- `apps/tasker/src/falcoria_tasker/temporal/workflows.py#start_batch_workflows` / `#scan_progress` / `#start_cancel_batch` / `#start_terminate_batch` — tasker's Temporal client-facade functions (this file defines no `@workflow.defn`). Open when changing how tasker starts, queries, or cancels workflows.
- `apps/tasker/src/falcoria_tasker/temporal/client.py#connect_temporal` / `#get_temporal_client` — lazy singleton client connection (not `@lru_cache`, since `Client.connect()` is a coroutine). Open when changing Temporal connection/TLS setup on the tasker side.
- `apps/tasker/src/falcoria_tasker/security.py#require_token` / `#require_project_access` — auth dependencies that relay the caller's token to scanledger's `check_access()`, with a 45s in-process TTL cache. Open when changing tasker-side auth caching.
- `apps/tasker/src/falcoria_tasker/scanledger.py#ScanledgerClient` — tasker's HTTP client to scanledger (`check_access`, `search_ips`, `create_ips`). Open when tasker needs a new scanledger call.
- `apps/tasker/src/falcoria_tasker/workers/service.py` — aggregates `DescribeTaskQueue` poller sightings into the fleet view shown at `GET /api/workers`, filtering stale pollers. Open when changing worker-fleet reporting.

### worker

- `apps/worker/src/falcoria_worker/temporal/workflows.py#ScanBatchWorkflow` — parent/fan-out workflow, windows children to `WORKER_WINDOW_SIZE` concurrent, exposes `get_progress` query. Open when changing batch orchestration or progress reporting.
- `apps/worker/src/falcoria_worker/temporal/workflows.py#ScanWorkflow` — one child per IP/task: `nmap_scan` then `upload_results`, sequential, no branches. Open when changing per-target scan/upload behavior or retry policy.
- `apps/worker/src/falcoria_worker/temporal/activities.py#ScanActivities` — the two `@activity.defn`s (`nmap_scan`, `upload_results`); deliberately imported only via string names in `activity_names.py`, never from `workflows.py` (keeps impure imports out of the sandboxed workflow module). Open when changing what an activity does.
- `apps/worker/src/falcoria_worker/nmap/scanner.py#run_nmap_scan` — two-phase scan orchestration (open-ports pass, conditional service-detection pass), builds the nmap argv. Open when changing scan phases or argument construction.
- `apps/worker/src/falcoria_worker/nmap/executor.py#AsyncCommandExecutor` — generic subprocess runner: heartbeat loop, SIGTERM→grace-period→SIGKILL escalation. Open when changing subprocess timeout/cancellation behavior (nmap-agnostic).
- `apps/worker/src/falcoria_worker/nmap/xml.py#parse_open_ports` / `#enrich_xml` — pure nmap-XML parsing and pass-merging via `defusedxml`. Open when changing what fields are extracted from or merged into scan output.
- `apps/worker/src/falcoria_worker/scanledger.py#ScanledgerClient.upload_report` — direct multipart POST of scan XML to scanledger's import endpoint (not routed through tasker). Open when changing how results reach scanledger.

### shared packages

- `packages/falcoria-contracts/src/falcoria_contracts/scan_io.py` (`ScanTask`, `ScanBatchInput`, `ScanBatchResult`) — the Temporal workflow input/output contract between tasker and worker. Open before changing any workflow signature.
- `packages/falcoria-contracts/src/falcoria_contracts/temporal_names.py` — workflow names, task queue name, query name, search-attribute keys, shared by tasker and worker. Open when adding a new workflow, query, or search attribute — the string constant must live here, not be duplicated.
- `packages/falcoria-contracts/src/falcoria_contracts/worker_identity.py#build_worker_identity` / `#parse_worker_identity` — builds (worker side) and parses (tasker fleet-view side) the Temporal client identity string. Open when changing what identifies a worker process.
- `packages/falcoria-http/src/falcoria_http/transport.py#RetryingTransport` — shared retrying httpx transport; retries only `httpx.TransportError`, never a 4xx/5xx response. Open when changing service-to-service HTTP retry behavior.
- `packages/falcoria-temporal/src/falcoria_temporal/search_attributes.py` — pre-built `SearchAttributeKey` objects; `SA_MODE` is operator-facing only (no in-code query filters on it — deliberate). Open when adding a new search attribute.

## Change-impact notes

- **`falcoria-contracts` (`scan_io.py`, `temporal_names.py`, `port.py`, `enums.py`)**: imported by every service. A field change here is a contract change across scanledger, tasker, and worker simultaneously — check all three apps' tests, not just the package's own. `AGENTS.md` requires asking first.
- **`ips/models.py` / any scanledger model**: check the matching Alembic migration, `ips/nmap.py` (export round-trip), and `history/models.py` if the change affects what counts as a tracked change.
- **`events/schemas.py`** (`IPChangedEvent`, `PortDetail`): the payload consumers (ASM) parse. Adding a field is safe; renaming or removing one breaks consumers. `PortDetail` fields must stay a subset of `falcoria_contracts.port.Port` (`tests/events/test_schemas.py` checks it).
- **`ips/service.py#apply_import` / `ips/modes.py`**: every import-mode change also changes events — re-run `tests/events/` (they assert event added/removed match the history STATE rows in every mode).
- **`apps/worker/temporal/workflows.py`**: check `apps/tasker/temporal/workflows.py` (the client-facade calling it must agree on workflow/query names, which come from `falcoria_contracts.temporal_names`) and `apps/worker/temporal/activity_names.py` (activities are referenced by string name, not import, from the workflow module).
- **`apps/worker/config.py` (`AppSettings.window_size`)**: read once at import time in `workflows.py`, not inside `run()` — the Temporal sandbox blocks the `.env` file I/O a runtime settings read would need. Changing this to a runtime read will break under the sandbox; see `INVARIANTS.md`.
- **Any app's `.github/workflows/ci.yml` docker filter list** (`changes` job): must be kept in sync with that app's `pyproject.toml` `falcoria-*` dependencies, or `docker-build-check` stops rebuilding the image on a real change.
- **`deploy/ansible/` anything**: has its own `AGENTS.md` with stricter rules (zero-trust ports, PKI via `community.crypto` only, idempotence). Read it before editing, not just this file.
- **`port_prevalence/data/nmap-services`**: refreshing it (re-download, replace, re-run `sync.py`) also means re-running `sync.py` against every environment's database — the vendored copy and the `port_prevalence` table can silently drift apart otherwise. Not yet exposed through any API — see `port_prevalence` in `STRUCTURE.md`.
