# Invariants

Rules that break at runtime without breaking a lint or type check. Each item: the rule, what
breaks if violated, the file it lives in.

## Temporal sandbox / determinism

- **`falcoria_worker.temporal.workflows` never imports `activities.py`.** Activities are
  invoked by the string constants in `activity_names.py` instead. Temporal's workflow sandbox
  re-executes a workflow-defining module's top-level imports on every replay; `activities.py`
  imports `httpx`, `tempfile`, and subprocess-touching code, which the sandbox forbids as
  non-deterministic. Importing it from `workflows.py` breaks worker startup.
  `apps/worker/src/falcoria_worker/temporal/activities.py`,
  `apps/worker/src/falcoria_worker/temporal/activity_names.py`.
- **`WORKER_WINDOW_SIZE` is read once at module import time in `workflows.py`, not inside
  `ScanBatchWorkflow.run()`.** Reading `get_app_settings()` during `run()` would trigger
  python-dotenv's `.env` file `open()` call inside the sandbox, which blocks non-deterministic
  I/O. Any test importing `falcoria_worker.temporal.workflows` must have `WORKER_WINDOW_SIZE`
  set in the environment *before* that import — the root `conftest.py` does this via
  `os.environ.setdefault(...)` before any app import. `apps/worker/src/falcoria_worker/temporal/workflows.py`,
  `conftest.py` (repo root).
- **Settings/pydantic schema imports in `workflows.py` go through
  `workflow.unsafe.imports_passed_through()`.** Without it, the sandbox re-executes those
  modules under restricted globals instead of reusing the host process's already-loaded
  copies — pydantic itself needs the same precaution.
  `apps/worker/src/falcoria_worker/temporal/workflows.py`.
- **Custom search attributes (`ProjectId`, `ScanId`, `Mode`, `Ip`) must be pre-registered on
  the Temporal cluster as keyword type before any workflow sets them.** Setting an
  unregistered search attribute fails at the server, not at compile time.
  `packages/falcoria-contracts/src/falcoria_contracts/temporal_names.py`.

## Subprocess / scanner safety

- **nmap is always invoked as an argv list via `asyncio.create_subprocess_exec`, never
  through a shell.** `command = [nmap_path, *args.split(), "-oX", str(output_path), target]`
  — `args` and `target` are attacker-influenced (built upstream from user-supplied scan
  options and hosts), but because there is no shell in the exec path there is no shell-
  injection surface even though they are unescaped strings. Introducing
  `create_subprocess_shell`, `shell=True`, or string-concatenated commands anywhere in this
  path would reopen that surface. `apps/worker/src/falcoria_worker/nmap/scanner.py`,
  `apps/worker/src/falcoria_worker/nmap/executor.py`.
- **Only untrusted nmap-produced XML is parsed with `defusedxml`; output is still built with
  stdlib `xml.etree.ElementTree`.** `parse_open_ports()` and `enrich_xml()` parse scan output
  (which can carry attacker-influenced content, e.g. via a crafted service banner) — this is
  the XXE-relevant boundary. Building/serializing the merged report uses the stdlib tree
  builder, which is fine since the process controls that content.
  `apps/worker/src/falcoria_worker/nmap/xml.py`.
- **Subprocess timeout/cancellation escalates SIGTERM → grace period → SIGKILL.** A timeout
  or `asyncio.CancelledError` triggers `_terminate()`; if the process is still alive after
  `command_grace_period_seconds`, it is force-killed. Skipping the grace period or the kill
  step leaks hung nmap processes. `apps/worker/src/falcoria_worker/nmap/executor.py`.
- **The service-detection nmap pass runs only if the open-ports pass found at least one open
  port, and only against those ports; each pass gets the full `timeout` budget
  independently (not split/summed).** Changing this to a shared budget or unconditional
  second pass changes scan duration and load characteristics.
  `apps/worker/src/falcoria_worker/nmap/scanner.py`.
- **`OpenPortsOpts.scan_type` (default `ScanType.SYN`) pins `-sS`/`-sT` explicitly for both
  nmap passes instead of letting nmap pick based on ambient privilege.** This only works
  because the worker's `nmap` binary has `cap_net_raw,cap_net_admin` file capabilities
  (`setcap` in `apps/worker/Dockerfile`, not root). A container missing that capability now
  fails the scan outright on a `SYN` request instead of silently falling back to a connect
  scan with different timing/signature — the explicit pin trades silent degradation for a
  loud failure. `apps/tasker/src/falcoria_tasker/scans/scanner_args.py`,
  `apps/worker/Dockerfile`.

## Data layer (scanledger)

- **Services never commit, roll back, or close the session `get_session()` provides.** A
  service may `flush()` to get a generated id, or `commit()` explicitly when it must act on
  already-committed state (the dependency's own commit is then a no-op). Committing/rolling
  back inside a service breaks the request-scoped unit-of-work contract.
  `apps/scanledger/src/falcoria_scanledger/database.py`.
- **The `ips` table stores open ports only.** A closed port is represented by deleting the
  `PortDB` row and writing a `history` entry, not by a `state=CLOSED` row. Code that expects
  to find closed ports in `ips`/`ports` will find none.
  `apps/scanledger/src/falcoria_scanledger/ips/models.py`,
  `apps/scanledger/src/falcoria_scanledger/ips/reconcile.py`.
- **`ip_port_history` uniqueness excludes `observed_state`/`reason`/`scan_id` but includes
  `created_at`.** Re-importing the identical scan writes nothing new (idempotent
  `ON CONFLICT DO NOTHING`); this only holds if `created_at` is computed consistently for a
  re-import of the same data. `apps/scanledger/src/falcoria_scanledger/history/models.py`.
- **Alembic owns the schema; the app issues no DDL.** `alembic upgrade head` must run before
  `scanledger` starts — this is stated in the `main.py` lifespan docstring, not enforced in
  code. Starting the app against an unmigrated database will fail on first query, not at
  startup. `apps/scanledger/src/falcoria_scanledger/main.py`.
- **The seed tokens (`SCANLEDGER_ADMIN_TOKEN`, `_TASKER_TOKEN`, `_WORKER_TOKEN`, and the
  optional `_ASM_TOKEN`) must all differ.** `ensure_primary_users` raises `ValueError` at
  startup if any two match — a config mistake fails loudly instead of silently merging
  identities. An empty `SCANLEDGER_ASM_TOKEN` seeds no `asm` account; clearing it later does
  not delete one already seeded.
  `apps/scanledger/src/falcoria_scanledger/auth/service.py`.
- **Auth tokens are hashed with a single unsalted SHA-256 round, deliberately.** A 60-char
  base62 token carries ~357 bits of entropy, so this is not a password hash and doesn't need
  salting/slow hashing — don't "fix" this to bcrypt/argon2 without revisiting the entropy
  argument. `apps/scanledger/src/falcoria_scanledger/auth/tokens.py`.
- **`port_prevalence` has no row for a port/protocol nmap-services never studied — a missing
  row is not the same as `score = 0`.** Code joining against it must use an outer join and
  treat `NULL` as "no data," not coerce it to zero. `score` is CHECK-constrained to `[0, 1]`.
  `apps/scanledger/src/falcoria_scanledger/port_prevalence/models.py`.
- **`port_prevalence` is refreshed by wholesale delete-then-bulk-insert, in one transaction,
  from a script — never by app code.** `sync.py` raises rather than run if parsing the
  vendored file yields zero entries, so a broken/missing source file can't silently empty the
  table. Nothing has a foreign key into this table, so the wipe is safe.
  `apps/scanledger/src/falcoria_scanledger/port_prevalence/sync.py`.
- **The vendored `nmap-services` data file is NPSL-licensed, not falcoria's own code.** Its
  own header states "(C) 1996-2025 by Insecure.Com LLC... distributed under the Nmap Public
  Source license." A known, accepted risk — see `refactor/known_risk_nmap_services_license.md`
  (gitignored, not part of this `docs/` tree) for the full reasoning and revisit trigger.
  `apps/scanledger/src/falcoria_scanledger/port_prevalence/data/nmap-services`.

- **Outbox rows are written in the import's own transaction, never after commit.**
  `events/service.write_events` only stages rows on the session. Writing them in a separate
  step after commit loses events on a crash between the two. `ips/service.py#apply_import`.
- **The feed cursor is `(txid, id)`, never `id` alone.** `id` is assigned at INSERT, not at
  COMMIT, so a lower `id` can become visible after a higher one; a cursor on `id` would skip
  it forever. `read_events` also filters `txid < pg_snapshot_xmin(pg_current_snapshot())`,
  so rows of a still-running transaction are held back. A long or idle-in-transaction
  session anywhere in the database delays the whole feed (no loss). `events/service.py`.
- **`_load`'s `SELECT ... FOR UPDATE` must stay the import's first statement.** A transaction
  gets its `txid` at its first write; an import waiting on the row locks has none yet, so
  feed order matches the order imports changed each IP. A write before the lock breaks
  that ordering. `ips/service.py#_load`.
- **scanledger's connections end any session idle inside a transaction for 60 s**
  (`idle_in_transaction_session_timeout` via `connect_args` in `get_engine`). Such a session
  would otherwise stall the event feed for every project. Code that waits on non-DB work
  mid-transaction for longer than that gets its connection terminated.
  `apps/scanledger/src/falcoria_scanledger/database.py`.
- **The feed only works on the primary.** `pg_current_snapshot()` on a read replica is not
  verified for this use. `events/service.py#read_events`.

## Cross-service query/status semantics (tasker)

- **`query_progress` uses an explicit short timeout, not Temporal's default 30s gRPC
  deadline.** A batch queued with no worker polling its task queue would otherwise hang a
  status request for the full default. `apps/tasker/src/falcoria_tasker/temporal/workflows.py`.
- **An `RPCError` from a progress query means "exclude from aggregate," not "zero
  progress."** A batch never picked up by a worker (queued, or cancelled before any task
  started) can't serve a query at all — Temporal raises `RPCError` rather than returning a
  result; treating that as zero would misreport an in-flight batch as stalled.
  `apps/tasker/src/falcoria_tasker/temporal/workflows.py`.
- **Cancellation is two-phase: graceful cancel, then a background task force-terminates
  after `CANCEL_TERMINATE_WAIT`.** That constant is derived as worker heartbeat timeout
  (30s) + graceful-shutdown timeout (0s) + a 10s buffer — shortening it risks terminating a
  workflow that was still shutting down cleanly.
  `apps/tasker/src/falcoria_tasker/scans/service.py`,
  `apps/tasker/src/falcoria_tasker/constants.py`.
- **The fire-and-forget terminate-after-grace-period task keeps an explicit reference.** A
  bare `asyncio.create_task(...)` with no other reference can be garbage-collected mid-flight;
  `scans/service.py` tracks references specifically to avoid that.

## Verification for this section

No dedicated command beyond the basics in `MAP.md`. The sandbox-related invariants
(activities not imported from `workflows.py`, `WORKER_WINDOW_SIZE` set before import) are
exercised implicitly by `uv run pytest apps/worker` — a violation typically surfaces as an
import-time or workflow-replay error in `apps/worker/tests/temporal/test_workflows.py`, not a
separate check.
