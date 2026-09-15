# Glossary

## Temporal (workflow engine)

- **Workflow** — durable, replayable orchestration code (`@workflow.defn`). Must be
  deterministic; runs inside a sandbox that restricts non-deterministic operations (file I/O,
  most network calls, unpinned randomness).
- **Activity** — the non-deterministic unit of work a workflow calls out to (`@activity.defn`).
  Runs outside the sandbox; can use httpx, subprocess, tempfile, etc.
- **Task queue** — the named queue a worker polls and a workflow/activity is dispatched to.
  This repo has one: `port-scanner-pool` (`falcoria_contracts.temporal_names.PORT_SCANNER_TASK_QUEUE`).
- **Child workflow** — a workflow started from inside another workflow (`ScanWorkflow` is a
  child of `ScanBatchWorkflow`). `parent_close_policy` controls what happens to children when
  the parent closes.
- **Signal** — an async, fire-and-forget message delivered to a running workflow. Not used in
  this repo — cancellation uses Temporal's built-in cancel/terminate, not a custom signal.
- **Query** — a synchronous, read-only request against a running workflow's state
  (`get_progress` in this repo). Fails with `RPCError` if the workflow can't currently serve
  it (e.g. never picked up by a worker).
- **Batch operation** — a server-side operation (cancel, terminate) applied to every workflow
  matching a visibility query, without enumerating workflow ids client-side. Used by tasker
  for `cancel_scan_by_id`/`cancel_all_scans`.
- **Search attribute** — a typed, indexed key-value pair set on a workflow execution, queryable
  via Temporal's visibility API (`ProjectId`, `ScanId`, `Mode`, `Ip` in this repo). Must be
  pre-registered on the cluster as the right type before use.
- **Visibility query** — Temporal's List Filter query string syntax (e.g. `Mode='replace'`)
  used to find/filter/batch-operate on workflow executions.
- **Poller** — a worker process actively long-polling a task queue for work. `DescribeTaskQueue`
  reports current pollers; tasker's `GET /api/workers` is built from this.
- **Data converter** — the (de)serialization layer between workflow/activity Python objects and
  the bytes Temporal stores/transmits. This repo pins `falcoria_temporal.pydantic_data_converter`
  so pydantic models round-trip correctly.
- **Sandboxed workflow runner** — the Temporal SDK component that enforces determinism inside
  a `@workflow.defn`; `SandboxRestrictions.default.with_passthrough_modules(...)` allowlists
  specific modules (here: `pydantic`, `pydantic_core`) to reuse the host process's copy instead
  of re-executing them under restricted globals.

## Domain (scanning platform)

- **Project** — the top-level scoping container in scanledger; owns IPs, ports, hostnames, and
  history. Access is via membership (or admin).
- **Import mode** — how newly-scanned data merges with what's already on record for a project:
  `INSERT` (add new, skip known), `REPLACE` (full reconcile — closes ports not seen this scan),
  `UPDATE`, `APPEND`. See `falcoria_contracts.enums.ImportMode`.
- **Scan** — one orchestration run (one `scan_id`) that may fan out into multiple Temporal
  batch/child workflows across many targets.
- **Batch** — one `ScanBatchWorkflow` execution: a chunk of a scan's tasks (bounded by
  `chunk_size` in `start_batch_workflows`), run as one workflow with windowed child fan-out.
- **Target** — a host to scan: an IP literal, a hostname (resolved before scanning), or
  something classified as private (handled separately from public targets).
- **Fleet view** — tasker's read-only report of which `worker` processes are currently polling
  the task queue, built from Temporal poller metadata, not a separate service registry.
- **Facet** — a per-dimension value-count aggregation over a filtered host population (e.g.
  counts by `service`, `product`, `os`) — `POST /ips/facets` in scanledger.
- **Reconcile** — the REPLACE-mode logic that decides which previously-open ports are now
  closed based on what the current scan pass actually covered.
