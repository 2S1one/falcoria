# Architecture

Falcoria is a network-scanning platform: it accepts a scan request for a project (a list of
hosts plus nmap-style options), runs the scan through a Temporal workflow on a pool of
worker processes, and stores the resulting port/service inventory in a Postgres-backed
system of record. Ownership splits by service: `scanledger` owns the IP/port inventory and
the change-history log; `tasker` owns scan orchestration and worker-fleet visibility;
`worker` owns nothing durable — it runs nmap and uploads results.

`README.md` and `AGENTS.md` still describe `tasker`, `worker`, and `falcli` as "not created
yet." That is stale: `tasker` and `worker` are implemented, tested, and deployed (see
`compose.prod.yaml`, `deploy/ansible/`); only `falcli` remains unbuilt. `[ASK USER]` whether
to update those two files — out of scope for this generation pass.

A local, gitignored `refactor/` directory (see `/refactor/` in `.gitignore`) holds planning
notes, a decision log, and session handoff briefs for the ongoing rebuild. Its own
`refactor/README.md` states it is "not project documentation" and that role belongs to this
`docs/` tree — so this generation treats it as background context, not a source to mirror.

## Services

| Service | Import name | Role | Framework |
|---|---|---|---|
| `apps/scanledger/` | `falcoria_scanledger` | System of record: projects, IP/port inventory, change history, auth | FastAPI + SQLModel + asyncpg + Alembic |
| `apps/tasker/` | `falcoria_tasker` | API server + Temporal client: starts/tracks/cancels scans, reports worker fleet | FastAPI + Temporal client |
| `apps/worker/` | `falcoria_worker` | Temporal worker: runs nmap, uploads results to scanledger | Temporal worker (no HTTP server) |
| `apps/falcli/` | `falcli` | Console client | not created yet |

Shared workspace packages: `falcoria-contracts` (pydantic-only DTOs/enums/constants),
`falcoria-http` (retrying httpx transport), `falcoria-logging` (stdout logging config),
`falcoria-temporal` (Temporal SDK glue — pinned data converter, search-attribute keys; kept
separate from `falcoria-contracts` because it needs `temporalio`, which `falcoria-contracts`'
pydantic-only rule forbids).

## Entrypoints

| Entrypoint | Trigger | File |
|---|---|---|
| `scanledger` FastAPI app | HTTP, ASGI process | `apps/scanledger/src/falcoria_scanledger/main.py` (`create_app()`) |
| `tasker` FastAPI app | HTTP, ASGI process | `apps/tasker/src/falcoria_tasker/main.py` (`create_app()`) |
| `worker` Temporal worker | polls `port-scanner-pool` task queue | `apps/worker/src/falcoria_worker/main.py` (`main()`) |
| Alembic migrations | manual, before scanledger starts | `apps/scanledger/migrations/` (`alembic upgrade head`) |

`scanledger` and `tasker` are HTTP entrypoints; `worker` is a polling entrypoint with **no**
HTTP server. Any number of `worker` processes can run against the same task queue — it holds
no local state beyond one in-flight subprocess per activity. `tasker` opens only a Temporal
**client** connection; it never starts a Temporal worker, so it defines no
`@workflow.defn`/`@activity.defn` code itself — see the routing note in `NAVIGATION.md`.

## Runtime flow: run a scan (HTTP path, tasker → worker)

```
client
  -> POST /api/projects/{project_id}/scans           [tasker: scans/router.run_scan]
       -> scans/service.run_scan()
            -> targets.remove_duplicates() / partition_targets()   (pure)
            -> resolve.resolve_targets()             (aiodns, public/private classification)
            -> [ImportMode.INSERT only] scanledger.search_ips() + workflows.already_running_ips()
                 -> [known, not running, new hostnames] scanledger.create_ips(..., INSERT)
            -> scanner_args / sharding                (pure: build nmap arg strings, shard ports)
            -> temporal/workflows.start_batch_workflows()
                 -> Client.start_workflow(SCAN_BATCH_WORKFLOW_NAME, ScanBatchInput, task_queue="port-scanner-pool")
                    one call per chunk of chunk_size tasks, concurrent

  (Temporal server dispatches to worker pool on "port-scanner-pool")

worker: ScanBatchWorkflow.run(ScanBatchInput)          [apps/worker/temporal/workflows.py]
  fan-out, windowed to WORKER_WINDOW_SIZE concurrent children
  +-> child ScanWorkflow.run(NmapWorkflowInput)  x N   (one per IP/port-shard task)
        -> activity nmap_scan(input) -> xml            [ScanActivities.nmap_scan]
             -> nmap/scanner.run_nmap_scan()
                  -> _run_nmap_pass(): asyncio.create_subprocess_exec(nmap_path, *args.split(), "-oX", tmpfile, target)
                  -> [open ports found + service_args set] second pass, restricted to those ports
                  -> nmap/xml.enrich_xml() merges passes, injects hostnames
        -> activity upload_results(input, xml)         [ScanActivities.upload_results]
             -> scanledger.py: ScanledgerClient.upload_report()
                  -> POST /api/projects/{project_id}/ips/import  (scanledger, direct — not via tasker)
```

Branch points: the INSERT-mode dedup step (skips re-scanning IPs scanledger already has and
nothing is currently scanning); the two-phase nmap scan (service-detection pass only runs if
the open-ports pass found something); child-workflow windowing in `ScanBatchWorkflow`
(bounded fan-out, not one child per task at once).

## Runtime flow: scan status and cancellation (tasker, Temporal client only)

```
client -> GET /api/projects/{project_id}/scans/{scan_id}        [scans/router.get_scan_status]
  -> scans/service.get_scan_status()
       -> temporal/workflows.scan_progress()    -> per-batch query "get_progress" (bounded concurrency, 2s timeout each)
       -> temporal/workflows.running_ips()      -> list running ScanWorkflow executions + assigned worker identity

client -> POST /api/projects/{project_id}/scans/{scan_id}/cancel
  -> scans/service.cancel_batches()
       -> temporal/workflows.start_cancel_batch(query)      Temporal batch cancel operation
       -> [after CANCEL_TERMINATE_WAIT grace period, background task]
       -> temporal/workflows.start_terminate_batch(query)   Temporal batch terminate operation (force)
```

`query_progress` uses a short explicit timeout rather than Temporal's default 30s gRPC
deadline, and treats an `RPCError` (batch never picked up by a worker) as "exclude from
aggregate," not "zero progress" — see `INVARIANTS.md`.

## Runtime flow: worker fleet visibility (tasker)

```
client -> GET /api/workers                          [tasker: workers/router.get_workers]
  -> workers/service.py
       -> temporal/workflows.describe_task_queue_pollers("port-scanner-pool")
            -> Temporal DescribeTaskQueueRequest (workflow- and activity-poller types)
       -> filters stale pollers (TASKER_WORKER_POLLER_STALE_SECONDS)
       -> parses each poller's identity via falcoria_contracts.worker_identity.parse_worker_identity()
```

This is distinct from `apps/worker` the service — `workers/` here is tasker's read-only view
of which worker processes are currently polling, built from Temporal's own poller metadata,
not a separate registry.

## Auth model

Every service-to-service call carries a static bearer token; `scanledger` is the sole source
of truth for who a token belongs to.

- `scanledger` seeds three primary accounts (`admin`, `tasker`, `worker`) from env-configured
  tokens on every startup (`auth/service.py::ensure_primary_users`); other users are created
  through the admin-gated `POST /admin/users` route.
- `tasker` and `worker` each hold their own `SCANLEDGER_TOKEN`-equivalent setting
  (`TASKER_SCANLEDGER_TOKEN` / `WORKER_SCANLEDGER_TOKEN`) and use it as a plain bearer token
  against scanledger; scanledger's `require_user`/`require_admin`/`validate_project_access`
  dependencies are the only enforcement point — tasker's `require_token`/
  `require_project_access` (`security.py`) relay the caller's own token to scanledger's
  `check_access()` and cache the result 45s in-process rather than re-implementing the check.

## Deployment shape

Two-tier: a control-plane node runs Caddy, Postgres, Temporal server, `scanledger`, and
`tasker` behind Caddy as the sole ingress (zero-trust: nothing else publishes a host port);
worker nodes run `falcoria-worker` containers with `network_mode: host` and
`NET_RAW`/`NET_ADMIN` capabilities for raw-socket nmap scans, reaching scanledger over HTTPS
and Temporal gRPC over mutual TLS through Caddy. Full detail, including the PKI/certificate
flow, is in `deploy/ansible/AGENTS.md` — that file is authoritative for deployment and is not
duplicated here.
