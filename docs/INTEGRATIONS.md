# Integrations

| Integration | Used by | How | Configured in | What breaks if unavailable |
|---|---|---|---|---|
| Postgres | `scanledger` (data), `temporal` server (its own schema, same instance) | `postgresql+asyncpg://` via SQLModel/asyncpg; Temporal's `auto-setup` image provisions its own `temporal`/`temporal_visibility` databases in the same instance | `scanledger`: `DatabaseSettings` (`SCANLEDGER_DB_*` env vars), `apps/scanledger/src/falcoria_scanledger/database.py`. Compose: `compose.dev.yaml` / `compose.prod.yaml` `postgres` service | `scanledger` fails every DB-backed request (health check still returns 200 — it runs no dependency checks); Temporal server itself fails to start |
| Temporal server | `tasker` (client only), `worker` (client + worker) | gRPC, `Client.connect()`; worker additionally polls the `port-scanner-pool` task queue | `tasker`: `TemporalSettings` (`TASKER_TEMPORAL_*`). `worker`: `TemporalSettings` + `TemporalTLSSettings` (`WORKER_TEMPORAL_*`), mTLS optional. Both via `falcoria_temporal.converter.pydantic_data_converter` | `tasker` can't start/query/cancel scans (its own endpoints return errors); `worker` can't pick up new work but any in-flight subprocess still runs to completion |
| scanledger (as an internal service) | `tasker` (dedup lookups, membership/access checks), `worker` (uploads scan results) | HTTP, `httpx.AsyncClient` over `falcoria_http.RetryingTransport`, static bearer token per caller | `tasker`: `ScanledgerClient` in `apps/tasker/src/falcoria_tasker/scanledger.py`, `TASKER_SCANLEDGER_BASE_URL`/`_TOKEN`. `worker`: `apps/worker/src/falcoria_worker/scanledger.py`, `WORKER_SCANLEDGER_BASE_URL`/`_TOKEN` | `tasker` auth checks and INSERT-mode dedup fail; `worker`'s `upload_results` activity fails and retries per its `RetryPolicy` (max 4 attempts), then the workflow reports the task as failed |
| api.ipify.org | `worker` (`_resolve_external_ip()` in `main.py`, startup only) | plain HTTPS GET, 5s timeout | hardcoded URL, no setting | falls back to the literal string `"unknown"` for the worker's identity string — does not block worker startup |
| nmap (subprocess, not a network service) | `worker` | `asyncio.create_subprocess_exec`, argv list, no shell | `WORKER_NMAP_PATH` (default `"nmap"`) | the `nmap_scan` activity raises `CommandExecutionError`/`CommandTimeoutError`, retried per its `RetryPolicy` (max 2 attempts) |
| Caddy (reverse proxy / TLS termination, production only) | external clients, worker-to-control-plane traffic | HTTPS ingress; Let's Encrypt/ZeroSSL certs; mutual TLS on the Temporal gRPC path | `deploy/ansible/roles/control_plane/` templates | in production, nothing external can reach scanledger/tasker/Temporal at all — see `deploy/ansible/AGENTS.md`, zero-trust port policy |

`falcoria-http`'s `RetryingTransport` retries only `httpx.TransportError` (connection-level
failures); a 4xx/5xx HTTP response from any of the above services is returned unchanged so
callers' own `raise_for_status()`/status handling still applies — it is not itself a retry
policy for application errors.

Deployment-layer detail (PKI/certificate flow, network topology, zero-trust invariants) lives
in `deploy/ansible/AGENTS.md` and is not duplicated here.
