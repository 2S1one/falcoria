# falcoria

Network-scanning platform. uv-workspace monorepo, built file-by-file along the data flow,
starting with `scanledger`.

## Layout

| Path | Import name | Role |
|---|---|---|
| `packages/falcoria-contracts/` | `falcoria_contracts` | Shared Pydantic contracts, enums, DTOs. `pydantic` + stdlib only. |
| `apps/scanledger/` | `falcoria_scanledger` | System of record for port-scan results (FastAPI + SQLModel + asyncpg). |
| `apps/tasker/` | `falcoria_tasker` | API server + Temporal orchestration (single instance). *Not created yet.* |
| `apps/worker/` | `falcoria_worker` | Job executor running nmap (N instances). *Not created yet.* |
| `apps/falcli/` | `falcli` | Console client. *Not created yet.* |

## Development

```sh
uv sync                       # whole workspace
uv sync --package falcoria-scanledger   # one member's dependency tree
```

Tooling: `uv run ruff format .`, `uv run ruff check . --fix`, `uv run pyright`,
`uv run pytest`. See `AGENTS.md` for conventions.
