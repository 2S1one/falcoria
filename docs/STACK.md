# Stack

Language, package manager, and per-member framework choices are all visible in the root
`pyproject.toml` and each member's own `pyproject.toml` — not repeated here. This file covers
the external runtime versions that live only in compose/deploy config, not in a language
manifest.

| Component | Version | Source |
|---|---|---|
| Python | 3.12 (`requires-python = ">=3.12"` everywhere; pyright `pythonVersion = "3.12"`) | root `pyproject.toml` |
| Postgres | 16 (`postgres:16` image) | `compose.dev.yaml`, `compose.prod.yaml` |
| Temporal server | 1.29.1 (`temporalio/auto-setup:1.29.1`) | `compose.dev.yaml`, `compose.prod.yaml` |
| Temporal admin tools | `temporalio/admin-tools:1.29.1-tctl-1.18.4-cli-1.5.0` (tctl 1.18.4, CLI 1.5.0) | `compose.dev.yaml`, `compose.prod.yaml` |
| Temporal UI | 2.34.0 (dev only, `temporalio/ui:2.34.0`) | `compose.dev.yaml` |
| uv | pinned via `astral-sh/setup-uv` action, no explicit version pin in-repo | `.github/workflows/ci.yml` |

Dev-only services (`compose.dev.yaml`): Postgres + Temporal (+ Temporal UI on `:8080`) — no
app containers; run the FastAPI/worker processes directly against this stack during
development. Production (`compose.prod.yaml`) runs the full stack including `scanledger`,
`tasker`, and `worker` containers, built from each app's own `Dockerfile`
(`apps/*/Dockerfile`).

Temporal's dev-cluster dynamic config lives in `dynamicconfig/development-sql.yaml`, mounted
into the `temporal` container by both compose files.
