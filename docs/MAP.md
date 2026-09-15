# Map

Generated at commit `a710f813451a9bd4057900876e5aaa12b2b687f8` on branch `feat/port-prevalence`.

Falcoria: a network-scanning platform, uv-workspace monorepo, three deployable services
(`scanledger`, `tasker`, `worker`) plus four shared libraries. `README.md` describes
`tasker`/`worker`/`falcli` as "not created yet" — stale for `tasker`/`worker`, accurate for
`falcli`. `AGENTS.md` no longer mentions `falcli` at all. See `ARCHITECTURE.md` for detail.

## Files in this set

- **`ARCHITECTURE.md`** — identity, entrypoints table, runtime-flow ASCII diagrams (run a
  scan, check status/cancel, worker-fleet visibility), auth model, deployment shape. Open
  first for "what does this system do and how does a request flow through it."
- **`STRUCTURE.md`** — directory → purpose tables (root, then per-service `src/` layout, three
  levels deep). Open for "what lives where," not "where do I start."
- **`NAVIGATION.md`** — task-routing table (12 common tasks → starting file), a curated
  symbol index for non-entrypoint functions on a runtime-flow path, and change-impact notes
  per module. Open for "where do I start to do X" and "what else breaks if I change Y."
- **`INVARIANTS.md`** — non-obvious runtime rules grouped by area (Temporal sandbox,
  subprocess/scanner safety, scanledger data layer, tasker query/cancel semantics), each with
  what breaks if violated and the owning file. Open before changing anything Temporal-sandbox-
  related, subprocess-related, or a DB commit boundary.
- **`INTEGRATIONS.md`** — every external dependency (Postgres, Temporal server, inter-service
  HTTP calls, api.ipify.org, nmap, Caddy) as a table: how it's called, where configured, what
  breaks if it's down.
- **`STACK.md`** — external runtime versions not visible in a language manifest (Postgres 16,
  Temporal server 1.29.1, Temporal admin-tools/UI versions), sourced from the compose files.
  Language/framework/dependency versions are in each member's own `pyproject.toml` — not
  duplicated here.
- **`TESTING.md`** — pytest marker requirements (`postgres`, `temporal`), the root
  `conftest.py`'s env-var-before-import requirement (tied to a Temporal sandbox invariant),
  scanledger's DB fixture pattern (transaction-per-test rollback, model-registration imports),
  anyio backend pinning.
- **`GLOSSARY.md`** — Temporal vocabulary (workflow, activity, task queue, search attribute,
  batch operation, ...) and domain vocabulary (import mode, batch, target, fleet view, facet,
  reconcile) in one place, since both are heavy enough to block a first read of the other
  files.

Skipped as not warranted for this generation: `diagrams/*.md` — the one fan-out point
(`ScanBatchWorkflow` → N `ScanWorkflow` children) is simple enough to stay as ASCII inside
`ARCHITECTURE.md`; a separate Mermaid diagram would just redraw the same single branch.

## Observed but out of scope for this skill

- `.gitignore` notes "ADRs from `refactor/decisions/` move into `docs/decisions/` when
  `docs/` is brought in" — a planned migration, not something this generation performed.
  Fabricating or moving ADRs is outside this skill's output contract; `[ASK USER]` if that
  migration should happen as a separate task.
- `README.md` claims `tasker`/`worker`/`falcli` are "not created yet"; `tasker` and `worker`
  are implemented and deployed. `AGENTS.md`'s equivalent staleness was already fixed
  (2026-09-15, outside this session). `[ASK USER]` whether to correct `README.md` — this
  skill does not edit files outside `docs/`.
- `refactor/known_risk_nmap_services_license.md` (gitignored) tracks a licensing risk for
  `port_prevalence/data/nmap-services` (NPSL) — noted in `INVARIANTS.md` since that file isn't
  part of this `docs/` tree and won't be visible to every clone.

## Verification

From the repo root:

```
uv run ruff format .
uv run ruff check . --fix
uv run pyright
uv run pytest -m "not postgres and not temporal"
```

The full `uv run pytest` (no marker filter) additionally needs Postgres and Temporal running
— see `TESTING.md`. `INVARIANTS.md`'s own verification note covers invariant-specific checks
only; this block is the baseline for any change.
