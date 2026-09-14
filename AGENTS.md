# AGENTS.md

Single source of truth for agents working in this repo. `CLAUDE.md` imports this file.
Nested `AGENTS.md` files (one per workspace member, and `deploy/ansible/AGENTS.md`) add
area-specific rules — the file nearest the edited file wins.

## Overview

**falcoria** is a network-scanning platform: a uv-workspace monorepo of a system-of-record
service (`scanledger`), an API server + Temporal orchestrator (`tasker`), nmap job runners
(`worker`), a console client (`falcli`), and a shared contracts package
(`falcoria-contracts`).

It is being rebuilt from scratch, file-by-file along the data flow, `scanledger` first.

## Commands

`uv` only — never bare `pip`.

| Task | Command |
|---|---|
| Sync the whole workspace | `uv sync` |
| Sync one member's deps | `uv sync --package falcoria-scanledger` |
| Add a runtime dep to a member | `uv add --package falcoria-scanledger <pkg>` |
| Add a workspace-wide dev tool | `uv add --group dev <pkg>` |
| Format | `uv run ruff format .` |
| Lint (autofix) | `uv run ruff check . --fix` |
| Type-check | `uv run pyright` |
| Test — all | `uv run pytest` |
| Test — fast (no Postgres/Temporal) | `uv run pytest -m "not postgres and not temporal"` |
| Test — one node | `uv run pytest apps/scanledger/tests/test_foo.py::test_bar` |

Run `uv` from the repo root — from inside a member directory `uv add` / `uv sync`
target that member, not the workspace.

## Project structure

```
packages/falcoria-contracts/   import falcoria_contracts    pydantic + stdlib only; pyright strict
apps/scanledger/               import falcoria_scanledger    FastAPI + SQLModel + asyncpg + alembic
apps/tasker/                   import falcoria_tasker         API server + Temporal (one instance)   [not created yet]
apps/worker/                   import falcoria_worker         nmap job runner (N instances)          [not created yet]
apps/falcli/                   import falcli                  console client                         [not created yet]
deploy/ansible/                Ansible playbooks & roles     Multi-node Zero-Trust mTLS deployment
```

- src-layout for every member: code lives in `<member>/src/<import_name>/`.
- Dist names are hyphenated, `falcoria-` prefixed (`falcoria-scanledger`); import names are
  underscored, `falcoria_` prefixed (`falcoria_scanledger`). `falcli` keeps its bare name.
- Cross-member deps go through `[tool.uv.sources] <name> = { workspace = true }`.
- Deployment is automated in `deploy/ansible/`. All deployment operations must be
  performed strictly following [`deploy/ansible/AGENTS.md`](deploy/ansible/AGENTS.md).

## Code style

Ruff, the Ruff formatter and pyright own formatting, lint, import order and typing — config
is in the root `pyproject.toml`. **Do not restate their rules as prose.** What they cannot
enforce:

- Type hints on all public code; concrete types over `Any`; narrow in tests with
  `assert isinstance(...)`, not `# type: ignore`.
- All imports at file top — inline imports hide dependencies.
- Catch specific exceptions; no bare `except Exception` outside a top-level handler;
  `logger.exception()` inside an `except`; keep `try` blocks small.
- Text I/O always `encoding="utf-8"`.
- Don't silence a checker (`# noqa` / `# type: ignore` / `# pragma: no cover`) to get the
  gate green — fix the cause. A suppression is allowed only when genuinely unavoidable, and
  only with a specific rule code plus a one-line reason.
- Model transformations via `model_dump()` / `model_validate()` — don't hand-list fields.
  `TargetModel(**source.model_dump(), field=override)` is the base pattern (pydantic v2
  drops unknown keys, so `include=` is never needed and is banned — it re-introduces a
  hidden hardcode). `model_dump(exclude={"x"})` only when a name means different things in
  source and target; `model_dump(mode="json")` when enums must serialise to `str` for the
  DB layer. An explicit field is acceptable only when the names differ (`number` → `port`).

### Docstrings

Ruff `D` (google convention) enforces presence on the public surface (`D101/102/103`);
private names, `tests/` and `migrations/` are exempt. What the tool cannot check:

- **Summary:** one physical line (≤ ~80 chars), capitalised, ending with a period.
  Descriptive voice — "Returns …", "Reconciles …" — not "Return", not "This function …".
- **Sections** (`Args:` / `Returns:` / `Raises:` / `Yields:`) only when they add what the
  signature and type annotations do not already say. Under the google convention `Args:`
  is all-or-nothing per function — document every parameter or none.
- **Body paragraph** only for the non-obvious: side effects, commit / transaction
  behaviour, invariants, units, what `None` / an empty result means, a precondition on the
  inputs, and — for a pure function — the rule it implements and what it deliberately does
  *not* do.
- **Narration test:** delete any line that re-describes the code step by step; that is a
  `# why` comment's job, and only for the *why*.
- **Pydantic schemas:** one line on the class (what the payload is, where it is used);
  document fields with `Field(description=...)`, not an `Attributes:` block. A `Settings`
  class *may* use `Attributes:` — the env-var names have no other home.
- **FastAPI handlers:** the docstring is the OpenAPI description — keep it client-facing.
  The error contract goes in `responses=` / `status_code`, never a `Raises:` block. Do not
  also pass `description=` (it overrides the docstring).
- **Custom exception classes:** one line stating *when* it is raised.
- **Scanner-neutral:** prose in docstrings, comments and `Field(description=...)` says
  "the scan" / "the scanner reported", never "nmap" — other scanners (masscan, …) are
  planned. Field *names* may still mirror the scanner-flavoured contract (`servicefp`).
- **No cross-references:** never point a docstring at another doc or spec file
  ("see …", "per the … spec"). State the rule inline in a few words, or leave it out.
- **Never:** restate the name; repeat an annotated type; open with "This function …" /
  "A helper that …"; put change history, TODO or author tags in a docstring.

## Git workflow

- Branch before committing on `main`.
- Never rebase, squash, amend or force-push commits that are already pushed.
- No attribution trailers — never add `Co-Authored-By` or a session/assistant id to a
  commit message.
- Conventional Commits format.
- Never commit secrets, credentials, or real scan data (IPs, hostnames, emails). Redact
  them from logs and test fixtures.

## Boundaries

**✅ always**
- Run the verification block below before calling a task done.
- New behaviour ships with tests.
- `uv add`, never `pip`. `encoding="utf-8"` on file I/O.

**⚠️ ask first**
- Adding a dependency.
- Changing a `falcoria-contracts` type — it is imported by every service, so a change here
  is a contract change.
- A DB schema or Alembic migration change.
- Anything outward-facing: an API contract, a published event, a CLI flag.

**🚫 never**
- Commit secrets or real scan data.
- Suppress a checker without a specific code and a one-line reason (see Code style).
- Delete or weaken a failing test without explicit authorization.
- Hand-edit generated Alembic revisions under `**/migrations/versions/`.

## Verification

Run verbatim before a task is complete — all four must pass:

```
uv run ruff format .
uv run ruff check . --fix
uv run pyright
uv run pytest
```

## Tests

- `pytest`; plain `test_*` functions, no `Test*` classes; mirror the source tree under
  `<member>/tests/`. Import mode is `importlib` (set in `pyproject.toml`).
- Async tests use `anyio`: put `pytestmark = pytest.mark.anyio` at the top of the file; the
  `anyio_backend` fixture in the root `conftest.py` pins the backend to asyncio.

## Working convention

During the rebuild, build along the data flow, one file at a time:

**show the file → explain what it does and why → wait for "yes" → write it → next file.**

Do not write or edit files before the approach is agreed.
