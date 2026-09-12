# syntax=docker/dockerfile:1
FROM python:3.12-slim AS builder

COPY --from=ghcr.io/astral-sh/uv:0.10.4 /uv /uvx /bin/

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

WORKDIR /app

# Third-party deps first, cached separately from app source changes.
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-install-workspace --no-dev --package falcoria-scanledger

# Now the workspace source, and the real (non-editable) install.
COPY packages/ packages/
COPY apps/scanledger/ apps/scanledger/
RUN uv sync --frozen --no-dev --no-editable --package falcoria-scanledger


FROM python:3.12-slim AS runtime

RUN useradd --create-home --uid 1000 appuser

WORKDIR /app

COPY --from=builder /app/.venv /app/.venv
# Migrations are a deploy step (`alembic -c apps/scanledger/alembic.ini
# upgrade head`), not run at app startup — kept alongside .venv so the same
# image serves both the app and that job.
COPY --from=builder /app/apps/scanledger/alembic.ini apps/scanledger/alembic.ini
COPY --from=builder /app/apps/scanledger/migrations apps/scanledger/migrations
ENV PATH="/app/.venv/bin:$PATH"

USER appuser

EXPOSE 8000

# WEB_CONCURRENCY: worker-process count, since this runs on bare metal/Docker
# without an orchestrator replicating containers. --proxy-headers trusts
# X-Forwarded-* from whatever reverse proxy terminates TLS in front of this.
CMD ["sh", "-c", "uvicorn falcoria_scanledger.main:app --host 0.0.0.0 --port 8000 --proxy-headers --workers ${WEB_CONCURRENCY:-4}"]
