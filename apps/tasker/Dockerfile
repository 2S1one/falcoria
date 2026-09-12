# syntax=docker/dockerfile:1
FROM python:3.12-slim AS builder

COPY --from=ghcr.io/astral-sh/uv:0.10.4 /uv /uvx /bin/

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

WORKDIR /app

# Third-party deps first, cached separately from app source changes.
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-install-workspace --no-dev --package falcoria-tasker

# Now the workspace source, and the real (non-editable) install.
COPY packages/ packages/
COPY apps/tasker/ apps/tasker/
RUN uv sync --frozen --no-dev --no-editable --package falcoria-tasker


FROM python:3.12-slim AS runtime

RUN useradd --create-home --uid 1000 appuser

COPY --from=builder /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH"

WORKDIR /app
USER appuser

EXPOSE 8000

# WEB_CONCURRENCY: worker-process count, since this runs on bare metal/Docker
# without an orchestrator replicating containers. --proxy-headers trusts
# X-Forwarded-* from whatever reverse proxy terminates TLS in front of this.
CMD ["sh", "-c", "uvicorn falcoria_tasker.main:app --host 0.0.0.0 --port 8000 --proxy-headers --workers ${WEB_CONCURRENCY:-4}"]
