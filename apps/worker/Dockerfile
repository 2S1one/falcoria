# syntax=docker/dockerfile:1
FROM python:3.12-slim AS builder

COPY --from=ghcr.io/astral-sh/uv:0.10.4 /uv /uvx /bin/

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

WORKDIR /app

# Third-party deps first, cached separately from app source changes.
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-install-workspace --no-dev --package falcoria-worker

# Now the workspace source, and the real (non-editable) install.
COPY packages/ packages/
COPY apps/worker/ apps/worker/
RUN uv sync --frozen --no-dev --no-editable --package falcoria-worker


FROM python:3.12-slim AS runtime

# libcap2-bin provides setcap, used once below then removed — the resulting
# file capability on the nmap binary is what matters at runtime, not the tool.
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        libcap2-bin \
    && setcap cap_net_raw,cap_net_admin+eip /usr/bin/nmap \
    && apt-get purge -y --auto-remove libcap2-bin \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --uid 1000 appuser

WORKDIR /app
COPY --from=builder /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH"

USER appuser

# nmap's default TCP scan and its UDP scan (-sU) need CAP_NET_RAW /
# CAP_NET_ADMIN, granted to the nmap binary above via setcap rather than
# running this container as root. Run it with
# `--cap-add=NET_RAW --cap-add=NET_ADMIN` (or the Kubernetes securityContext
# equivalent later) or scans fail with a permissions error.
CMD ["python", "-m", "falcoria_worker.main"]
