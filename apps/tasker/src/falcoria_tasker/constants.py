"""Cross-cutting constants: values referenced from more than one package."""

from datetime import timedelta
from enum import Enum
from typing import Any

from fastapi import status


class Tag(str, Enum):
    """OpenAPI tag groups; one per route package."""

    META = "meta"
    SCANS = "scans"
    WORKERS = "workers"


# OpenAPI `responses=` entries for any router mounted behind an auth dependency.
AUTH_RESPONSES: dict[int | str, dict[str, Any]] = {
    status.HTTP_401_UNAUTHORIZED: {"description": "Missing or invalid bearer token."},
    status.HTTP_403_FORBIDDEN: {"description": "Authenticated, but not permitted."},
}

# Tasks per ScanBatchWorkflow; a scan's targets are chunked into batches of at
# most this many (IP x port-shard) tasks, one workflow per chunk.
SCAN_BATCH_CHUNK_SIZE = 500

# IPs per Temporal visibility query page while cancelling a scan.
CANCEL_BATCH_SIZE = 50

# Grace period between the graceful cancel() signal and terminate() during a
# scan cancel: worker heartbeat timeout + worker graceful-shutdown timeout +
# a fixed buffer.
WORKER_HEARTBEAT_TIMEOUT = timedelta(seconds=30)
WORKER_GRACEFUL_SHUTDOWN_TIMEOUT = timedelta(seconds=0)
CANCEL_TERMINATE_BUFFER = timedelta(seconds=10)
CANCEL_TERMINATE_WAIT = (
    WORKER_HEARTBEAT_TIMEOUT + WORKER_GRACEFUL_SHUTDOWN_TIMEOUT + CANCEL_TERMINATE_BUFFER
)
