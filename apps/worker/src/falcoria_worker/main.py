"""Worker entrypoint: connects to Temporal, registers workflows/activities, and polls."""

import asyncio
import logging
import os
import socket

import httpx
from falcoria_logging import configure_logging
from temporalio.worker import Worker
from temporalio.worker.workflow_sandbox import SandboxedWorkflowRunner, SandboxRestrictions

from falcoria_contracts.temporal_names import PORT_SCANNER_TASK_QUEUE
from falcoria_contracts.worker_identity import build_worker_identity
from falcoria_worker.config import Env, get_app_settings
from falcoria_worker.scanledger import ScanledgerClient
from falcoria_worker.temporal.activities import ScanActivities
from falcoria_worker.temporal.client import connect_temporal
from falcoria_worker.temporal.workflows import ScanBatchWorkflow, ScanWorkflow

logger = logging.getLogger(__name__)

_EXTERNAL_IP_URL = "https://api.ipify.org"
_EXTERNAL_IP_TIMEOUT_SECONDS = 5.0


async def _resolve_external_ip() -> str:
    """Fetches this host's external IP; falls back to "unknown" on any failure."""
    try:
        async with httpx.AsyncClient(timeout=_EXTERNAL_IP_TIMEOUT_SECONDS) as client:
            response = await client.get(_EXTERNAL_IP_URL)
            response.raise_for_status()
            return response.text.strip()
    except httpx.HTTPError:
        logger.warning("Could not resolve external IP; using 'unknown'.")
        return "unknown"


async def main() -> None:
    """Connects to Temporal and scanledger, then polls PORT_SCANNER_TASK_QUEUE until stopped."""
    settings = get_app_settings()
    configure_logging(level=settings.log_level, json_output=settings.env is not Env.LOCAL)
    external_ip = await _resolve_external_ip()
    identity = build_worker_identity(os.getpid(), socket.gethostname(), external_ip)
    client = await connect_temporal(identity)

    scanledger = ScanledgerClient(
        settings.scanledger_base_url,
        settings.scanledger_token.get_secret_value(),
        verify=settings.scanledger_tls_verify,
    )
    activities = ScanActivities(
        scanledger,
        settings.nmap_path,
        settings.command_grace_period_seconds,
        settings.heartbeat_interval_seconds,
    )

    worker = Worker(
        client,
        task_queue=PORT_SCANNER_TASK_QUEUE,
        workflows=[ScanBatchWorkflow, ScanWorkflow],
        activities=[activities.nmap_scan, activities.upload_results],
        max_concurrent_activities=settings.max_concurrent_activities,
        workflow_runner=SandboxedWorkflowRunner(
            restrictions=SandboxRestrictions.default.with_passthrough_modules(
                "pydantic", "pydantic_core"
            )
        ),
    )
    try:
        await worker.run()
    finally:
        await scanledger.aclose()


if __name__ == "__main__":
    asyncio.run(main())
