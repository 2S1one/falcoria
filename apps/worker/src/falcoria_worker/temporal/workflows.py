"""Temporal workflow definitions: batch fan-out and per-IP scan orchestration.

Settings and pydantic schemas are imported inside
`workflow.unsafe.imports_passed_through()` so the sandbox reuses the host
process's already-loaded modules instead of re-executing them under
restricted globals — the same precaution pydantic itself needs by default.
Never imports `activities.py` — its httpx/tempfile/subprocess-touching
dependencies must stay out of this module's sandboxed import graph; activities
are invoked by the string names in `activity_names.py` instead.
"""

import asyncio
from datetime import timedelta

from falcoria_temporal.search_attributes import SA_IP, SA_PROJECT_ID, SA_SCAN_ID
from temporalio import workflow
from temporalio.common import RetryPolicy, SearchAttributePair, TypedSearchAttributes

from falcoria_contracts.temporal_names import (
    QUERY_GET_PROGRESS,
    SCAN_BATCH_WORKFLOW_NAME,
    SCAN_WORKFLOW_NAME,
)
from falcoria_worker.temporal.activity_names import NMAP_SCAN_ACTIVITY, UPLOAD_RESULTS_ACTIVITY

with workflow.unsafe.imports_passed_through():
    from falcoria_contracts.scan_io import ScanBatchInput, ScanBatchResult, ScanTask
    from falcoria_worker.config import get_app_settings
    from falcoria_worker.temporal.schemas import NmapWorkflowInput

# Read once at import time, outside any workflow execution context: calling
# get_app_settings() *during* run() would have it read the .env file via
# python-dotenv's open(), which the sandbox blocks as non-deterministic I/O.
_WINDOW_SIZE = get_app_settings().window_size


def _child_workflow_id(project_id: str, scan_id: str, ip: str) -> str:
    """Builds one child ScanWorkflow's id — random suffix, not deduped across attempts."""
    return f"{project_id}-{scan_id}-{ip}-{workflow.uuid4()}"


@workflow.defn(name=SCAN_BATCH_WORKFLOW_NAME)
class ScanBatchWorkflow:
    """Parent workflow: fans out one child `ScanWorkflow` per task, windowed."""

    def __init__(self) -> None:
        self._total = 0
        self._completed = 0
        self._failed = 0

    @workflow.query(name=QUERY_GET_PROGRESS)
    def get_progress(self) -> ScanBatchResult:
        """Returns the batch's current task-completion counts."""
        return ScanBatchResult(total=self._total, completed=self._completed, failed=self._failed)

    @workflow.run
    async def run(self, input: ScanBatchInput) -> ScanBatchResult:
        """Fans out `input.tasks` as child `ScanWorkflow`s, at most `window_size` at once."""
        self._total = len(input.tasks)
        pending: list[asyncio.Task[None]] = []

        async def run_child(task: ScanTask) -> None:
            child_input = NmapWorkflowInput(
                **task.model_dump(), project_id=input.project_id, scan_id=input.scan_id
            )
            search_attrs = TypedSearchAttributes(
                [
                    SearchAttributePair(SA_PROJECT_ID, input.project_id),
                    SearchAttributePair(SA_SCAN_ID, input.scan_id),
                    SearchAttributePair(SA_IP, task.ip),
                ]
            )
            try:
                await workflow.execute_child_workflow(
                    SCAN_WORKFLOW_NAME,
                    child_input,
                    id=_child_workflow_id(input.project_id, input.scan_id, task.ip),
                    search_attributes=search_attrs,
                    parent_close_policy=workflow.ParentClosePolicy.REQUEST_CANCEL,
                )
                self._completed += 1
            except Exception:
                workflow.logger.exception("Child workflow failed: ip=%s", task.ip)
                self._failed += 1

        for task in input.tasks:
            if len(pending) >= _WINDOW_SIZE:
                _, pending = await workflow.wait(pending, return_when=asyncio.FIRST_COMPLETED)
            pending.append(asyncio.ensure_future(run_child(task)))

        if pending:
            await workflow.wait(pending)

        return ScanBatchResult(total=self._total, completed=self._completed, failed=self._failed)


@workflow.defn(name=SCAN_WORKFLOW_NAME)
class ScanWorkflow:
    """Child workflow: runs one IP's scan, then uploads the result."""

    @workflow.run
    async def run(self, input: NmapWorkflowInput) -> None:
        """Runs the nmap_scan activity, then upload_results with its output."""
        xml = await workflow.execute_activity(
            NMAP_SCAN_ACTIVITY,
            input,
            result_type=str,
            start_to_close_timeout=timedelta(seconds=input.timeout + 60),
            heartbeat_timeout=timedelta(seconds=30),
            retry_policy=RetryPolicy(maximum_attempts=2),
        )
        await workflow.execute_activity(
            UPLOAD_RESULTS_ACTIVITY,
            args=[input, xml],
            start_to_close_timeout=timedelta(seconds=60),
            retry_policy=RetryPolicy(maximum_attempts=4),
        )
