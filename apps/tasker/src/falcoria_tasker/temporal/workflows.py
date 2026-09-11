"""Impure Temporal Client operations: starting, querying, and cancelling scan workflows."""

import asyncio
from uuid import UUID

from temporalio.client import WorkflowExecutionAsyncIterator

from falcoria_contracts.enums import ImportMode
from falcoria_contracts.scan_io import ScanBatchInput, ScanBatchResult, ScanTask
from falcoria_contracts.temporal_names import (
    PORT_SCANNER_TASK_QUEUE,
    QUERY_GET_PROGRESS,
    SCAN_BATCH_WORKFLOW_NAME,
)
from falcoria_tasker.temporal.client import get_temporal_client
from falcoria_tasker.temporal.visibility import (
    batch_workflow_id,
    build_batch_search_attrs,
    extract_ip_from_search_attrs,
    running_batch_query,
    running_scan_targets_query,
)


async def start_batch_workflows(
    project_id: UUID,
    scan_id: str,
    tasks: list[ScanTask],
    mode: ImportMode,
    chunk_size: int,
) -> None:
    """Starts one ScanBatchWorkflow per chunk of at most chunk_size tasks."""
    client = get_temporal_client()
    search_attrs = build_batch_search_attrs(project_id, scan_id, mode)
    chunks = [tasks[i : i + chunk_size] for i in range(0, len(tasks), chunk_size)]

    await asyncio.gather(
        *(
            client.start_workflow(
                SCAN_BATCH_WORKFLOW_NAME,
                ScanBatchInput(project_id=str(project_id), scan_id=scan_id, tasks=chunk),
                id=batch_workflow_id(project_id, scan_id, batch_index),
                task_queue=PORT_SCANNER_TASK_QUEUE,
                search_attributes=search_attrs,
                result_type=ScanBatchResult,
            )
            for batch_index, chunk in enumerate(chunks)
        )
    )


def list_running_batches(project_id: UUID) -> WorkflowExecutionAsyncIterator:
    """Lists a project's currently running ScanBatchWorkflows."""
    return get_temporal_client().list_workflows(running_batch_query(project_id))


async def query_progress(workflow_id: str) -> ScanBatchResult:
    """Queries a running ScanBatchWorkflow's current task-completion counts."""
    handle = get_temporal_client().get_workflow_handle(workflow_id)
    return await handle.query(QUERY_GET_PROGRESS, result_type=ScanBatchResult)


async def signal_cancel(workflow_id: str) -> None:
    """Requests cancellation of a running workflow."""
    await get_temporal_client().get_workflow_handle(workflow_id).cancel()


async def terminate(workflow_id: str) -> None:
    """Forcibly terminates a workflow, regardless of its current state."""
    await get_temporal_client().get_workflow_handle(workflow_id).terminate()


async def running_ips(project_id: UUID, scan_id: str) -> list[tuple[str, str]]:
    """Lists (ip, worker_identity) for one scan's currently running targets.

    A running ScanWorkflow with no assigned worker yet (no pending activity)
    is omitted - it has no worker identity to report.
    """
    client = get_temporal_client()
    targets: list[tuple[str, str]] = []
    async for workflow in client.list_workflows(running_scan_targets_query(project_id, scan_id)):
        ip = extract_ip_from_search_attrs(workflow.typed_search_attributes)
        if not ip:
            continue
        description = await client.get_workflow_handle(workflow.id).describe()
        pending_activities = description.raw_description.pending_activities
        if not pending_activities:
            continue
        identity = pending_activities[0].last_worker_identity
        worker = identity.split(":")[-1] if ":" in identity else identity
        if worker:
            targets.append((ip, worker))
    return targets
