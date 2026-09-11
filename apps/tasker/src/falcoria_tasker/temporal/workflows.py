"""Impure Temporal Client operations: starting, querying, and cancelling scan workflows."""

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal
from uuid import UUID

from google.protobuf.timestamp_pb2 import Timestamp
from temporalio.api.enums.v1 import TaskQueueType
from temporalio.api.taskqueue.v1 import TaskQueue
from temporalio.api.workflowservice.v1 import DescribeTaskQueueRequest
from temporalio.client import (
    WorkflowExecution,
    WorkflowExecutionAsyncIterator,
    WorkflowExecutionStatus,
)

from falcoria_contracts.enums import ImportMode
from falcoria_contracts.scan_io import ScanBatchInput, ScanBatchResult, ScanTask
from falcoria_contracts.temporal_names import (
    PORT_SCANNER_TASK_QUEUE,
    QUERY_GET_PROGRESS,
    SCAN_BATCH_WORKFLOW_NAME,
)
from falcoria_tasker.constants import CANCEL_BATCH_SIZE
from falcoria_tasker.temporal.client import get_temporal_client
from falcoria_tasker.temporal.visibility import (
    batch_workflow_id,
    batch_workflows_by_scan_query,
    build_batch_search_attrs,
    extract_ip_from_search_attrs,
    extract_scan_id_from_search_attrs,
    running_batch_by_scan_query,
    running_batch_query,
    running_scan_targets_query,
    running_scans_by_ips_query,
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


async def already_running_ips(project_id: UUID, ips: list[str]) -> set[str]:
    """Returns the subset of ips currently scanned by any running scan in project_id.

    Used before a scan_id exists yet, to dedupe INSERT-mode targets against
    every scan already in flight for the project - not just one scan_id.
    """
    if not ips:
        return set()
    client = get_temporal_client()
    running: set[str] = set()
    async for workflow in client.list_workflows(running_scans_by_ips_query(project_id, ips)):
        ip = extract_ip_from_search_attrs(workflow.typed_search_attributes)
        if ip:
            running.add(ip)
    return running


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


async def list_running_scan_ids(project_id: UUID) -> set[str]:
    """Returns the distinct scan_ids of the project's currently running batch workflows."""
    scan_ids: set[str] = set()
    async for workflow in list_running_batches(project_id):
        scan_id = extract_scan_id_from_search_attrs(workflow.typed_search_attributes)
        if scan_id:
            scan_ids.add(scan_id)
    return scan_ids


async def scan_progress(project_id: UUID, scan_id: str) -> ScanBatchResult | None:
    """Aggregates total/completed/failed across every batch workflow of one scan.

    A still-running batch is queried live; a closed one returns its stored
    result directly - querying a closed workflow execution isn't guaranteed
    servable. Returns None if no batch workflow was ever started for scan_id.
    """
    client = get_temporal_client()
    executions = [
        wf async for wf in client.list_workflows(batch_workflows_by_scan_query(project_id, scan_id))
    ]
    if not executions:
        return None

    async def _progress(execution: WorkflowExecution) -> ScanBatchResult:
        if execution.status is WorkflowExecutionStatus.RUNNING:
            return await query_progress(execution.id)
        handle = client.get_workflow_handle(execution.id, result_type=ScanBatchResult)
        return await handle.result()

    results = await asyncio.gather(*(_progress(execution) for execution in executions))
    return ScanBatchResult(
        total=sum(r.total for r in results),
        completed=sum(r.completed for r in results),
        failed=sum(r.failed for r in results),
    )


async def cancel_running_batches(project_id: UUID, scan_id: str | None) -> list[str]:
    """Signals cancel on every running batch workflow, optionally scoped to scan_id.

    Returns the cancelled workflow ids.
    """
    client = get_temporal_client()
    query = (
        running_batch_query(project_id)
        if scan_id is None
        else running_batch_by_scan_query(project_id, scan_id)
    )
    workflow_ids = [wf.id async for wf in client.list_workflows(query)]
    await asyncio.gather(*(client.get_workflow_handle(wid).cancel() for wid in workflow_ids))
    return workflow_ids


async def cancel_running_scans_by_ips(project_id: UUID, ips: list[str]) -> list[str]:
    """Signals cancel on every running per-IP scan workflow matching any of ips.

    Chunks the visibility query at CANCEL_BATCH_SIZE ips per call, since an
    unbounded IN(...) clause doesn't scale. Returns the cancelled workflow ids.
    """
    client = get_temporal_client()
    workflow_ids: list[str] = []
    unique_ips = sorted(set(ips))
    for i in range(0, len(unique_ips), CANCEL_BATCH_SIZE):
        chunk = unique_ips[i : i + CANCEL_BATCH_SIZE]
        chunk_ids = [
            wf.id
            async for wf in client.list_workflows(running_scans_by_ips_query(project_id, chunk))
        ]
        await asyncio.gather(*(client.get_workflow_handle(wid).cancel() for wid in chunk_ids))
        workflow_ids.extend(chunk_ids)
    return workflow_ids


async def terminate_if_still_running(workflow_id: str) -> None:
    """Terminates workflow_id only if it is still RUNNING; a no-op otherwise."""
    handle = get_temporal_client().get_workflow_handle(workflow_id)
    description = await handle.describe()
    if description.status is WorkflowExecutionStatus.RUNNING:
        await handle.terminate()


@dataclass(slots=True)
class PollerSighting:
    """One poller entry read from a DescribeTaskQueue response."""

    identity: str
    last_access_time: datetime | None
    poller_type: Literal["workflow", "activity"]


def _timestamp_to_datetime(ts: Timestamp) -> datetime | None:
    if ts.seconds == 0 and ts.nanos == 0:
        return None
    return ts.ToDatetime(tzinfo=UTC)


async def describe_task_queue_pollers(queue_name: str) -> list[PollerSighting]:
    """Lists every poller currently reported for queue_name, across both poller types."""
    client = get_temporal_client()

    async def _pollers(
        task_queue_type: TaskQueueType.ValueType, poller_type: Literal["workflow", "activity"]
    ) -> list[PollerSighting]:
        response = await client.workflow_service.describe_task_queue(
            DescribeTaskQueueRequest(
                namespace=client.namespace,
                task_queue=TaskQueue(name=queue_name),
                task_queue_type=task_queue_type,
            )
        )
        return [
            PollerSighting(
                identity=poller.identity,
                last_access_time=_timestamp_to_datetime(poller.last_access_time),
                poller_type=poller_type,
            )
            for poller in response.pollers
            if poller.identity
        ]

    workflow_pollers, activity_pollers = await asyncio.gather(
        _pollers(TaskQueueType.TASK_QUEUE_TYPE_WORKFLOW, "workflow"),
        _pollers(TaskQueueType.TASK_QUEUE_TYPE_ACTIVITY, "activity"),
    )
    return workflow_pollers + activity_pollers
