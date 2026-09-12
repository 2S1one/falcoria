"""Impure Temporal Client operations: starting, querying, and cancelling scan workflows."""

import asyncio
import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Literal
from uuid import UUID, uuid4

from google.protobuf.timestamp_pb2 import Timestamp
from temporalio.api.batch.v1 import BatchOperationCancellation, BatchOperationTermination
from temporalio.api.enums.v1 import TaskQueueType
from temporalio.api.taskqueue.v1 import TaskQueue
from temporalio.api.workflowservice.v1 import DescribeTaskQueueRequest, StartBatchOperationRequest
from temporalio.client import (
    WorkflowExecutionAsyncIterator,
    WorkflowExecutionStatus,
)
from temporalio.service import RPCError

from falcoria_contracts.enums import ImportMode
from falcoria_contracts.scan_io import ScanBatchInput, ScanBatchResult, ScanTask
from falcoria_contracts.temporal_names import (
    PORT_SCANNER_TASK_QUEUE,
    QUERY_GET_PROGRESS,
    SCAN_BATCH_WORKFLOW_NAME,
)
from falcoria_tasker.concurrency import bounded_gather
from falcoria_tasker.temporal.client import get_temporal_client
from falcoria_tasker.temporal.visibility import (
    batch_workflow_id,
    batch_workflows_by_scan_query,
    build_batch_search_attrs,
    extract_ip_from_search_attrs,
    extract_scan_id_from_search_attrs,
    running_batch_query,
    running_scan_targets_query,
    running_scans_query,
)

logger = logging.getLogger("falcoria_tasker")


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


async def query_progress(workflow_id: str, *, timeout_seconds: float = 2.0) -> ScanBatchResult:
    """Queries a running ScanBatchWorkflow's current task-completion counts.

    Bounded by timeout_seconds rather than the default 30s gRPC deadline - a
    batch queued with no worker polling its task queue would otherwise hang
    a status request for the full default deadline.
    """
    handle = get_temporal_client().get_workflow_handle(workflow_id)
    return await handle.query(
        QUERY_GET_PROGRESS,
        result_type=ScanBatchResult,
        rpc_timeout=timedelta(seconds=timeout_seconds),
    )


async def _safe_query_progress(workflow_id: str, timeout_seconds: float) -> ScanBatchResult | None:
    """Queries workflow_id's progress, or None if the query itself failed.

    A batch that was never picked up by a worker (queued, or cancelled before
    any worker started its first task) can't serve a query at all - Temporal
    raises RPCError rather than returning a result. That's a query-layer
    failure, not evidence the batch made no progress, so it's logged and
    excluded from the aggregate rather than reported as zero.
    """
    try:
        return await query_progress(workflow_id, timeout_seconds=timeout_seconds)
    except RPCError:
        logger.warning("Failed to query progress for batch workflow %s.", workflow_id)
        return None


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
    candidates = set(ips)
    client = get_temporal_client()
    running: set[str] = set()
    async for workflow in client.list_workflows(running_scans_query(project_id)):
        ip = extract_ip_from_search_attrs(workflow.typed_search_attributes)
        if ip and ip in candidates:
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


class BatchState(str, Enum):
    """Overall execution state of a scan's batch workflows, derived from their Temporal status."""

    RUNNING = "running"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"


@dataclass(slots=True)
class ScanProgress:
    """Aggregated task-completion counts and overall state for one scan's batch workflows."""

    total: int
    completed: int
    failed: int
    state: BatchState


async def scan_progress(
    project_id: UUID, scan_id: str, semaphore_limit: int, query_timeout_seconds: float
) -> ScanProgress | None:
    """Aggregates total/completed/failed and overall state across a scan's batch workflows.

    Always queries each batch live via query_progress(), regardless of its
    Temporal execution status - querying a closed workflow isn't guaranteed
    servable via .result(), but a query always is. state comes entirely from
    Temporal visibility metadata (execution.status), independent of query
    success, so it's always reported even if every query below fails.
    Concurrency is capped at semaphore_limit in-flight queries. Returns None
    if no batch workflow was ever started for scan_id.
    """
    client = get_temporal_client()
    executions = [
        wf async for wf in client.list_workflows(batch_workflows_by_scan_query(project_id, scan_id))
    ]
    if not executions:
        return None

    queried = await bounded_gather(
        (_safe_query_progress(execution.id, query_timeout_seconds) for execution in executions),
        semaphore_limit,
    )
    results = [r for r in queried if r is not None]
    statuses = {execution.status for execution in executions}
    if WorkflowExecutionStatus.RUNNING in statuses:
        state = BatchState.RUNNING
    elif statuses & {WorkflowExecutionStatus.CANCELED, WorkflowExecutionStatus.TERMINATED}:
        state = BatchState.CANCELLED
    elif statuses & {WorkflowExecutionStatus.FAILED, WorkflowExecutionStatus.TIMED_OUT}:
        state = BatchState.FAILED
    else:
        state = BatchState.COMPLETED

    return ScanProgress(
        total=sum(r.total for r in results),
        completed=sum(r.completed for r in results),
        failed=sum(r.failed for r in results),
        state=state,
    )


async def start_cancel_batch(query: str) -> None:
    """Requests a graceful cancel, via batch operation, of everything matching query."""
    client = get_temporal_client()
    await client.workflow_service.start_batch_operation(
        StartBatchOperationRequest(
            namespace=client.namespace,
            visibility_query=query,
            job_id=str(uuid4()),
            reason="scan cancel requested",
            cancellation_operation=BatchOperationCancellation(),
        )
    )


async def start_terminate_batch(query: str) -> None:
    """Force-terminates, via batch operation, everything currently matching query."""
    client = get_temporal_client()
    await client.workflow_service.start_batch_operation(
        StartBatchOperationRequest(
            namespace=client.namespace,
            visibility_query=query,
            job_id=str(uuid4()),
            reason="scan cancel grace period expired",
            termination_operation=BatchOperationTermination(),
        )
    )


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
