"""Tests for temporal/workflows.py.

Most functions are exercised against WorkflowEnvironment's time-skipping test
server (fast, in-process). list_running_batches and running_ips use list_workflows
(the visibility API), which that server does not implement - those run against
the real dev cluster instead (docker compose up -d temporal), marked `temporal`.
"""

import asyncio
from collections.abc import AsyncIterator
from datetime import timedelta
from uuid import UUID, uuid4

import pytest
from temporalio import activity, workflow
from temporalio.api.enums.v1 import IndexedValueType
from temporalio.api.operatorservice.v1 import AddSearchAttributesRequest
from temporalio.client import Client, WorkflowExecutionStatus, WorkflowFailureError
from temporalio.common import SearchAttributePair, TypedSearchAttributes
from temporalio.service import RPCError
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import UnsandboxedWorkflowRunner, Worker

with workflow.unsafe.imports_passed_through():
    from falcoria_temporal.converter import pydantic_data_converter
    from falcoria_temporal.search_attributes import SA_IP, SA_PROJECT_ID, SA_SCAN_ID

    from falcoria_contracts.enums import ImportMode
    from falcoria_contracts.scan_io import ScanBatchInput, ScanBatchResult, ScanTask
    from falcoria_contracts.temporal_names import (
        PORT_SCANNER_TASK_QUEUE,
        QUERY_GET_PROGRESS,
        SCAN_BATCH_WORKFLOW_NAME,
        SCAN_WORKFLOW_NAME,
        SEARCH_ATTR_IP,
        SEARCH_ATTR_MODE,
        SEARCH_ATTR_PROJECT_ID,
        SEARCH_ATTR_SCAN_ID,
    )

import falcoria_tasker.temporal.client as temporal_client_module
from falcoria_tasker.config import get_temporal_settings
from falcoria_tasker.temporal.client import connect_temporal, dispose_temporal
from falcoria_tasker.temporal.visibility import batch_workflow_id
from falcoria_tasker.temporal.workflows import (
    list_running_batches,
    query_progress,
    running_ips,
    signal_cancel,
    start_batch_workflows,
    terminate,
)

pytestmark = pytest.mark.anyio

PROJECT_ID = UUID("22222222-2222-2222-2222-222222222222")


@workflow.defn(name=SCAN_BATCH_WORKFLOW_NAME)
class _StubScanBatchWorkflow:
    """Stub carrying the real workflow name, query name, and search attributes."""

    def __init__(self) -> None:
        self._result = ScanBatchResult(total=0, completed=0, failed=0)

    @workflow.query(name=QUERY_GET_PROGRESS)
    def get_progress(self) -> ScanBatchResult:
        return self._result

    @workflow.run
    async def run(self, input: ScanBatchInput) -> ScanBatchResult:
        self._result = ScanBatchResult(total=len(input.tasks), completed=0, failed=0)
        await workflow.wait_condition(lambda: False)
        return self._result


@activity.defn
async def _stub_scan_activity() -> None:
    await asyncio.sleep(2.0)


@workflow.defn(name=SCAN_WORKFLOW_NAME)
class _StubScanWorkflow:
    """Stub per-IP workflow: runs one slow activity so describe() sees it pending."""

    @workflow.run
    async def run(self) -> None:
        await workflow.execute_activity(
            _stub_scan_activity, start_to_close_timeout=timedelta(seconds=5)
        )


def _one_task() -> list[ScanTask]:
    return [ScanTask(ip="10.0.0.1", open_ports_args="-p 80", timeout=30, mode=ImportMode.INSERT)]


# --- Fast: WorkflowEnvironment's time-skipping test server ---


@pytest.fixture
async def temporal(monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[Client]:
    """Starts a time-skipping test server + worker, and points get_temporal_client() at it."""
    async with await WorkflowEnvironment.start_time_skipping(
        data_converter=pydantic_data_converter
    ) as env:
        # A fresh test server has no custom search attributes; the real cluster
        # needs the same one-time registration (see compose.yaml's temporal-init).
        await env.client.operator_service.add_search_attributes(
            AddSearchAttributesRequest(
                namespace=env.client.namespace,
                search_attributes={
                    SEARCH_ATTR_PROJECT_ID: IndexedValueType.INDEXED_VALUE_TYPE_KEYWORD,
                    SEARCH_ATTR_SCAN_ID: IndexedValueType.INDEXED_VALUE_TYPE_KEYWORD,
                    SEARCH_ATTR_MODE: IndexedValueType.INDEXED_VALUE_TYPE_KEYWORD,
                    SEARCH_ATTR_IP: IndexedValueType.INDEXED_VALUE_TYPE_KEYWORD,
                },
            )
        )
        monkeypatch.setattr(temporal_client_module._connection, "client", env.client)
        async with Worker(
            env.client,
            task_queue=PORT_SCANNER_TASK_QUEUE,
            workflows=[_StubScanBatchWorkflow, _StubScanWorkflow],
            activities=[_stub_scan_activity],
            # The stub workflows live in this test module, which pytest's importlib
            # import mode doesn't register as a real package - the sandbox's
            # re-import would fail. Sandboxing is a worker-code-determinism concern
            # for the (separate, future) worker rebuild, not this client-wrapper test.
            workflow_runner=UnsandboxedWorkflowRunner(),
        ):
            yield env.client


async def test_start_batch_workflows_chunks_correctly(temporal: Client) -> None:
    scan_id = str(uuid4())
    tasks = [
        ScanTask(ip=f"10.0.0.{i}", open_ports_args="-p 80", timeout=30, mode=ImportMode.INSERT)
        for i in range(3)
    ]

    await start_batch_workflows(PROJECT_ID, scan_id, tasks, ImportMode.INSERT, chunk_size=2)

    first = await query_progress(batch_workflow_id(PROJECT_ID, scan_id, 0))
    second = await query_progress(batch_workflow_id(PROJECT_ID, scan_id, 1))
    assert {first.total, second.total} == {2, 1}
    with pytest.raises(RPCError):
        await query_progress(batch_workflow_id(PROJECT_ID, scan_id, 2))


async def test_query_progress_returns_current_counts(temporal: Client) -> None:
    scan_id = str(uuid4())
    await start_batch_workflows(PROJECT_ID, scan_id, _one_task(), ImportMode.INSERT, chunk_size=10)
    workflow_id = batch_workflow_id(PROJECT_ID, scan_id, 0)

    result = await query_progress(workflow_id)

    assert result.total == 1
    assert result.completed == 0


async def test_signal_cancel_cancels_the_workflow(temporal: Client) -> None:
    scan_id = str(uuid4())
    await start_batch_workflows(PROJECT_ID, scan_id, _one_task(), ImportMode.INSERT, chunk_size=10)
    workflow_id = batch_workflow_id(PROJECT_ID, scan_id, 0)

    await signal_cancel(workflow_id)

    handle = temporal.get_workflow_handle(workflow_id)
    with pytest.raises(WorkflowFailureError):
        await handle.result()
    description = await handle.describe()
    assert description.status == WorkflowExecutionStatus.CANCELED


async def test_terminate_stops_the_workflow(temporal: Client) -> None:
    scan_id = str(uuid4())
    await start_batch_workflows(PROJECT_ID, scan_id, _one_task(), ImportMode.INSERT, chunk_size=10)
    workflow_id = batch_workflow_id(PROJECT_ID, scan_id, 0)

    await terminate(workflow_id)

    handle = temporal.get_workflow_handle(workflow_id)
    with pytest.raises(WorkflowFailureError):
        await handle.result()
    description = await handle.describe()
    assert description.status == WorkflowExecutionStatus.TERMINATED


# --- Real cluster: needed for list_workflows (visibility) ---


@pytest.fixture
async def real_temporal(monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[Client]:
    """Connects to the real dev Temporal cluster (docker compose up -d temporal)."""
    monkeypatch.setenv("TASKER_TEMPORAL_ADDRESS", "localhost:7233")
    get_temporal_settings.cache_clear()
    client = await connect_temporal()
    try:
        async with Worker(
            client,
            task_queue=PORT_SCANNER_TASK_QUEUE,
            workflows=[_StubScanBatchWorkflow, _StubScanWorkflow],
            activities=[_stub_scan_activity],
            workflow_runner=UnsandboxedWorkflowRunner(),
        ):
            yield client
    finally:
        await dispose_temporal()
        get_temporal_settings.cache_clear()


@pytest.mark.temporal
async def test_list_running_batches_lists_started_batches(real_temporal: Client) -> None:
    scan_id = str(uuid4())
    await start_batch_workflows(PROJECT_ID, scan_id, _one_task(), ImportMode.INSERT, chunk_size=10)
    workflow_id = batch_workflow_id(PROJECT_ID, scan_id, 0)
    try:
        # The real cluster's visibility store indexes a new workflow with a
        # short delay; give it a moment before checking.
        await asyncio.sleep(0.5)
        batches = [wf async for wf in list_running_batches(PROJECT_ID)]
        assert any(wf.id == workflow_id for wf in batches)
    finally:
        await terminate(workflow_id)


@pytest.mark.temporal
async def test_running_ips_reports_worker_identity(real_temporal: Client) -> None:
    scan_id = str(uuid4())
    ip = "10.0.0.42"
    workflow_id = f"scan-workflow-{uuid4()}"
    await real_temporal.start_workflow(
        SCAN_WORKFLOW_NAME,
        id=workflow_id,
        task_queue=PORT_SCANNER_TASK_QUEUE,
        search_attributes=TypedSearchAttributes(
            [
                SearchAttributePair(SA_PROJECT_ID, str(PROJECT_ID)),
                SearchAttributePair(SA_SCAN_ID, scan_id),
                SearchAttributePair(SA_IP, ip),
            ]
        ),
    )
    try:
        # The activity sleeps 2s; wait long enough for the real cluster's
        # visibility store to index the workflow (observed ~0.5s lag), but
        # well before the activity itself completes.
        await asyncio.sleep(1.0)

        targets = await running_ips(PROJECT_ID, scan_id)

        assert len(targets) == 1
        reported_ip, worker = targets[0]
        assert reported_ip == ip
        assert worker
    finally:
        await real_temporal.get_workflow_handle(workflow_id).terminate()


@pytest.mark.temporal
async def test_running_ips_omits_targets_without_an_ip_attribute(real_temporal: Client) -> None:
    scan_id = str(uuid4())
    workflow_id = f"scan-workflow-{uuid4()}"
    await real_temporal.start_workflow(
        SCAN_WORKFLOW_NAME,
        id=workflow_id,
        task_queue=PORT_SCANNER_TASK_QUEUE,
        search_attributes=TypedSearchAttributes(
            [
                SearchAttributePair(SA_PROJECT_ID, str(PROJECT_ID)),
                SearchAttributePair(SA_SCAN_ID, scan_id),
            ]
        ),
    )
    try:
        await asyncio.sleep(0.5)

        targets = await running_ips(PROJECT_ID, scan_id)

        assert targets == []
    finally:
        await real_temporal.get_workflow_handle(workflow_id).terminate()
