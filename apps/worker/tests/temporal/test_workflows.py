"""Tests for temporal/workflows.py — ScanBatchWorkflow fan-out and ScanWorkflow.

Runs against WorkflowEnvironment's time-skipping test server, using the real
ScanBatchWorkflow/ScanWorkflow classes with Temporal's default (sandboxed)
workflow runner — this exercises the actual import-isolation design (activities
referenced by name, not import), not just a stand-in.
"""

from collections.abc import AsyncIterator

import pytest
from falcoria_temporal.converter import pydantic_data_converter
from temporalio import activity
from temporalio.api.enums.v1 import IndexedValueType
from temporalio.api.operatorservice.v1 import AddSearchAttributesRequest
from temporalio.client import Client
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from falcoria_contracts.enums import ImportMode
from falcoria_contracts.scan_io import ScanBatchInput, ScanTask
from falcoria_contracts.temporal_names import (
    PORT_SCANNER_TASK_QUEUE,
    SEARCH_ATTR_IP,
    SEARCH_ATTR_MODE,
    SEARCH_ATTR_PROJECT_ID,
    SEARCH_ATTR_SCAN_ID,
)
from falcoria_worker.temporal.activity_names import NMAP_SCAN_ACTIVITY, UPLOAD_RESULTS_ACTIVITY
from falcoria_worker.temporal.schemas import NmapWorkflowInput
from falcoria_worker.temporal.workflows import ScanBatchWorkflow, ScanWorkflow

pytestmark = pytest.mark.anyio


@activity.defn(name=NMAP_SCAN_ACTIVITY)
async def _stub_nmap_scan(input: NmapWorkflowInput) -> str:
    return "<xml/>"


@activity.defn(name=NMAP_SCAN_ACTIVITY)
async def _failing_nmap_scan(input: NmapWorkflowInput) -> str:
    raise RuntimeError("scan failed")


@activity.defn(name=UPLOAD_RESULTS_ACTIVITY)
async def _stub_upload_results(input: NmapWorkflowInput, xml: str) -> None:
    return None


def _tasks(n: int) -> list[ScanTask]:
    return [
        ScanTask(ip=f"10.0.0.{i}", open_ports_args="-p 80", timeout=5, mode=ImportMode.INSERT)
        for i in range(n)
    ]


@pytest.fixture
async def temporal_env() -> AsyncIterator[Client]:
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
        yield env.client


async def test_scan_batch_workflow_completes_all_tasks(temporal_env: Client) -> None:
    async with Worker(
        temporal_env,
        task_queue=PORT_SCANNER_TASK_QUEUE,
        workflows=[ScanBatchWorkflow, ScanWorkflow],
        activities=[_stub_nmap_scan, _stub_upload_results],
    ):
        result = await temporal_env.execute_workflow(
            ScanBatchWorkflow.run,
            ScanBatchInput(project_id="proj-1", scan_id="scan-1", tasks=_tasks(5)),
            id="test-batch-completes",
            task_queue=PORT_SCANNER_TASK_QUEUE,
        )

    assert result.total == 5
    assert result.completed == 5
    assert result.failed == 0


async def test_scan_batch_workflow_counts_child_failures(temporal_env: Client) -> None:
    async with Worker(
        temporal_env,
        task_queue=PORT_SCANNER_TASK_QUEUE,
        workflows=[ScanBatchWorkflow, ScanWorkflow],
        activities=[_failing_nmap_scan, _stub_upload_results],
    ):
        result = await temporal_env.execute_workflow(
            ScanBatchWorkflow.run,
            ScanBatchInput(project_id="proj-1", scan_id="scan-1", tasks=_tasks(3)),
            id="test-batch-failures",
            task_queue=PORT_SCANNER_TASK_QUEUE,
        )

    assert result.total == 3
    assert result.completed == 0
    assert result.failed == 3
