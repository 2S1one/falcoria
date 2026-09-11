from uuid import UUID

from falcoria_temporal.search_attributes import SA_IP, SA_MODE, SA_PROJECT_ID, SA_SCAN_ID
from temporalio.common import SearchAttributePair, TypedSearchAttributes

from falcoria_contracts.enums import ImportMode
from falcoria_tasker.temporal.visibility import (
    batch_workflow_id,
    batch_workflows_by_scan_query,
    build_batch_search_attrs,
    extract_ip_from_search_attrs,
    running_batch_query,
    running_scan_targets_query,
    running_scans_by_ips_query,
    running_scans_query,
)

PROJECT_ID = UUID("11111111-1111-1111-1111-111111111111")


def test_batch_workflow_id_is_deterministic() -> None:
    assert batch_workflow_id(PROJECT_ID, "scan-1", 2) == f"{PROJECT_ID}-scan-1-2"


def test_batch_workflows_by_scan_query() -> None:
    query = batch_workflows_by_scan_query(PROJECT_ID, "scan-1")

    assert f'ProjectId = "{PROJECT_ID}"' in query
    assert 'ScanId = "scan-1"' in query
    assert 'WorkflowType = "ScanBatchWorkflow"' in query


def test_running_batch_query() -> None:
    query = running_batch_query(PROJECT_ID)

    assert 'ExecutionStatus = "Running"' in query
    assert 'WorkflowType = "ScanBatchWorkflow"' in query


def test_running_scans_query() -> None:
    query = running_scans_query(PROJECT_ID)

    assert 'WorkflowType = "ScanWorkflow"' in query


def test_running_scans_by_ips_query() -> None:
    query = running_scans_by_ips_query(PROJECT_ID, ["10.0.0.1", "10.0.0.2"])

    assert query.startswith(running_scans_query(PROJECT_ID))
    assert 'Ip IN ("10.0.0.1", "10.0.0.2")' in query


def test_build_batch_search_attrs_roundtrips() -> None:
    attrs = build_batch_search_attrs(PROJECT_ID, "scan-1", ImportMode.INSERT)

    assert attrs.get(SA_PROJECT_ID) == str(PROJECT_ID)
    assert attrs.get(SA_SCAN_ID) == "scan-1"
    assert attrs.get(SA_MODE) == ImportMode.INSERT.value


def test_extract_ip_from_search_attrs_present() -> None:
    attrs = TypedSearchAttributes([SearchAttributePair(SA_IP, "10.0.0.1")])

    assert extract_ip_from_search_attrs(attrs) == "10.0.0.1"


def test_extract_ip_from_search_attrs_absent() -> None:
    assert extract_ip_from_search_attrs(TypedSearchAttributes.empty) is None


def test_running_scan_targets_query() -> None:
    query = running_scan_targets_query(PROJECT_ID, "scan-1")

    assert query.startswith(running_scans_query(PROJECT_ID))
    assert 'ScanId = "scan-1"' in query
