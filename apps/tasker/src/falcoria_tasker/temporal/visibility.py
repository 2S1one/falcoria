"""Pure Temporal visibility helpers: workflow ids, query strings, search attributes."""

from uuid import UUID

from falcoria_temporal.search_attributes import SA_IP, SA_MODE, SA_PROJECT_ID, SA_SCAN_ID
from temporalio.common import SearchAttributePair, TypedSearchAttributes

from falcoria_contracts.enums import ImportMode
from falcoria_contracts.temporal_names import SCAN_BATCH_WORKFLOW_NAME, SCAN_WORKFLOW_NAME


def batch_workflow_id(project_id: UUID, scan_id: str, batch_index: int) -> str:
    """Builds the deterministic workflow id for one ScanBatchWorkflow chunk."""
    return f"{project_id}-{scan_id}-{batch_index}"


def batch_workflows_by_scan_query(project_id: UUID, scan_id: str) -> str:
    """Builds a visibility query for every ScanBatchWorkflow started by one scan."""
    return (
        f'ProjectId = "{project_id}" AND ScanId = "{scan_id}" '
        f'AND WorkflowType = "{SCAN_BATCH_WORKFLOW_NAME}"'
    )


def build_batch_search_attrs(
    project_id: UUID, scan_id: str, mode: ImportMode
) -> TypedSearchAttributes:
    """Builds the search attributes set on a ScanBatchWorkflow at start."""
    return TypedSearchAttributes(
        [
            SearchAttributePair(SA_PROJECT_ID, str(project_id)),
            SearchAttributePair(SA_SCAN_ID, scan_id),
            SearchAttributePair(SA_MODE, mode.value),
        ]
    )


def extract_ip_from_search_attrs(search_attributes: TypedSearchAttributes) -> str | None:
    """Returns the Ip search attribute's value, or None if absent."""
    return search_attributes.get(SA_IP)


def running_batch_query(project_id: UUID) -> str:
    """Builds a visibility query for a project's currently running ScanBatchWorkflows."""
    return (
        f'ExecutionStatus = "Running" AND ProjectId = "{project_id}" '
        f'AND WorkflowType = "{SCAN_BATCH_WORKFLOW_NAME}"'
    )


def running_scans_query(project_id: UUID) -> str:
    """Builds a visibility query for a project's currently running ScanWorkflows."""
    return (
        f'ExecutionStatus = "Running" AND ProjectId = "{project_id}" '
        f'AND WorkflowType = "{SCAN_WORKFLOW_NAME}"'
    )


def running_scans_by_ips_query(project_id: UUID, ips: list[str]) -> str:
    """Builds a visibility query for a project's running ScanWorkflows scanning any of ips."""
    ip_list = ", ".join(f'"{ip}"' for ip in ips)
    return f"{running_scans_query(project_id)} AND Ip IN ({ip_list})"
