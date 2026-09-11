"""Temporal workflow, task-queue, and query names shared between tasker and worker."""

SCAN_WORKFLOW_NAME = "ScanWorkflow"
SCAN_BATCH_WORKFLOW_NAME = "ScanBatchWorkflow"

PORT_SCANNER_TASK_QUEUE = "port-scanner-pool"

QUERY_GET_PROGRESS = "get_progress"

# Custom search attributes; must be pre-registered on the Temporal cluster
# (keyword type) before any workflow sets them.
SEARCH_ATTR_PROJECT_ID = "ProjectId"
SEARCH_ATTR_SCAN_ID = "ScanId"
SEARCH_ATTR_MODE = "Mode"
SEARCH_ATTR_IP = "Ip"
