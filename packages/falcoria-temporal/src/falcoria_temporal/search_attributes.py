"""Pre-built Temporal search-attribute keys, shared by tasker and worker.

Lives here rather than in falcoria-contracts because it needs `temporalio`,
which falcoria-contracts' pydantic-only rule (AGENTS.md) forbids.
"""

from temporalio.common import SearchAttributeKey

from falcoria_contracts.temporal_names import (
    SEARCH_ATTR_IP,
    SEARCH_ATTR_MODE,
    SEARCH_ATTR_PROJECT_ID,
    SEARCH_ATTR_SCAN_ID,
)

SA_PROJECT_ID = SearchAttributeKey.for_keyword(SEARCH_ATTR_PROJECT_ID)
SA_SCAN_ID = SearchAttributeKey.for_keyword(SEARCH_ATTR_SCAN_ID)
# Operator-facing only: set on ScanBatchWorkflow for ad-hoc queries in Temporal's
# own UI/CLI (e.g. `temporal workflow list -q "Mode='replace'"`). No query builder
# in this codebase filters on it — that's intentional, not an oversight.
SA_MODE = SearchAttributeKey.for_keyword(SEARCH_ATTR_MODE)
SA_IP = SearchAttributeKey.for_keyword(SEARCH_ATTR_IP)
