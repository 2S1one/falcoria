"""The pinned Temporal pydantic data converter, shared by tasker and worker.

Lives here rather than in falcoria-contracts because it needs `temporalio`,
which falcoria-contracts' pydantic-only rule (AGENTS.md) forbids.
"""

from temporalio.contrib.pydantic import pydantic_data_converter

__all__ = ["pydantic_data_converter"]
