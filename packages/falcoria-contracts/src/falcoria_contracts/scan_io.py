"""Temporal scan I/O contract shared between tasker and worker."""

from pydantic import BaseModel, Field

from falcoria_contracts.enums import ImportMode


class ScanTask(BaseModel):
    """One (IP, port-shard) unit of work inside a scan batch."""

    ip: str
    open_ports_args: str = Field(
        description="Pre-built scanner arguments for the open-ports phase."
    )
    service_args: str | None = Field(
        default=None,
        description="Pre-built scanner arguments for the service-detection phase, or None to skip it.",
    )
    timeout: int = Field(gt=0, description="Per-IP scan timeout in seconds.")
    mode: ImportMode
    hostnames: list[str] = []


class ScanBatchInput(BaseModel):
    """Input to one `ScanBatchWorkflow` — a chunk of a scan's tasks."""

    project_id: str
    scan_id: str
    tasks: list[ScanTask]


class ScanBatchResult(BaseModel):
    """Output of a `ScanBatchWorkflow` — its final task-completion counts."""

    total: int
    completed: int
    failed: int
