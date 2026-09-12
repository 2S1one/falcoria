"""Worker-internal Temporal payload models — never sent across the tasker/worker boundary."""

from pydantic import BaseModel, Field

from falcoria_contracts.enums import ImportMode


class NmapWorkflowInput(BaseModel):
    """Input to one `ScanWorkflow` — one IP's scan, built by `ScanBatchWorkflow` from a `ScanTask`."""

    project_id: str
    scan_id: str
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
