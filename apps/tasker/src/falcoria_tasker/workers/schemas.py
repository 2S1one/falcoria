"""Worker fleet-visibility response schemas."""

from datetime import datetime

from pydantic import BaseModel, Field


class WorkerInfo(BaseModel):
    """One worker process currently (or recently) polling the port-scanner task queue."""

    identity: str = Field(description="hostname:external_ip, as reported by the worker.")
    external_ip: str | None
    last_access_time: datetime | None = Field(
        description="Most recent poll across the workflow and activity queues."
    )
    last_seen_seconds: int | None = Field(
        description="Seconds since last_access_time, or None if it was never seen."
    )
    task_queue: str
    poller_types: list[str] = Field(
        description='Which of "workflow" / "activity" this worker has polled.'
    )


class WorkersResponse(BaseModel):
    """The active worker fleet on the port-scanner task queue."""

    workers: list[WorkerInfo]
    available_workers: int
