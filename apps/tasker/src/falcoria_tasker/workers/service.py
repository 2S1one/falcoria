"""Worker fleet-visibility policy: group poller sightings into the fleet view."""

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from falcoria_contracts.temporal_names import PORT_SCANNER_TASK_QUEUE
from falcoria_contracts.worker_identity import parse_worker_identity
from falcoria_tasker.config import get_app_settings
from falcoria_tasker.temporal.workflows import describe_task_queue_pollers
from falcoria_tasker.workers.schemas import WorkerInfo, WorkersResponse


@dataclass(slots=True)
class _WorkerAggregate:
    """A worker identity's most recent poll and which poller types it's served."""

    last_access_time: datetime | None = None
    poller_types: set[str] = field(default_factory=set)


async def get_workers() -> WorkersResponse:
    """Lists the active worker fleet on the port-scanner task queue."""
    sightings = await describe_task_queue_pollers(PORT_SCANNER_TASK_QUEUE)

    by_identity: dict[str, _WorkerAggregate] = defaultdict(_WorkerAggregate)
    for sighting in sightings:
        aggregate = by_identity[sighting.identity]
        if sighting.last_access_time and (
            aggregate.last_access_time is None
            or sighting.last_access_time > aggregate.last_access_time
        ):
            aggregate.last_access_time = sighting.last_access_time
        aggregate.poller_types.add(sighting.poller_type)

    now = datetime.now(UTC)
    stale_after = timedelta(seconds=get_app_settings().worker_poller_stale_seconds)

    workers: list[WorkerInfo] = []
    for identity, aggregate in by_identity.items():
        last_access_time = aggregate.last_access_time
        if last_access_time is None or now - last_access_time > stale_after:
            continue
        parsed = parse_worker_identity(identity)
        display_identity = (
            f"{parsed.hostname}:{parsed.external_ip}" if parsed.external_ip else parsed.hostname
        )
        workers.append(
            WorkerInfo(
                identity=display_identity,
                external_ip=parsed.external_ip,
                last_access_time=last_access_time,
                last_seen_seconds=int((now - last_access_time).total_seconds()),
                task_queue=PORT_SCANNER_TASK_QUEUE,
                poller_types=sorted(aggregate.poller_types),
            )
        )

    workers.sort(key=lambda w: w.last_access_time or datetime.min.replace(tzinfo=UTC), reverse=True)

    return WorkersResponse(workers=workers, available_workers=len(workers))
