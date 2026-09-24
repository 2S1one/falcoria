"""Builds the outbox event for one reconciled IP."""

import uuid

from falcoria_contracts.enums import PortChangeType
from falcoria_contracts.port import Port
from falcoria_scanledger.events.schemas import (
    HostnameDelta,
    IPChangedEvent,
    PortDelta,
    PortDetail,
    PortRef,
    ServiceChange,
)
from falcoria_scanledger.ips.schemas import ChangeSet, StoredIP

_SERVICE_FIELDS = {PortChangeType.SERVICE, PortChangeType.PRODUCT, PortChangeType.VERSION}


def build_event(
    event_id: uuid.UUID,
    project_id: uuid.UUID,
    scan_id: uuid.UUID | None,
    stored: StoredIP | None,
    change: ChangeSet,
) -> IPChangedEvent | None:
    """Returns the event describing how `change` moves the IP away from `stored`.

    ``stored`` None means the IP is new, so everything in ``change`` counts as
    added. Returns None unless a hostname or open port appeared or disappeared,
    or a service, product or version changed; a status or OS change alone, or a
    new IP with no ports and no hostnames, yields no event. Every list is
    sorted, so the same change always produces the same payload.
    """
    old_hosts = sorted(stored.hostnames) if stored else []
    current_hosts = sorted(change.hostnames)
    old_ports = _details(stored.open_ports if stored else [])
    current_ports = _details(change.open_ports)

    old_refs = [_ref(p) for p in old_ports]
    current_refs = [_ref(p) for p in current_ports]
    added = [r for r in current_refs if r not in old_refs]
    removed = [r for r in old_refs if r not in current_refs]
    service_changes = [
        ServiceChange.model_validate(
            {
                **pc.model_dump(),
                "field": pc.change_type.value,
                "old": pc.old_value,
                "new": pc.new_value,
            }
        )
        for pc in change.port_changes
        if pc.change_type in _SERVICE_FIELDS
    ]
    if old_hosts == current_hosts and not added and not removed and not service_changes:
        return None

    return IPChangedEvent(
        event_id=event_id,
        project_id=project_id,
        ip=change.ip,
        scan_id=scan_id,
        observed_at=change.endtime,
        hostnames=HostnameDelta(
            old=old_hosts,
            current=current_hosts,
            added=[h for h in current_hosts if h not in old_hosts],
            removed=[h for h in old_hosts if h not in current_hosts],
        ),
        ports=PortDelta(old=old_refs, current=current_ports, added=added, removed=removed),
        service_changes=service_changes,
    )


def _details(ports: list[Port]) -> list[PortDetail]:
    details = [PortDetail.model_validate(p.model_dump()) for p in ports]
    return sorted(details, key=lambda p: (p.number, p.protocol.value))


def _ref(port: PortDetail) -> PortRef:
    return PortRef.model_validate(port.model_dump())
