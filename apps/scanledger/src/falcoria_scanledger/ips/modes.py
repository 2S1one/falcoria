"""The four import-mode policies.

Pure: a mode maps (stored state, incoming report) to one ChangeSet; the caller
applies it inside a transaction.
"""

from typing import NamedTuple

from falcoria_contracts.enums import ImportMode, PortChangeType, PortProtocol, PortState
from falcoria_contracts.port import Port
from falcoria_scanledger.ips.reconcile import (
    close_stale_port,
    diff_ports,
    is_open,
    refresh_port,
)
from falcoria_scanledger.ips.schemas import ChangeSet, IPIn, PortChange, StoredIP


class _Policy(NamedTuple):
    add_new_open: bool  # add ports open in the report but not stored
    refresh_matched: bool  # refresh service fields on ports open in both
    close_stale: bool  # close stored ports no longer open (REPLACE close rules)
    refresh_meta: bool  # refresh host status / os


# The LOCKED per-mode matrix, one row each.
_POLICIES: dict[ImportMode, _Policy] = {
    ImportMode.INSERT: _Policy(False, False, False, False),
    ImportMode.APPEND: _Policy(True, False, False, False),
    ImportMode.UPDATE: _Policy(True, True, False, True),
    ImportMode.REPLACE: _Policy(True, True, True, True),
}


def apply_mode(mode: ImportMode, stored: StoredIP | None, incoming: IPIn) -> ChangeSet:
    """Reconcile one incoming IP against its stored state under `mode`.

    ``stored`` None means the address is new: every mode creates it with only
    its open ports. For an existing address the mode's policy decides which of
    add / refresh / close / metadata-refresh run; all modes merge new hostnames.
    """
    if stored is None:
        return _created(incoming)
    return _updated(_POLICIES[mode], stored, incoming)


def _created(incoming: IPIn) -> ChangeSet:
    open_ports = [p for p in incoming.ports if is_open(p)]
    return ChangeSet(
        ip=incoming.ip,
        created=True,
        changed=True,
        endtime=incoming.endtime,
        status=incoming.status,
        os=incoming.os,
        open_ports=open_ports,
        port_changes=[_opened(p) for p in open_ports],
        hostnames=list(incoming.hostnames),
        new_hostnames=list(incoming.hostnames),
    )


def _updated(policy: _Policy, stored: StoredIP, incoming: IPIn) -> ChangeSet:
    diff = diff_ports(stored.open_ports, incoming.ports)
    kept: dict[tuple[int, PortProtocol], Port] = {
        (p.number, p.protocol): p for p in stored.open_ports
    }
    changes: list[PortChange] = []

    if policy.add_new_open:
        for port in diff.new_open:
            kept[(port.number, port.protocol)] = port
            changes.append(_opened(port))

    if policy.refresh_matched:
        for stored_port, incoming_port in diff.matched:
            updated, field_changes = refresh_port(stored_port, incoming_port)
            kept[(stored_port.number, stored_port.protocol)] = updated
            changes.extend(field_changes)

    if policy.close_stale:
        for stored_port, incoming_port in diff.stale:
            change = close_stale_port(stored_port, incoming_port, incoming.scanned_ports)
            if change is not None:
                kept.pop((stored_port.number, stored_port.protocol), None)
                changes.append(change)

    known = set(stored.hostnames)
    new_hostnames = [h for h in incoming.hostnames if h not in known]

    status = incoming.status if policy.refresh_meta and incoming.status else stored.status
    os = incoming.os if policy.refresh_meta and incoming.os else stored.os

    return ChangeSet(
        ip=incoming.ip,
        created=False,
        changed=bool(changes or new_hostnames) or status != stored.status or os != stored.os,
        endtime=incoming.endtime,
        status=status,
        os=os,
        open_ports=list(kept.values()),
        port_changes=changes,
        hostnames=[*stored.hostnames, *new_hostnames],
        new_hostnames=new_hostnames,
    )


def _opened(port: Port) -> PortChange:
    return PortChange(
        number=port.number,
        protocol=port.protocol,
        change_type=PortChangeType.STATE,
        old_value=None,
        new_value=PortState.OPEN.value,
    )
