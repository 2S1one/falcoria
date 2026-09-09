"""Pure primitives shared by the import modes.

Port diff, service-field change classification, and the REPLACE close-rule
evaluation. Stored ports arrive as ``Port`` (the caller converts rows first);
nothing here touches a session or the ORM.
"""

from typing import NamedTuple

from falcoria_contracts.enums import PortChangeType, PortState
from falcoria_contracts.port import Port
from falcoria_scanledger.ips.schemas import PortChange

# Carried straight from an incoming port onto a stored one during a refresh; the
# key and the open-only invariant are never overwritten.
_REFRESH_EXCLUDE = {"number", "protocol", "state"}
_EMPTY: tuple[object, ...] = (None, "", [], {})


def is_open(port: Port) -> bool:
    """Whether a port counts as open for scope purposes (TCP: state 'open' only)."""
    return port.state == PortState.OPEN


def in_any_range(number: int, ranges: list[tuple[int, int]]) -> bool:
    """Whether a port number falls inside any scanned range."""
    return any(lo <= number <= hi for lo, hi in ranges)


class PortDiff(NamedTuple):
    """Partition of an incoming port set against the stored open-port set."""

    new_open: list[Port]  # open in the report, not stored
    matched: list[tuple[Port, Port]]  # (stored, incoming) — same key, incoming open
    stale: list[tuple[Port, Port | None]]  # (stored, incoming-or-None) — not open in the report


def diff_ports(stored: list[Port], incoming: list[Port]) -> PortDiff:
    """Split incoming ports into new-open / matched / stale against stored."""
    inc = {(p.number, p.protocol): p for p in incoming}
    sto = {(p.number, p.protocol): p for p in stored}
    new_open = [p for k, p in inc.items() if is_open(p) and k not in sto]
    matched = [(sto[k], p) for k, p in inc.items() if is_open(p) and k in sto]
    stale: list[tuple[Port, Port | None]] = []
    for k, s in sto.items():
        i = inc.get(k)
        if i is None or not is_open(i):
            stale.append((s, i))
    return PortDiff(new_open, matched, stale)


def refresh_port(stored: Port, incoming: Port) -> tuple[Port, list[PortChange]]:
    """Apply non-empty incoming service fields to a stored port.

    Returns the updated port and one PortChange per changed field among
    service / product / version. A blank incoming value never clears a stored
    one.
    """
    changes = [
        PortChange(
            number=stored.number,
            protocol=stored.protocol,
            change_type=ct,
            old_value=getattr(stored, field),
            new_value=getattr(incoming, field),
        )
        for ct, field in (
            (PortChangeType.SERVICE, "service"),
            (PortChangeType.PRODUCT, "product"),
            (PortChangeType.VERSION, "version"),
        )
        if getattr(incoming, field) and getattr(incoming, field) != getattr(stored, field)
    ]
    # Keys come from Port's own model_dump, so they are real field names — the
    # typo risk of a literal-keyed update dict does not apply here.
    updates = {
        f: v for f, v in incoming.model_dump(exclude=_REFRESH_EXCLUDE).items() if v not in _EMPTY
    }
    return stored.model_copy(update=updates), changes


def close_stale_port(
    stored: Port, incoming: Port | None, scanned_ports: list[tuple[int, int]]
) -> PortChange | None:
    """Decide whether a stale stored port closes under REPLACE.

    Closes when the report names it as not-open (recording that raw state and
    reason), or when it is absent but inside a scanned range (no raw detail).
    An absent port outside every scanned range — or any port when no range is
    known — stays open.
    """
    if incoming is not None and not is_open(incoming):
        return _closed(stored, observed_state=incoming.state.value, reason=incoming.reason)
    if incoming is None and in_any_range(stored.number, scanned_ports):
        return _closed(stored, observed_state=None, reason=None)
    return None


def _closed(stored: Port, *, observed_state: str | None, reason: str | None) -> PortChange:
    return PortChange(
        number=stored.number,
        protocol=stored.protocol,
        change_type=PortChangeType.STATE,
        old_value=PortState.OPEN.value,
        new_value=PortState.CLOSED.value,
        observed_state=observed_state,
        reason=reason,
    )
