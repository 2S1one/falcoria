"""Collapse repeated IP entries within a single import batch."""

from collections.abc import Iterable

from falcoria_contracts.enums import PortProtocol
from falcoria_contracts.port import Port
from falcoria_scanledger.ips.schemas import IPIn, merge_port_ranges


def dedup_batch(entries: Iterable[IPIn]) -> list[IPIn]:
    """Return one IPIn per address, folding repeats in first-seen order.

    Within and across repeats, ports are de-duplicated by ``(number,
    protocol)`` with the later entry winning; hostnames are unioned keeping
    first-seen order; ``scanned_ports`` are merged; ``endtime`` takes the max;
    ``status`` and ``os`` take the latest non-empty value. Inputs are not
    mutated.
    """
    merged: dict[str, IPIn] = {}
    for incoming in entries:
        current = merged.get(incoming.ip)
        merged[incoming.ip] = _fold(current, incoming) if current else _dedup_one(incoming)
    return list(merged.values())


def _dedup_one(entry: IPIn) -> IPIn:
    # Attribute assignment on a copy, not model_copy(update={...}): the field
    # names are then checked by the type checker. Untouched fields pass through.
    out = entry.model_copy()
    out.ports = _dedup_ports(entry.ports)
    out.hostnames = _unique(entry.hostnames)
    return out


def _fold(current: IPIn, incoming: IPIn) -> IPIn:
    out = current.model_copy()
    out.ports = _dedup_ports([*current.ports, *incoming.ports])
    out.hostnames = _unique([*current.hostnames, *incoming.hostnames])
    out.scanned_ports = merge_port_ranges([*current.scanned_ports, *incoming.scanned_ports])
    out.endtime = max(current.endtime, incoming.endtime)
    out.status = incoming.status or current.status
    out.os = incoming.os or current.os
    return out


def _dedup_ports(ports: list[Port]) -> list[Port]:
    by_key: dict[tuple[int, PortProtocol], Port] = {}
    for port in ports:
        by_key[(port.number, port.protocol)] = port  # later wins
    return list(by_key.values())


def _unique(items: list[str]) -> list[str]:
    seen: dict[str, None] = {}
    for item in items:
        seen.setdefault(item, None)
    return list(seen)
