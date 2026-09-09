"""Coverage for ips/modes.py — the four import-mode policies."""

import pytest

from falcoria_contracts.enums import ImportMode, PortChangeType, PortProtocol, PortState
from falcoria_contracts.port import Port
from falcoria_scanledger.ips.modes import apply_mode
from falcoria_scanledger.ips.schemas import IPIn, StoredIP


def _p(
    number: int,
    *,
    state: PortState = PortState.OPEN,
    service: str | None = None,
    product: str | None = None,
    protocol: PortProtocol = PortProtocol.TCP,
) -> Port:
    return Port(number=number, protocol=protocol, state=state, service=service, product=product)


def _ipin(
    *,
    ip: str = "1.1.1.1",
    ports: list[Port] | None = None,
    hostnames: list[str] | None = None,
    endtime: int = 100,
    status: str | None = "up",
    os: str | None = None,
    scanned_ports: list[tuple[int, int]] | None = None,
) -> IPIn:
    return IPIn(
        ip=ip,
        ports=ports or [],
        hostnames=hostnames or [],
        endtime=endtime,
        status=status,
        os=os,
        scanned_ports=scanned_ports or [],
    )


def _stored(
    *,
    ip: str = "1.1.1.1",
    status: str | None = "up",
    os: str | None = "Linux",
    hostnames: list[str] | None = None,
    open_ports: list[Port] | None = None,
) -> StoredIP:
    return StoredIP(
        ip=ip, status=status, os=os, hostnames=hostnames or [], open_ports=open_ports or []
    )


def _nums(ports: list[Port]) -> set[int]:
    return {p.number for p in ports}


@pytest.mark.parametrize("mode", list(ImportMode))
def test_new_ip_is_identical_for_every_mode(mode: ImportMode) -> None:
    incoming = _ipin(
        ports=[_p(80, service="http"), _p(23, state=PortState.CLOSED)],
        hostnames=["a", "b"],
        os="Linux",
    )
    cs = apply_mode(mode, None, incoming)

    assert cs.created is True
    assert _nums(cs.open_ports) == {80}  # the closed port is dropped
    assert [(c.change_type, c.new_value) for c in cs.port_changes] == [
        (PortChangeType.STATE, "open")
    ]
    assert cs.new_hostnames == ["a", "b"]
    assert cs.hostnames == ["a", "b"]
    assert (cs.status, cs.os) == ("up", "Linux")
    assert cs.endtime == 100


def test_insert_existing_merges_hostnames_only() -> None:
    stored = _stored(open_ports=[_p(22), _p(80, service="http")], hostnames=["a"])
    incoming = _ipin(
        ports=[_p(80, service="https"), _p(443)],
        hostnames=["a", "b"],
        status="down",
        os="Windows",
    )
    cs = apply_mode(ImportMode.INSERT, stored, incoming)

    assert cs.created is False
    assert _nums(cs.open_ports) == {22, 80}  # 443 not added
    assert next(p for p in cs.open_ports if p.number == 80).service == "http"  # not refreshed
    assert cs.port_changes == []
    assert cs.new_hostnames == ["b"]
    assert cs.hostnames == ["a", "b"]
    assert (cs.status, cs.os) == ("up", "Linux")  # metadata untouched


def test_append_adds_new_open_only() -> None:
    stored = _stored(open_ports=[_p(22), _p(80, service="http")])
    incoming = _ipin(
        ports=[_p(80, service="https"), _p(443)],  # 22 absent -> stale
        scanned_ports=[(1, 1024)],
    )
    cs = apply_mode(ImportMode.APPEND, stored, incoming)

    assert _nums(cs.open_ports) == {22, 80, 443}  # 22 not closed, 443 added
    assert next(p for p in cs.open_ports if p.number == 80).service == "http"  # not refreshed
    assert [(c.number, c.change_type) for c in cs.port_changes] == [(443, PortChangeType.STATE)]


def test_update_adds_and_refreshes_but_never_closes() -> None:
    stored = _stored(open_ports=[_p(22), _p(80, service="http", product="nginx")])
    incoming = _ipin(
        ports=[_p(80, service="http", product="Apache"), _p(443)],  # 22 absent
        scanned_ports=[(1, 1024)],
        status="down",
        os="Windows",
    )
    cs = apply_mode(ImportMode.UPDATE, stored, incoming)

    assert _nums(cs.open_ports) == {22, 80, 443}  # 22 stays open (UPDATE never closes)
    assert next(p for p in cs.open_ports if p.number == 80).product == "Apache"
    kinds = {(c.number, c.change_type) for c in cs.port_changes}
    assert kinds == {(443, PortChangeType.STATE), (80, PortChangeType.PRODUCT)}
    assert (cs.status, cs.os) == ("down", "Windows")  # metadata refreshed


def test_replace_closes_stale_ports() -> None:
    stored = _stored(open_ports=[_p(22), _p(80, service="http", product="nginx")])
    incoming = _ipin(
        ports=[_p(80, service="http", product="Apache"), _p(443)],  # 22 absent, in range
        scanned_ports=[(1, 1024)],
        status="down",
    )
    cs = apply_mode(ImportMode.REPLACE, stored, incoming)

    assert _nums(cs.open_ports) == {80, 443}  # 22 closed
    closed = next(c for c in cs.port_changes if c.number == 22)
    assert (closed.change_type, closed.old_value, closed.new_value) == (
        PortChangeType.STATE,
        "open",
        "closed",
    )
    assert {(c.number, c.change_type) for c in cs.port_changes} == {
        (443, PortChangeType.STATE),
        (80, PortChangeType.PRODUCT),
        (22, PortChangeType.STATE),
    }


def test_replace_keeps_absent_port_outside_scanned_range() -> None:
    stored = _stored(open_ports=[_p(22), _p(9999)])
    incoming = _ipin(ports=[], scanned_ports=[(1, 1024)])
    cs = apply_mode(ImportMode.REPLACE, stored, incoming)

    assert _nums(cs.open_ports) == {9999}  # 22 closed, 9999 never scanned
    assert [c.number for c in cs.port_changes] == [22]


def test_update_metadata_guard_keeps_stored_on_blank_incoming() -> None:
    stored = _stored(status="up", os="Linux")
    incoming = _ipin(status=None, os=None)
    cs = apply_mode(ImportMode.UPDATE, stored, incoming)

    assert (cs.status, cs.os) == ("up", "Linux")


def test_insert_existing_no_hostname_change_is_a_noop_changeset() -> None:
    stored = _stored(open_ports=[_p(80)], hostnames=["a"])
    incoming = _ipin(ports=[_p(80), _p(443)], hostnames=["a"])
    cs = apply_mode(ImportMode.INSERT, stored, incoming)

    assert cs.port_changes == []
    assert cs.new_hostnames == []
    assert _nums(cs.open_ports) == {80}
