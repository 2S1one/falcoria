"""Coverage for ips/reconcile.py — the pure reconciliation primitives."""

from falcoria_contracts.enums import PortChangeType, PortProtocol, PortState
from falcoria_contracts.port import Port
from falcoria_scanledger.ips.reconcile import (
    close_stale_port,
    diff_ports,
    in_any_range,
    is_open,
    refresh_port,
)


def _p(
    number: int,
    *,
    state: PortState = PortState.OPEN,
    service: str | None = None,
    product: str | None = None,
    version: str | None = None,
    reason: str | None = None,
    protocol: PortProtocol = PortProtocol.TCP,
) -> Port:
    return Port(
        number=number,
        protocol=protocol,
        state=state,
        service=service,
        product=product,
        version=version,
        reason=reason,
    )


def test_is_open_only_true_for_state_open() -> None:
    assert is_open(_p(80))
    assert not is_open(_p(80, state=PortState.OPEN_FILTERED))
    assert not is_open(_p(80, state=PortState.CLOSED))
    assert not is_open(_p(80, state=PortState.FILTERED))


def test_in_any_range() -> None:
    ranges = [(80, 80), (100, 200)]
    assert in_any_range(80, ranges)
    assert in_any_range(150, ranges)
    assert in_any_range(200, ranges)
    assert not in_any_range(81, ranges)
    assert not in_any_range(50, [])


def test_diff_ports_partitions() -> None:
    stored = [_p(22, service="ssh"), _p(80, service="http"), _p(443)]
    incoming = [
        _p(80, service="http"),  # matched
        _p(443, state=PortState.CLOSED),  # stale — present but not open
        _p(8080),  # new open
        _p(9999, state=PortState.FILTERED),  # dropped — not open, not stored
    ]
    diff = diff_ports(stored, incoming)

    assert [p.number for p in diff.new_open] == [8080]
    assert [(s.number, i.number) for s, i in diff.matched] == [(80, 80)]

    stale = {s.number: i for s, i in diff.stale}
    assert set(stale) == {22, 443}
    assert stale[22] is None  # stored, absent from the report
    stale_443 = stale[443]
    assert stale_443 is not None
    assert stale_443.state is PortState.CLOSED


def test_refresh_port_change_per_field_and_never_blanks() -> None:
    stored = _p(80, service="http", product="nginx", version="1.18")
    incoming = _p(80, service="http", product="Apache", version="")
    updated, changes = refresh_port(stored, incoming)

    assert updated.product == "Apache"
    assert updated.version == "1.18"  # blank incoming did not clear it
    assert [c.change_type for c in changes] == [PortChangeType.PRODUCT]
    assert (changes[0].old_value, changes[0].new_value) == ("nginx", "Apache")


def test_refresh_port_all_three_fields() -> None:
    stored = _p(80, service="http", product="nginx", version="1.0")
    incoming = _p(80, service="https", product="Apache", version="2.0")
    updated, changes = refresh_port(stored, incoming)

    assert {c.change_type for c in changes} == {
        PortChangeType.SERVICE,
        PortChangeType.PRODUCT,
        PortChangeType.VERSION,
    }
    assert (updated.service, updated.product, updated.version) == ("https", "Apache", "2.0")


def test_refresh_port_keeps_key_and_state() -> None:
    stored = _p(80, state=PortState.OPEN)
    incoming = _p(80, state=PortState.CLOSED, service="http", reason="syn-ack")
    updated, changes = refresh_port(stored, incoming)

    assert updated.state is PortState.OPEN  # state is never overwritten
    assert updated.number == 80
    assert updated.reason == "syn-ack"  # a non-classified field is still refreshed
    assert [c.change_type for c in changes] == [PortChangeType.SERVICE]


def test_close_stale_port_explicit_not_open() -> None:
    change = close_stale_port(_p(443), _p(443, state=PortState.FILTERED, reason="no-response"), [])

    assert change is not None
    assert change.change_type is PortChangeType.STATE
    assert (change.old_value, change.new_value) == ("open", "closed")
    assert change.observed_state == "filtered"
    assert change.reason == "no-response"


def test_close_stale_port_absent_inside_range() -> None:
    change = close_stale_port(_p(80), None, [(1, 1024)])

    assert change is not None
    assert change.new_value == "closed"
    assert change.observed_state is None
    assert change.reason is None


def test_close_stale_port_absent_outside_range_stays_open() -> None:
    assert close_stale_port(_p(9999), None, [(1, 1024)]) is None


def test_close_stale_port_absent_without_ranges_stays_open() -> None:
    assert close_stale_port(_p(80), None, []) is None


def test_close_stale_port_ignores_still_open_incoming() -> None:
    assert close_stale_port(_p(80), _p(80), []) is None
