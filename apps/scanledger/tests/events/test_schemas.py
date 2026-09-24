import uuid

import pytest
from pydantic import ValidationError

from falcoria_contracts.enums import PortProtocol, ServiceMethod
from falcoria_contracts.port import Port
from falcoria_scanledger.events.schemas import (
    HostnameDelta,
    IPChangedEvent,
    PortDelta,
    PortDetail,
    PortRef,
)


def _port(number: int) -> PortRef:
    return PortRef(number=number, protocol=PortProtocol.TCP)


def _detail(number: int, **fields: object) -> PortDetail:
    return PortDetail.model_validate({"number": number, "protocol": "tcp", **fields})


def test_hostname_delta_accepts_consistent_sets() -> None:
    delta = HostnameDelta(old=["a", "b"], current=["a", "c"], added=["c"], removed=["b"])
    assert delta.current == ["a", "c"]


def test_port_delta_accepts_consistent_sets() -> None:
    delta = PortDelta(
        old=[_port(80)], current=[_detail(80), _detail(443)], added=[_port(443)], removed=[]
    )
    assert delta.added == [_port(443)]


def test_all_empty_delta_is_valid() -> None:
    assert HostnameDelta(old=[], current=[], added=[], removed=[]).current == []


@pytest.mark.parametrize(
    ("old", "current", "added", "removed"),
    [
        (["a"], ["a", "b"], [], []),  # current has an item nobody added
        (["a"], ["a"], ["a"], []),  # added item was already in old
        (["a"], ["a"], [], ["b"]),  # removed item was never in old
        (["a"], ["a"], [], ["a"]),  # removed item still in current
        (["a", "a"], ["a", "a"], [], []),  # duplicates
    ],
)
def test_hostname_delta_rejects_inconsistent_sets(
    old: list[str], current: list[str], added: list[str], removed: list[str]
) -> None:
    with pytest.raises(ValidationError):
        HostnameDelta(old=old, current=current, added=added, removed=removed)


def test_port_identity_includes_protocol() -> None:
    udp = PortRef(number=53, protocol=PortProtocol.UDP)
    tcp = PortRef(number=53, protocol=PortProtocol.TCP)
    current = [_detail(53), _detail(53, protocol="udp")]
    delta = PortDelta(old=[tcp], current=current, added=[udp], removed=[])
    assert len(delta.current) == 2


def test_port_ref_rejects_out_of_range_number() -> None:
    with pytest.raises(ValidationError):
        PortRef(number=65536, protocol=PortProtocol.TCP)


def test_event_round_trips_through_json() -> None:
    event = IPChangedEvent(
        event_id=uuid.uuid4(),
        project_id=uuid.uuid4(),
        ip="192.0.2.10",
        scan_id=None,
        observed_at=1769005856,
        hostnames=HostnameDelta(
            old=[], current=["a.example.com"], added=["a.example.com"], removed=[]
        ),
        ports=PortDelta(
            old=[],
            current=[_detail(443, cpe=["cpe:/a:nginx:nginx"])],
            added=[_port(443)],
            removed=[],
        ),
    )
    assert IPChangedEvent.model_validate(event.model_dump(mode="json")) == event


def test_port_detail_fields_exist_on_port() -> None:
    # A rename in Port would otherwise silently null the field in every event.
    assert set(PortDetail.model_fields) <= set(Port.model_fields)


def test_port_detail_built_from_port_keeps_only_its_fields() -> None:
    port = Port(
        number=443,
        service="http",
        service_method=ServiceMethod.PROBED,
        tunnel="ssl",
        servicefp="SF-Port443...",
        scripts={"http-title": "x"},
    )
    detail = PortDetail.model_validate(port.model_dump())
    assert detail.tunnel == "ssl"
    assert detail.service_method == ServiceMethod.PROBED
    assert "servicefp" not in detail.model_dump()


def test_service_change_on_kept_port_is_not_a_removal() -> None:
    delta = PortDelta(old=[_port(443)], current=[_detail(443, version="2.0")], added=[], removed=[])
    assert delta.removed == []


def test_port_delta_rejects_current_detail_nobody_added() -> None:
    with pytest.raises(ValidationError):
        PortDelta(old=[], current=[_detail(443)], added=[], removed=[])
