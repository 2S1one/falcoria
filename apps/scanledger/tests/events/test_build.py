import uuid

from falcoria_contracts.enums import ImportMode, PortProtocol
from falcoria_contracts.port import Port
from falcoria_scanledger.events.build import build_event
from falcoria_scanledger.events.schemas import IPChangedEvent, PortRef
from falcoria_scanledger.ips.modes import apply_mode
from falcoria_scanledger.ips.schemas import IPIn, StoredIP

_PROJECT = uuid.uuid4()
_IP = "192.0.2.10"
_END = 1769005856


def _in(ports: list[Port], hostnames: list[str] | None = None, **kw: object) -> IPIn:
    return IPIn.model_validate(
        {
            "ip": _IP,
            "endtime": _END,
            "ports": ports,
            "hostnames": hostnames or [],
            "scanned_ports": [(1, 65535)],
            **kw,
        }
    )


def _stored(ports: list[Port], hostnames: list[str] | None = None, **kw: object) -> StoredIP:
    return StoredIP.model_validate(
        {"ip": _IP, "open_ports": ports, "hostnames": hostnames or [], **kw}
    )


def _event(
    stored: StoredIP | None, incoming: IPIn, mode: ImportMode = ImportMode.REPLACE
) -> IPChangedEvent | None:
    change = apply_mode(mode, stored, incoming)
    return build_event(uuid.uuid4(), _PROJECT, None, stored, change)


def _ref(number: int) -> PortRef:
    return PortRef(number=number, protocol=PortProtocol.TCP)


def test_new_ip_reports_everything_as_added() -> None:
    event = _event(None, _in([Port(number=443), Port(number=80)], ["b.example", "a.example"]))
    assert event is not None
    assert event.ports.old == []
    assert event.ports.added == [_ref(80), _ref(443)]
    assert event.hostnames.added == ["a.example", "b.example"]
    assert event.observed_at == _END


def test_new_ip_without_ports_or_hostnames_yields_no_event() -> None:
    assert _event(None, _in([])) is None


def test_port_opened() -> None:
    event = _event(_stored([Port(number=80)]), _in([Port(number=80), Port(number=443)]))
    assert event is not None
    assert event.ports.old == [_ref(80)]
    assert event.ports.added == [_ref(443)]
    assert event.ports.removed == []


def test_port_closed_under_replace() -> None:
    event = _event(_stored([Port(number=80), Port(number=443)]), _in([Port(number=80)]))
    assert event is not None
    assert event.ports.removed == [_ref(443)]
    assert [p.number for p in event.ports.current] == [80]


def test_hostname_only_change() -> None:
    event = _event(_stored([Port(number=80)], ["a.example"]), _in([Port(number=80)], ["c.example"]))
    assert event is not None
    assert event.hostnames.added == ["c.example"]
    assert event.hostnames.current == ["a.example", "c.example"]
    assert event.ports.added == []
    assert event.ports.removed == []


def test_service_change_on_kept_port() -> None:
    stored = _stored([Port(number=80, product="nginx", version="1.0")])
    event = _event(stored, _in([Port(number=80, product="nginx", version="2.0")]))
    assert event is not None
    assert event.ports.added == []
    assert [(c.field, c.old, c.new) for c in event.service_changes] == [("version", "1.0", "2.0")]


def test_os_only_change_yields_no_event() -> None:
    stored = _stored([Port(number=80)], os="Linux")
    assert _event(stored, _in([Port(number=80)], os="FreeBSD")) is None


def test_tunnel_only_change_yields_no_event() -> None:
    stored = _stored([Port(number=443, service="http")])
    assert _event(stored, _in([Port(number=443, service="http", tunnel="ssl")])) is None


def test_unchanged_rescan_yields_no_event() -> None:
    stored = _stored([Port(number=80)], ["a.example"])
    assert _event(stored, _in([Port(number=80)], ["a.example"])) is None


def test_current_ports_carry_details_but_not_raw_fingerprints() -> None:
    port = Port(number=443, service="http", tunnel="ssl", cpe=["cpe:/a:x"], servicefp="SF:...")
    event = _event(None, _in([port]))
    assert event is not None
    (detail,) = event.ports.current
    assert detail.tunnel == "ssl"
    assert detail.cpe == ["cpe:/a:x"]
    assert "servicefp" not in event.model_dump()["ports"]["current"][0]


def test_port_added_matches_history_state_rows_in_every_mode() -> None:
    stored = _stored([Port(number=80), Port(number=22)])
    incoming = _in([Port(number=80), Port(number=443)])
    for mode in ImportMode:
        change = apply_mode(mode, stored, incoming)
        event = build_event(uuid.uuid4(), _PROJECT, None, stored, change)
        opened = sorted(pc.number for pc in change.port_changes if pc.new_value == "open")
        closed = sorted(pc.number for pc in change.port_changes if pc.new_value == "closed")
        added = [r.number for r in event.ports.added] if event else []
        removed = [r.number for r in event.ports.removed] if event else []
        assert (added, removed) == (opened, closed), mode
