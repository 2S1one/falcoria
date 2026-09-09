"""Coverage for ips/dedup.py — the pure batch-collapse pass."""

from falcoria_contracts.enums import PortProtocol, PortState
from falcoria_contracts.port import Port
from falcoria_scanledger.ips.dedup import dedup_batch
from falcoria_scanledger.ips.schemas import IPIn


def _port(
    number: int,
    *,
    state: PortState = PortState.OPEN,
    service: str | None = None,
    protocol: PortProtocol = PortProtocol.TCP,
) -> Port:
    return Port(number=number, protocol=protocol, state=state, service=service)


def _ip(
    ip: str,
    *,
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


def test_dedups_ports_and_hostnames_within_one_entry() -> None:
    entry = _ip(
        "1.1.1.1",
        ports=[_port(80, service="http-old"), _port(80, service="http-new"), _port(22)],
        hostnames=["a", "b", "a"],
    )
    [out] = dedup_batch([entry])
    assert [(p.number, p.service) for p in out.ports] == [(80, "http-new"), (22, None)]
    assert out.hostnames == ["a", "b"]


def test_same_ip_unions_ports_and_hostnames() -> None:
    a = _ip("2.2.2.2", ports=[_port(80, service="http")], hostnames=["x"], endtime=100)
    b = _ip("2.2.2.2", ports=[_port(443, service="https")], hostnames=["y", "x"], endtime=200)
    [out] = dedup_batch([a, b])
    assert sorted(p.number for p in out.ports) == [80, 443]
    assert out.hostnames == ["x", "y"]
    assert out.endtime == 200


def test_port_collision_across_entries_later_wins() -> None:
    a = _ip("3.3.3.3", ports=[_port(80, state=PortState.OPEN)])
    b = _ip("3.3.3.3", ports=[_port(80, state=PortState.CLOSED)])
    [out] = dedup_batch([a, b])
    assert len(out.ports) == 1
    assert out.ports[0].state is PortState.CLOSED


def test_status_and_os_take_latest_non_empty() -> None:
    a = _ip("4.4.4.4", status="up", os="Linux", endtime=100)
    b = _ip("4.4.4.4", status="down", os=None, endtime=200)
    [out] = dedup_batch([a, b])
    assert out.status == "down"  # incoming non-empty wins
    assert out.os == "Linux"  # incoming None does not clobber


def test_scanned_ports_merged_across_entries() -> None:
    a = _ip("5.5.5.5", scanned_ports=[(80, 80)])
    b = _ip("5.5.5.5", scanned_ports=[(81, 90), (22, 22)])
    [out] = dedup_batch([a, b])
    assert out.scanned_ports == [(22, 22), (80, 90)]


def test_first_seen_ip_order_is_preserved() -> None:
    out = dedup_batch([_ip("9.9.9.9"), _ip("1.1.1.1"), _ip("9.9.9.9"), _ip("5.5.5.5")])
    assert [o.ip for o in out] == ["9.9.9.9", "1.1.1.1", "5.5.5.5"]


def test_inputs_are_not_mutated() -> None:
    a = _ip("6.6.6.6", ports=[_port(80), _port(80)], hostnames=["h", "h"])
    dedup_batch([a, a])
    assert len(a.ports) == 2
    assert a.hostnames == ["h", "h"]
