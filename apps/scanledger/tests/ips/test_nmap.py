"""Parser coverage for ips/nmap.py against real and generated nmap XML."""

from pathlib import Path
from xml.etree.ElementTree import ParseError

import pytest
from defusedxml.ElementTree import fromstring
from pydantic import ValidationError

from falcoria_contracts.enums import PortProtocol, PortState, ServiceMethod
from falcoria_scanledger.ips.nmap import NmapPort, parse_report
from falcoria_scanledger.ips.schemas import IPIn, merge_port_ranges

_FIXTURES = Path(__file__).parent.parent / "fixtures" / "nmap"


def _load(name: str) -> str:
    return (_FIXTURES / name).read_text(encoding="utf-8")


def _by_ip(name: str) -> dict[str, IPIn]:
    return {ip.ip: ip for ip in parse_report(_load(name))}


def test_singleton_scaninfo_becomes_singleton_ranges() -> None:
    hosts = _by_ip("A_B_http_only.xml")
    assert set(hosts) == {"64.227.71.252", "164.90.197.207"}

    first = hosts["64.227.71.252"]
    assert first.scanned_ports == [(80, 80), (443, 443), (8080, 8080), (8443, 8443)]
    assert first.status == "up"
    assert isinstance(first.endtime, int)
    assert first.hostnames == []
    assert [(p.number, p.state) for p in first.ports] == [(8080, PortState.OPEN)]


def test_full_range_scaninfo_and_no_extraports_expansion() -> None:
    host = _by_ip("full_tcp.xml")["64.227.71.252"]
    assert host.scanned_ports == [(1, 65535)]

    # Seven <port> elements; the 65k filtered/closed ports live only in
    # <extraports> and must not be materialised.
    assert len(host.ports) == 7
    assert {p.state for p in host.ports} == {PortState.OPEN}
    assert sorted(p.number for p in host.ports) == [22, 2222, 5432, 6379, 8080, 50500, 50999]

    no_service = next(p for p in host.ports if p.number == 50500)
    assert no_service.service is None
    assert no_service.product is None


def test_service_version_fields_and_hostname_dedupe() -> None:
    host = _by_ip("scanme.xml")["45.33.32.156"]
    # scanme.nmap.org appears twice (type "user" and "PTR").
    assert host.hostnames == ["scanme.nmap.org"]

    port = host.ports[0]
    assert port.number == 80
    assert port.service == "http"
    assert port.product == "Apache httpd"
    assert port.version == "2.4.7"
    assert port.extrainfo == "(Ubuntu)"
    assert port.service_method is ServiceMethod.PROBED
    assert port.service_confidence == 10
    assert port.cpe == ["cpe:/a:apache:http_server:2.4.7"]


def test_not_open_port_elements_are_kept() -> None:
    host = _by_ip("service_version.xml")["127.0.0.1"]
    states = {p.number: p.state for p in host.ports}
    assert states == {22: PortState.OPEN, 23: PortState.CLOSED}

    ssh = next(p for p in host.ports if p.number == 22)
    assert ssh.product == "OpenSSH"
    assert ssh.protocol is PortProtocol.TCP
    assert ssh.reason == "syn-ack"


def test_filtered_ports_are_kept() -> None:
    host = _by_ip("filtered_host.xml")["192.0.2.1"]
    assert {p.state for p in host.ports} == {PortState.FILTERED}
    assert {p.reason for p in host.ports} == {"no-response"}


def test_ping_sweep_has_no_scanned_ports_and_falls_back_to_finished_time() -> None:
    host = _by_ip("ping_sweep.xml")["127.0.0.1"]
    assert host.scanned_ports == []
    assert host.ports == []
    assert host.status == "up"
    assert host.endtime == 1788972617  # runstats/finished @time, host has no endtime


def test_down_host_is_emitted_with_empty_ports() -> None:
    host = _by_ip("down_host.xml")["198.51.100.7"]
    assert host.status == "down"
    assert host.ports == []
    assert host.hostnames == []
    assert host.scanned_ports == [(80, 80)]
    assert isinstance(host.endtime, int)


def test_malformed_xml_raises_parse_error() -> None:
    with pytest.raises(ParseError):
        parse_report("<nmaprun><host>")


def test_merge_port_ranges_sorts_and_coalesces() -> None:
    assert merge_port_ranges([(80, 80), (22, 25), (23, 30), (100, 100)]) == [
        (22, 30),
        (80, 80),
        (100, 100),
    ]
    # Touching ranges fuse (hi + 1 == next lo).
    assert merge_port_ranges([(1, 10), (11, 20)]) == [(1, 20)]
    assert merge_port_ranges([(50, 40)]) == [(40, 50)]
    assert merge_port_ranges([]) == []


def test_merge_port_ranges_rejects_out_of_bounds() -> None:
    with pytest.raises(ValueError, match="out of bounds"):
        merge_port_ranges([(0, 70000)])


def test_ipin_validator_normalises_scanned_ports() -> None:
    ip = IPIn(ip="1.2.3.4", endtime=0, scanned_ports=[(11, 20), (1, 10)])
    assert ip.scanned_ports == [(1, 20)]


def test_nmap_port_from_element_coerces_and_validates() -> None:
    port = NmapPort.from_element(
        fromstring(
            '<port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/></port>'
        )
    )
    assert port.number == 443
    assert port.protocol is PortProtocol.TCP
    assert port.state is PortState.OPEN

    with pytest.raises(ValidationError):
        NmapPort.from_element(
            fromstring('<port portid="not-a-number"><state state="open"/></port>')
        )
