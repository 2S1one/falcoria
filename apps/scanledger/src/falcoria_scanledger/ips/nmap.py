"""Parse and model nmap XML for the IP import/export pipeline.

The ``Nmap*`` models are the one declaration of the report structure scanledger
reads: only fields used today are present, and capturing more means adding a
field to the relevant model. ``parse_report`` is the entry point; a host is
projected onto the scanner-neutral ``IPIn`` by ``NmapHost.to_ipin``.
"""

import json
import time
from ipaddress import ip_address
from typing import Self
from xml.etree.ElementTree import Element, SubElement, indent, tostring

from defusedxml.ElementTree import fromstring
from pydantic import BaseModel, ConfigDict, Field, field_validator

from falcoria_contracts.enums import PortProtocol, PortState, ServiceMethod
from falcoria_contracts.port import Port
from falcoria_scanledger.ips.schemas import IPIn, IPOut, merge_port_ranges

_ADDR_TYPES = {"ipv4", "ipv6"}


class _NmapModel(BaseModel):
    # extra="forbid": a mistyped key in a from_element() dict raises instead of
    # silently falling back to the field default.
    model_config = ConfigDict(extra="forbid")


class NmapService(_NmapModel):
    """An nmap ``<service>`` element; field names mirror nmap's attributes."""

    name: str | None = None
    product: str | None = None
    version: str | None = None
    extrainfo: str | None = None
    servicefp: str | None = None
    method: ServiceMethod | None = None
    conf: int | None = Field(default=None, ge=0, le=10)
    tunnel: str | None = None
    cpe: list[str] = Field(default_factory=list)
    scripts: dict[str, str] = Field(default_factory=dict)

    @classmethod
    def from_element(cls, el: Element | None) -> "NmapService | None":
        """Build from a ``<service>`` child, or return None when it is absent."""
        if el is None:
            return None
        return cls.model_validate(
            {
                "name": el.get("name"),
                "product": el.get("product"),
                "version": el.get("version"),
                "extrainfo": el.get("extrainfo"),
                "servicefp": el.get("servicefp"),
                "method": el.get("method"),
                "conf": el.get("conf"),
                "tunnel": el.get("tunnel"),
                "cpe": [c.text for c in el.findall("cpe") if c.text],
                "scripts": {s.get("id", ""): s.get("output", "") for s in el.findall("script")},
            }
        )


class NmapPort(_NmapModel):
    """An nmap ``<port>`` element together with its ``<state>``."""

    number: int = Field(ge=0, le=65535)
    protocol: PortProtocol = PortProtocol.TCP
    state: PortState = PortState.OPEN
    reason: str | None = None
    service: NmapService | None = None

    @classmethod
    def from_element(cls, el: Element) -> Self:
        """Build from a ``<port>`` element."""
        state = el.find("state")
        return cls.model_validate(
            {
                "number": el.get("portid"),
                "protocol": el.get("protocol", "tcp"),
                "state": (state.get("state") if state is not None else None) or PortState.OPEN,
                "reason": state.get("reason") if state is not None else None,
                "service": NmapService.from_element(el.find("service")),
            }
        )


class NmapHost(_NmapModel):
    """The parts of an nmap ``<host>`` that carry inventory data."""

    ip: str
    status: str | None = None
    os: str | None = None
    endtime: int | None = None
    hostnames: list[str] = Field(default_factory=list)
    ports: list[NmapPort] = Field(default_factory=list)

    @field_validator("ip")
    @classmethod
    def _normalise_ip(cls, v: str) -> str:
        return str(ip_address(v))

    @classmethod
    def from_element(cls, el: Element) -> Self:
        """Build from a ``<host>`` element (up, down, or discovery-only)."""
        status = el.find("status")
        return cls.model_validate(
            {
                "ip": _host_address(el),
                "status": status.get("state") if status is not None else None,
                "os": _best_osmatch(el),
                "endtime": el.get("endtime"),
                "hostnames": _hostnames(el),
                "ports": [NmapPort.from_element(p) for p in el.findall("ports/port")],
            }
        )

    def to_ipin(self, scanned_ports: list[tuple[int, int]], fallback_endtime: int | None) -> IPIn:
        """Project the host onto the scanner-neutral ``IPIn``.

        ``endtime`` falls back to the report's finish time for a host that
        carries none (down or discovery-only). Raises ``ValueError`` when
        neither is available.
        """
        endtime = self.endtime if self.endtime is not None else fallback_endtime
        if endtime is None:
            raise ValueError(f"no end time for host {self.ip}")
        return IPIn(
            **self.model_dump(exclude={"ports", "endtime"}),
            endtime=endtime,
            ports=[_to_port(p) for p in self.ports],
            scanned_ports=scanned_ports,
        )


class NmapReport(_NmapModel):
    """A parsed nmap run: coverage ranges, finish time, and hosts."""

    scanned_ports: list[tuple[int, int]] = Field(default_factory=list)
    finished_time: int | None = None
    hosts: list[NmapHost] = Field(default_factory=list)

    @classmethod
    def from_element(cls, root: Element) -> Self:
        """Build from the ``<nmaprun>`` root element."""
        return cls.model_validate(
            {
                "scanned_ports": _scanned_ports(root),
                "finished_time": _finished_time(root),
                "hosts": [NmapHost.from_element(h) for h in root.findall("host")],
            }
        )


def parse_report(xml: str | bytes) -> list[IPIn]:
    """Return one ``IPIn`` per ``<host>`` in an nmap XML report.

    Down and discovery-only hosts are included with an empty ``ports`` list.
    ``scanned_ports`` comes from the report's port-scan ``<scaninfo>`` and is
    shared by every host. Propagates ``defusedxml`` parse errors on malformed or
    unsafe XML, and ``ValueError`` / ``ValidationError`` on a host with no
    address or an unparseable field.
    """
    report = NmapReport.from_element(fromstring(xml))
    return [h.to_ipin(report.scanned_ports, report.finished_time) for h in report.hosts]


def _host_address(host: Element) -> str:
    for addr in host.findall("address"):
        if addr.get("addrtype") in _ADDR_TYPES:
            return addr.get("addr", "")
    raise ValueError("host element has no ipv4/ipv6 address")


def _hostnames(host: Element) -> list[str]:
    # dict preserves first-seen order while de-duplicating (a name can repeat as
    # both type="user" and type="PTR").
    seen: dict[str, None] = {}
    for hn in host.findall("hostnames/hostname"):
        name = hn.get("name")
        if name:
            seen.setdefault(name, None)
    return list(seen)


def _best_osmatch(host: Element) -> str | None:
    matches = host.findall("os/osmatch")
    if not matches:
        return None
    return max(matches, key=lambda m: int(m.get("accuracy", "0"))).get("name")


def _scanned_ports(root: Element) -> list[tuple[int, int]]:
    # Exclude only type="ping": a discovery-only run (-sn) emits no <scaninfo>
    # at all, and nmap may add port-scan types beyond an allowlist later.
    pairs: list[tuple[int, int]] = []
    found = False
    for si in root.findall("scaninfo"):
        services = si.get("services")
        if si.get("type") == "ping" or services is None:
            continue
        found = True
        pairs.extend(_parse_ranges(services))
    return merge_port_ranges(pairs) if found else []


def _parse_ranges(spec: str) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    for part in filter(None, (p.strip() for p in spec.split(","))):
        lo_s, _, hi_s = part.partition("-")
        lo = int(lo_s)
        out.append((lo, int(hi_s) if hi_s else lo))
    return out


def _finished_time(root: Element) -> int | None:
    el = root.find("runstats/finished")
    t = el.get("time") if el is not None else None
    return int(t) if t is not None else None


def _to_port(port: NmapPort) -> Port:
    """Flatten an ``NmapPort`` onto the neutral contract ``Port``."""
    svc = port.service
    return Port.model_validate(
        {
            **port.model_dump(exclude={"service"}),
            **(svc.model_dump(exclude={"name", "method", "conf"}) if svc else {}),
            "service": svc.name if svc else None,
            "service_method": svc.method if svc else None,
            "service_confidence": svc.conf if svc else None,
        }
    )


_EXPORT_NMAP_VERSION = "7.94"
_EXPORT_XMLOUTPUTVERSION = "1.05"
_EXPORT_ARGS = "scanledger export"


def export_report(ips: list[IPOut], *, started: int | None = None) -> str:
    """Renders stored IPs as an nmap-format XML report string.

    Round-trips through ``parse_report`` except ``first_seen``, which has no
    place in the format and collapses to ``last_seen`` on re-import. Empty
    ``ips`` still yields a well-formed empty report. ``started`` (unix seconds,
    default now) sets the run timestamps and the initiation comment.
    """
    now = int(time.time()) if started is None else started
    root = Element(
        "nmaprun",
        {
            "scanner": "nmap",
            "args": _EXPORT_ARGS,
            "start": str(now),
            "version": _EXPORT_NMAP_VERSION,
            "xmloutputversion": _EXPORT_XMLOUTPUTVERSION,
        },
    )
    SubElement(root, "verbose", {"level": "0"})
    SubElement(root, "debugging", {"level": "0"})
    for ip in ips:
        _append_host(root, ip)
    SubElement(SubElement(root, "runstats"), "finished", {"time": str(now)})

    indent(root)
    body = tostring(root, encoding="unicode")
    when = time.strftime("%a %b %d %H:%M:%S %Y", time.gmtime(now))
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        "<!DOCTYPE nmaprun>\n"
        '<?xml-stylesheet href="file:///usr/bin/../share/nmap/nmap.xsl" type="text/xsl"?>\n'
        f"<!-- Nmap {_EXPORT_NMAP_VERSION} scan initiated {when} as: {_EXPORT_ARGS} -->\n"
        f"{body}\n"
    )


def _append_host(root: Element, ip: IPOut) -> None:
    host = SubElement(root, "host", {"endtime": str(ip.last_seen)})
    SubElement(host, "status", {"state": ip.status or "up"})
    SubElement(host, "address", {"addr": ip.ip, "addrtype": "ipv6" if ":" in ip.ip else "ipv4"})
    if ip.hostnames:
        names = SubElement(host, "hostnames")
        for name in ip.hostnames:
            SubElement(names, "hostname", {"name": name, "type": "user"})
    if ip.os:
        SubElement(SubElement(host, "os"), "osmatch", {"name": ip.os})
    if ip.ports:
        ports = SubElement(host, "ports")
        for port in ip.ports:
            _append_port(ports, port)


def _append_port(ports: Element, port: Port) -> None:
    port_el = SubElement(
        ports, "port", {"protocol": port.protocol.value, "portid": str(port.number)}
    )
    state_attrs = {"state": port.state.value}
    if port.reason is not None:
        state_attrs["reason"] = port.reason
    SubElement(port_el, "state", state_attrs)
    _append_service(port_el, port)


def _append_service(port_el: Element, port: Port) -> None:
    attrs = {
        "name": port.service,
        "product": port.product,
        "version": port.version,
        "extrainfo": port.extrainfo,
        "tunnel": port.tunnel,
        "servicefp": port.servicefp,
        "method": port.service_method.value if port.service_method else None,
        "conf": str(port.service_confidence) if port.service_confidence is not None else None,
    }
    set_attrs = {k: v for k, v in attrs.items() if v is not None}
    if not set_attrs and not port.cpe and not port.scripts:
        return
    service = SubElement(port_el, "service", set_attrs)
    for cpe in port.cpe:
        SubElement(service, "cpe").text = cpe
    for script_id, output in port.scripts.items():
        SubElement(service, "script", {"id": script_id, "output": _script_text(output)})


def _script_text(output: object) -> str:
    if isinstance(output, str):
        return output
    return json.dumps(output, default=str, sort_keys=True)
