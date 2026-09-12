"""Pure nmap-XML manipulation: parsing open ports and merging scan passes.

No I/O — every function here takes and returns strings or in-memory XML trees.
"""

from xml.etree.ElementTree import Element, SubElement, tostring

from defusedxml.ElementTree import fromstring

_ServicePortKey = tuple[str | None, str | None, str | None]


def parse_open_ports(xml: str) -> list[int]:
    """Returns the open port numbers reported anywhere in an nmap XML report."""
    root = fromstring(xml)
    ports: list[int] = []
    for port in root.findall(".//port"):
        state = port.find("state")
        if state is None or state.get("state") != "open":
            continue
        portid = port.get("portid")
        if portid is not None and portid.isdigit():
            ports.append(int(portid))
    return ports


def enrich_xml(
    base_xml: str, target_ip: str, hostnames: list[str], service_xml: str | None = None
) -> str:
    """Merges hostnames and an optional service-detection pass into a base scan."""
    base_root = fromstring(base_xml)
    _set_hostnames(base_root, target_ip, hostnames)
    if service_xml is not None:
        _merge_service_data(base_root, fromstring(service_xml))
    return tostring(base_root, encoding="utf-8", xml_declaration=True).decode("utf-8")


def _set_hostnames(root: Element, target_ip: str, hostnames: list[str]) -> None:
    """Replaces `target_ip`'s `<hostnames>` block with `hostnames`, in place."""
    for host in root.findall("host"):
        addr = host.find("address")
        if addr is None or addr.get("addr") != target_ip:
            continue
        hostnames_elem = host.find("hostnames")
        if hostnames_elem is None:
            hostnames_elem = SubElement(host, "hostnames")
        else:
            hostnames_elem.clear()
        for name in hostnames:
            SubElement(hostnames_elem, "hostname", attrib={"name": name, "type": "user"})


def _index_ports_by_key(root: Element) -> dict[_ServicePortKey, Element]:
    """Maps each `<port>` under `root` to its (ip, portid, protocol) key."""
    ports: dict[_ServicePortKey, Element] = {}
    for host in root.findall("host"):
        addr = host.find("address")
        if addr is None:
            continue
        ip = addr.get("addr")
        for port in host.findall(".//port"):
            ports[(ip, port.get("portid"), port.get("protocol"))] = port
    return ports


def _merge_service_data(base_root: Element, service_root: Element) -> None:
    """Overlays each base port's `<service>`/`<script>` from the matching service-scan port."""
    service_ports = _index_ports_by_key(service_root)
    for key, port in _index_ports_by_key(base_root).items():
        service_port = service_ports.get(key)
        if service_port is None:
            continue
        for tag in ("service", "script"):
            existing = port.find(tag)
            if existing is not None:
                port.remove(existing)
            replacement = service_port.find(tag)
            if replacement is not None:
                port.append(replacement)
