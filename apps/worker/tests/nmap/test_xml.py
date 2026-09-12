"""Tests for nmap/xml.py — pure open-port parsing and XML merging."""

from falcoria_worker.nmap.xml import enrich_xml, parse_open_ports

_BASE_XML = """<?xml version="1.0"?>
<nmaprun><host>
  <address addr="10.0.0.1" addrtype="ipv4"/>
  <ports>
    <port protocol="tcp" portid="22"><state state="closed"/></port>
    <port protocol="tcp" portid="80"><state state="open"/></port>
    <port protocol="tcp" portid="443"><state state="open"/></port>
  </ports>
</host></nmaprun>
"""

_SERVICE_XML = """<?xml version="1.0"?>
<nmaprun><host>
  <address addr="10.0.0.1" addrtype="ipv4"/>
  <ports>
    <port protocol="tcp" portid="80">
      <state state="open"/>
      <service name="http" product="nginx"/>
    </port>
    <port protocol="tcp" portid="443">
      <state state="open"/>
      <service name="https" product="nginx"/>
      <script id="ssl-cert" output="..."/>
    </port>
  </ports>
</host></nmaprun>
"""


def test_parse_open_ports_returns_only_open_ports() -> None:
    assert parse_open_ports(_BASE_XML) == [80, 443]


def test_parse_open_ports_empty_when_none_open() -> None:
    xml = """<?xml version="1.0"?><nmaprun><host>
        <address addr="10.0.0.1" addrtype="ipv4"/>
        <ports><port protocol="tcp" portid="22"><state state="closed"/></port></ports>
    </host></nmaprun>"""
    assert parse_open_ports(xml) == []


def test_enrich_xml_injects_hostnames() -> None:
    xml = enrich_xml(_BASE_XML, "10.0.0.1", ["example.com", "www.example.com"])
    assert 'name="example.com"' in xml
    assert 'name="www.example.com"' in xml


def test_enrich_xml_ignores_other_hosts() -> None:
    xml = enrich_xml(_BASE_XML, "10.0.0.99", ["example.com"])
    assert "example.com" not in xml


def test_enrich_xml_merges_service_data_by_port() -> None:
    xml = enrich_xml(_BASE_XML, "10.0.0.1", [], service_xml=_SERVICE_XML)
    assert 'product="nginx"' in xml
    assert 'id="ssl-cert"' in xml
    assert xml.count("<service") == 2


def test_enrich_xml_without_service_xml_leaves_ports_unchanged() -> None:
    xml = enrich_xml(_BASE_XML, "10.0.0.1", [])
    assert "<service" not in xml
