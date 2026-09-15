"""Parse coverage for port_prevalence/parser.py against nmap-services-shaped input."""

from falcoria_contracts.enums import PortProtocol
from falcoria_scanledger.port_prevalence.parser import ParsedPortPrevalence, parse_nmap_services


def test_parses_name_port_protocol_score_and_comment() -> None:
    lines = ["http\t80/tcp\t0.484143\t# HyperText Transfer Protocol"]
    entries = parse_nmap_services(lines)
    assert len(entries) == 1
    entry = entries[0]
    assert entry.number == 80
    assert entry.protocol == PortProtocol.TCP
    assert entry.score == 0.484143


def test_parses_line_with_no_trailing_comment() -> None:
    entries = parse_nmap_services(["unknown\t4/tcp\t0.000477"])
    assert entries == [ParsedPortPrevalence(number=4, protocol=PortProtocol.TCP, score=0.000477)]


def test_skips_comment_and_blank_lines() -> None:
    lines = [
        "# THIS FILE IS GENERATED AUTOMATICALLY FROM A MASTER - DO NOT EDIT.",
        "",
        "   ",
        "http\t80/tcp\t0.484143\t# HyperText Transfer Protocol",
    ]
    entries = parse_nmap_services(lines)
    assert [e.number for e in entries] == [80]


def test_skips_unsupported_protocol() -> None:
    lines = [
        "echo\t7/sctp\t0.000000",
        "echo\t7/tcp\t0.004855",
    ]
    entries = parse_nmap_services(lines)
    assert [(e.number, e.protocol) for e in entries] == [(7, PortProtocol.TCP)]


def test_skips_lines_with_too_few_fields() -> None:
    entries = parse_nmap_services(["malformed-line-with-only-a-name"])
    assert entries == []


def test_preserves_source_order_and_duplicates() -> None:
    lines = [
        "tcpmux\t1/tcp\t0.001995",
        "tcpmux\t1/udp\t0.001236",
        "compressnet\t2/tcp\t0.000013",
    ]
    entries = parse_nmap_services(lines)
    assert [(e.number, e.protocol) for e in entries] == [
        (1, PortProtocol.TCP),
        (1, PortProtocol.UDP),
        (2, PortProtocol.TCP),
    ]
