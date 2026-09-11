import pytest
from pydantic import ValidationError

from falcoria_contracts.enums import ImportMode, PortProtocol
from falcoria_tasker.scans.schemas import (
    CancelScanRequest,
    OpenPortsOpts,
    RunScanRequest,
    ScanSummary,
    ServiceOpts,
    SkippedCounts,
)


def test_open_ports_opts_defaults() -> None:
    opts = OpenPortsOpts(ports=["22", "80"])

    assert opts.transport_protocol is PortProtocol.TCP
    assert opts.skip_host_discovery is True


@pytest.mark.parametrize("ports", [["0"], ["70000"], ["100-50"], ["abc"], ["22-x"]])
def test_open_ports_opts_rejects_invalid_ports(ports: list[str]) -> None:
    with pytest.raises(ValidationError):
        OpenPortsOpts(ports=ports)


def test_open_ports_opts_accepts_ranges() -> None:
    opts = OpenPortsOpts(ports=["22", "1000-2000"])

    assert opts.ports == ["22", "1000-2000"]


def test_service_opts_defaults() -> None:
    opts = ServiceOpts()

    assert opts.aggressive_scan is False
    assert opts.traceroute is False


def _request(hosts: list[str]) -> RunScanRequest:
    return RunScanRequest(
        hosts=hosts,
        open_ports_opts=OpenPortsOpts(ports=["22"]),
        service_opts=ServiceOpts(),
        timeout=30,
        include_services=False,
        mode=ImportMode.INSERT,
    )


def test_run_scan_request_accepts_ip_cidr_and_fqdn() -> None:
    request = _request(hosts=["10.0.0.1", "10.0.0.0/24", "example.com"])

    assert request.hosts == ["10.0.0.1", "10.0.0.0/24", "example.com"]


def test_run_scan_request_rejects_ipv6_address() -> None:
    with pytest.raises(ValidationError, match="IPv6"):
        _request(hosts=["2001:db8::1"])


def test_run_scan_request_rejects_ipv6_cidr() -> None:
    with pytest.raises(ValidationError, match="IPv6"):
        _request(hosts=["2001:db8::/64"])


def test_run_scan_request_rejects_oversized_cidr() -> None:
    with pytest.raises(ValidationError, match="CIDR too large"):
        _request(hosts=["10.0.0.0/8"])


def test_run_scan_request_accepts_cidr_at_the_size_limit() -> None:
    request = _request(hosts=["10.0.0.0/16"])

    assert request.hosts == ["10.0.0.0/16"]


def test_run_scan_request_rejects_malformed_host() -> None:
    with pytest.raises(ValidationError, match="Invalid host format"):
        _request(hosts=["not a host!"])


def test_cancel_scan_request_normalizes_and_dedupes_nothing_but_validates_ips() -> None:
    request = CancelScanRequest(ips=["10.0.0.1", "10.0.0.2"])

    assert request.ips == ["10.0.0.1", "10.0.0.2"]


def test_cancel_scan_request_rejects_invalid_ip() -> None:
    with pytest.raises(ValidationError, match="Invalid IP address"):
        CancelScanRequest(ips=["not-an-ip"])


def test_cancel_scan_request_empty_ips_becomes_none() -> None:
    request = CancelScanRequest(ips=[])

    assert request.ips is None


def test_skipped_counts_total_sums_all_reasons() -> None:
    counts = SkippedCounts(
        private_ip=1, unresolvable=2, already_known=3, already_running=4, other=5
    )

    assert counts.total == 15


def test_scan_summary_accepts_consistent_counts() -> None:
    summary = ScanSummary(
        provided=10,
        duplicates_removed=1,
        resolved_ips=8,
        skipped=SkippedCounts(already_known=2),
        started=6,
    )

    assert summary.started == 6


def test_scan_summary_rejects_inconsistent_counts() -> None:
    with pytest.raises(ValidationError, match="started"):
        ScanSummary(
            provided=10,
            duplicates_removed=1,
            resolved_ips=8,
            skipped=SkippedCounts(already_known=2),
            started=99,
        )
