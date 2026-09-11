from falcoria_contracts.enums import PortProtocol, ScannerFormat
from falcoria_tasker.scans.scanner_args import build_open_ports_args, build_service_args
from falcoria_tasker.scans.schemas import OpenPortsOpts, ServiceOpts


def test_build_open_ports_args_includes_ports_and_skip_host_discovery() -> None:
    opts = OpenPortsOpts(ports=["22", "80"])

    args = build_open_ports_args(opts, ScannerFormat.NMAP)

    assert "-p 22,80" in args
    assert "-Pn" in args


def test_build_open_ports_args_udp_adds_su_flag() -> None:
    opts = OpenPortsOpts(ports=["53"], transport_protocol=PortProtocol.UDP)

    args = build_open_ports_args(opts, ScannerFormat.NMAP)

    assert "-sU" in args


def test_build_open_ports_args_applies_common_opts() -> None:
    opts = OpenPortsOpts(ports=["22"], dns_resolution=False, max_retries=3)

    args = build_open_ports_args(opts, ScannerFormat.NMAP)

    assert "-n" in args
    assert "--max-retries 3" in args


def test_build_service_args_includes_base_flags() -> None:
    args = build_service_args(ServiceOpts(), ScannerFormat.NMAP, PortProtocol.TCP)

    assert "-sV" in args
    assert "-Pn" in args


def test_build_service_args_applies_optional_flags() -> None:
    opts = ServiceOpts(aggressive_scan=True, os_detection=True, traceroute=True)

    args = build_service_args(opts, ScannerFormat.NMAP, PortProtocol.TCP)

    assert "-A" in args
    assert "-O" in args
    assert "--traceroute" in args


def test_build_service_args_udp_adds_su_flag() -> None:
    args = build_service_args(ServiceOpts(), ScannerFormat.NMAP, PortProtocol.UDP)

    assert "-sU" in args
