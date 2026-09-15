from falcoria_contracts.enums import PortProtocol, ScannerFormat
from falcoria_tasker.scans.scanner_args import build_open_ports_args, build_service_args
from falcoria_tasker.scans.schemas import OpenPortsOpts, ScanType, ServiceOpts


def test_build_open_ports_args_includes_ports_and_skip_host_discovery() -> None:
    opts = OpenPortsOpts(ports=["22", "80"])

    args = build_open_ports_args(opts, ScannerFormat.NMAP)

    assert "-p 22,80" in args
    assert "-Pn" in args


def test_build_open_ports_args_udp_adds_su_flag() -> None:
    opts = OpenPortsOpts(ports=["53"], transport_protocol=PortProtocol.UDP)

    args = build_open_ports_args(opts, ScannerFormat.NMAP)

    assert "-sU" in args


def test_build_open_ports_args_tcp_syn_adds_ss_flag() -> None:
    opts = OpenPortsOpts(ports=["22"])

    args = build_open_ports_args(opts, ScannerFormat.NMAP)

    assert "-sS" in args


def test_build_open_ports_args_tcp_connect_adds_st_flag() -> None:
    opts = OpenPortsOpts(ports=["22"], scan_type=ScanType.CONNECT)

    args = build_open_ports_args(opts, ScannerFormat.NMAP)

    assert "-sT" in args


def test_build_open_ports_args_applies_common_opts() -> None:
    opts = OpenPortsOpts(ports=["22"], dns_resolution=False, max_retries=3)

    args = build_open_ports_args(opts, ScannerFormat.NMAP)

    assert "-n" in args
    assert "--max-retries 3" in args


def test_build_service_args_includes_base_flags() -> None:
    args = build_service_args(ServiceOpts(), ScannerFormat.NMAP, PortProtocol.TCP, ScanType.SYN)

    assert "-sV" in args
    assert "-Pn" in args


def test_build_service_args_applies_optional_flags() -> None:
    opts = ServiceOpts(aggressive_scan=True, os_detection=True, traceroute=True)

    args = build_service_args(opts, ScannerFormat.NMAP, PortProtocol.TCP, ScanType.SYN)

    assert "-A" in args
    assert "-O" in args
    assert "--traceroute" in args


def test_build_service_args_udp_adds_su_flag() -> None:
    args = build_service_args(ServiceOpts(), ScannerFormat.NMAP, PortProtocol.UDP, ScanType.SYN)

    assert "-sU" in args


def test_build_service_args_tcp_syn_adds_ss_flag() -> None:
    args = build_service_args(ServiceOpts(), ScannerFormat.NMAP, PortProtocol.TCP, ScanType.SYN)

    assert "-sS" in args


def test_build_service_args_tcp_connect_adds_st_flag() -> None:
    args = build_service_args(ServiceOpts(), ScannerFormat.NMAP, PortProtocol.TCP, ScanType.CONNECT)

    assert "-sT" in args


def test_build_service_args_version_intensity() -> None:
    opts = ServiceOpts(version_intensity=5)

    args = build_service_args(opts, ScannerFormat.NMAP, PortProtocol.TCP, ScanType.SYN)

    assert "--version-intensity 5" in args
