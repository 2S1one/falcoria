"""Pure scanner argument building: option models -> CLI arg strings."""

from falcoria_contracts.enums import PortProtocol, ScannerFormat
from falcoria_tasker.scans.schemas import CommonScanOpts, OpenPortsOpts, ScanType, ServiceOpts


def _common_args(opts: CommonScanOpts) -> list[str]:
    args = []
    if opts.dns_resolution is not None:
        args.append("-R" if opts.dns_resolution else "-n")
    if opts.max_retries is not None:
        args.append(f"--max-retries {opts.max_retries}")
    if opts.min_rtt_timeout_ms is not None:
        args.append(f"--min-rtt-timeout {opts.min_rtt_timeout_ms}ms")
    if opts.max_rtt_timeout_ms is not None:
        args.append(f"--max-rtt-timeout {opts.max_rtt_timeout_ms}ms")
    if opts.initial_rtt_timeout_ms is not None:
        args.append(f"--initial-rtt-timeout {opts.initial_rtt_timeout_ms}ms")
    if opts.min_rate is not None:
        args.append(f"--min-rate {opts.min_rate}")
    if opts.max_rate is not None:
        args.append(f"--max-rate {opts.max_rate}")
    return args


def _scan_type_flag(transport_protocol: PortProtocol, scan_type: ScanType) -> str:
    if transport_protocol is PortProtocol.UDP:
        return "-sU"
    return "-sS" if scan_type is ScanType.SYN else "-sT"


def build_open_ports_args(opts: OpenPortsOpts, scanner: ScannerFormat) -> str:
    """Builds the open-ports-phase CLI arguments for scanner."""
    if scanner is not ScannerFormat.NMAP:
        raise ValueError(f"unsupported scanner: {scanner}")
    args = _common_args(opts)
    args.append(_scan_type_flag(opts.transport_protocol, opts.scan_type))
    if opts.skip_host_discovery:
        args.append("-Pn")
    args.append(f"-p {','.join(opts.ports)}")
    return " ".join(args)


def build_service_args(
    opts: ServiceOpts,
    scanner: ScannerFormat,
    transport_protocol: PortProtocol,
    scan_type: ScanType,
) -> str:
    """Builds the service-detection-phase CLI arguments for scanner."""
    if scanner is not ScannerFormat.NMAP:
        raise ValueError(f"unsupported scanner: {scanner}")
    args = [*_common_args(opts), "-Pn", "-sV"]
    if opts.version_intensity is not None:
        args.append(f"--version-intensity {opts.version_intensity}")
    if opts.aggressive_scan:
        args.append("-A")
    if opts.default_scripts:
        args.append("-sC")
    if opts.os_detection:
        args.append("-O")
    if opts.traceroute:
        args.append("--traceroute")
    args.append(_scan_type_flag(transport_protocol, scan_type))
    return " ".join(args)
