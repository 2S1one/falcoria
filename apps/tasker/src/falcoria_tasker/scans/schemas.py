"""Scan option and request/response DTOs."""

import re
from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network

from pydantic import BaseModel, Field, computed_field, field_validator, model_validator

from falcoria_contracts.enums import ImportMode, PortProtocol


class CommonScanOpts(BaseModel):
    """Timing and retry knobs shared by the open-ports and service-detection phases."""

    dns_resolution: bool | None = Field(default=None, description="-n (False), -R (True)")
    max_retries: int | None = Field(default=None, ge=0, le=20, description="--max-retries")
    min_rtt_timeout_ms: int | None = Field(
        default=None, ge=1, le=60000, description="--min-rtt-timeout"
    )
    max_rtt_timeout_ms: int | None = Field(
        default=None, ge=1, le=60000, description="--max-rtt-timeout"
    )
    initial_rtt_timeout_ms: int | None = Field(
        default=None, ge=1, le=60000, description="--initial-rtt-timeout"
    )
    min_rate: int | None = Field(default=None, ge=1, le=30000, description="--min-rate")
    max_rate: int | None = Field(default=None, ge=1, le=30000, description="--max-rate")


class OpenPortsOpts(CommonScanOpts):
    """Options for the open-ports discovery phase, which always runs."""

    transport_protocol: PortProtocol = PortProtocol.TCP
    ports: list[str] = Field(description="Ports or ranges, e.g. '22', '1000-2000'.")
    skip_host_discovery: bool = Field(default=True, description="-Pn")

    @field_validator("ports")
    @classmethod
    def _validate_ports(cls, ports: list[str]) -> list[str]:
        for port in ports:
            if "-" in port:
                parts = port.split("-")
                if len(parts) != 2 or not all(p.isdigit() for p in parts):
                    raise ValueError(f"Invalid port range format: {port}")
                start, end = map(int, parts)
                if not (1 <= start <= 65535) or start > end:
                    raise ValueError(f"Port range out of bounds: {port}")
            elif not port.isdigit() or not (1 <= int(port) <= 65535):
                raise ValueError(f"Invalid port: {port}")
        return ports


class ServiceOpts(CommonScanOpts):
    """Options for the optional service-detection phase."""

    aggressive_scan: bool = Field(default=False, description="-A")
    default_scripts: bool = Field(default=False, description="-sC")
    os_detection: bool = Field(default=False, description="-O")
    traceroute: bool = Field(default=False, description="--traceroute")


# --- API request/response ---

_FQDN_RE = re.compile(r"^((?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,63}$", re.IGNORECASE)
_MIN_CIDR_PREFIX = 16  # /16 = 65,534 hosts - the largest single CIDR one request may specify


def _validate_host(host: str) -> str:
    """Confirms host is an IPv4 address, an IPv4 CIDR no larger than /16, or an FQDN.

    IPv6 is out of scope (see refactor/known-risks.md #7): nothing downstream
    (is_public_ip, the worker, nmap-flavored arg building) is built for it.
    """
    try:
        parsed = ip_address(host)
    except ValueError:
        parsed = None
    if parsed is not None:
        if not isinstance(parsed, IPv4Address):
            raise ValueError(f'IPv6 is not supported: "{host}"')
        return host

    try:
        network = ip_network(host, strict=False)
    except ValueError:
        network = None
    if network is not None:
        if not isinstance(network, IPv4Network):
            raise ValueError(f'IPv6 is not supported: "{host}"')
        if network.prefixlen < _MIN_CIDR_PREFIX:
            raise ValueError(f'CIDR too large (min /{_MIN_CIDR_PREFIX}): "{host}"')
        return host

    if not _FQDN_RE.match(host):
        raise ValueError(f'Invalid host format "{host}" - must be IP, CIDR, or FQDN')
    if len(host) > 253:
        raise ValueError("FQDN must be 253 characters or less")
    return host


class ShardingConfig(BaseModel):
    """How many shards to split a scan into; ignored in INSERT mode."""

    shard_count: int = Field(
        ge=2,
        le=500,
        description="Number of shards to split the scan into. Only applies if mode is not 'insert'.",
    )


class RunScanRequest(BaseModel):
    """A request to scan a set of hosts."""

    hosts: list[str]
    open_ports_opts: OpenPortsOpts
    service_opts: ServiceOpts
    timeout: int = Field(gt=0, le=60 * 60 * 24, description="Timeout per IP in seconds.")
    include_services: bool = Field(description="Whether to run the service-detection phase.")
    single_resolve: bool = Field(default=False, description="Resolve a hostname to one IP only.")
    mode: ImportMode = Field(description="scanledger import mode.")
    sharding: ShardingConfig | None = None

    @field_validator("hosts", mode="before")
    @classmethod
    def _validate_hosts(cls, hosts: list[str]) -> list[str]:
        return [_validate_host(host) for host in hosts]


class CancelScanRequest(BaseModel):
    """Cancels a scan by scan_id, by ips, or (both omitted) every running scan in the project."""

    scan_id: str | None = None
    ips: list[str] | None = None

    @field_validator("ips", mode="before")
    @classmethod
    def _validate_ips(cls, ips: list[str] | None) -> list[str] | None:
        if ips is None:
            return None
        validated = []
        for ip in ips:
            try:
                ip_address(ip)
            except ValueError:
                raise ValueError(f'Invalid IP address: "{ip}"') from None
            validated.append(ip)
        return validated or None


class SkippedCounts(BaseModel):
    """Why targets were not started, broken down by reason."""

    private_ip: int = 0
    unresolvable: int = 0
    already_known: int = 0
    already_running: int = 0
    other: int = 0

    @computed_field
    @property
    def total(self) -> int:
        """Returns the sum of all skip reasons."""
        return (
            self.private_ip
            + self.unresolvable
            + self.already_known
            + self.already_running
            + self.other
        )


class ScanSummary(BaseModel):
    """Accounting for one run-scan request, from provided hosts down to started targets."""

    provided: int
    duplicates_removed: int
    resolved_ips: int
    hostnames_collapsed_to_ip: int = 0
    skipped: SkippedCounts = Field(default_factory=SkippedCounts)
    started: int

    @model_validator(mode="after")
    def _validate_math(self) -> "ScanSummary":
        post_resolution_skipped = (
            self.skipped.already_known + self.skipped.already_running + self.skipped.other
        )
        expected = self.resolved_ips - post_resolution_skipped
        if self.started != expected:
            raise ValueError(
                f"started={self.started} != resolved_ips({self.resolved_ips}) "
                f"- post_resolution_skipped({post_resolution_skipped})"
            )
        return self


class NotScannedDetails(BaseModel):
    """Targets excluded from the scan, for the caller's visibility."""

    private_targets: dict[str, list[str]] = Field(default_factory=dict)
    unresolvable_hosts: list[str] = Field(default_factory=list)


class RunScanResponse(BaseModel):
    """Result of a run-scan request."""

    scan_id: str | None
    summary: ScanSummary
    not_scanned: NotScannedDetails


class CancelScanResponse(BaseModel):
    """Result of a cancel request."""

    success: bool = True


class ScanListResponse(BaseModel):
    """Count and ids of a project's currently running scans."""

    running: int
    scan_ids: list[str] = Field(default_factory=list)


class RunningTarget(BaseModel):
    """One IP currently being scanned, and which worker (if known) is running it."""

    ip: str
    worker: str | None


class ScanStatusResponse(BaseModel):
    """Progress of one scan: task-completion counts plus its currently running targets."""

    total: int
    completed: int
    failed: int
    running_targets: list[RunningTarget] = Field(default_factory=list)
