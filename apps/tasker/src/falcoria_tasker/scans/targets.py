"""Pure target classification: no I/O, no DNS."""

from dataclasses import dataclass, field
from ipaddress import IPv4Address, ip_address, ip_network


def is_public_ip(ip: str) -> bool:
    """Returns whether ip is a public (non-private) IPv4 address."""
    try:
        parsed = ip_address(ip)
    except ValueError:
        return False
    return isinstance(parsed, IPv4Address) and not parsed.is_private


def expand_cidr(cidr: str) -> list[str]:
    """Expands a CIDR block to its host IPs; a /32 returns just that one IP."""
    network = ip_network(cidr, strict=False)
    if network.num_addresses == 1:
        return [str(network.network_address)]
    return [str(ip) for ip in network.hosts()]


def _normalize(entry: str) -> str:
    """Canonicalizes one entry for duplicate comparison, without expanding a CIDR's hosts."""
    if "/" in entry:
        network = ip_network(entry, strict=False)
        return str(network.network_address) if network.num_addresses == 1 else str(network)
    try:
        return str(ip_address(entry))
    except ValueError:
        return entry


def remove_duplicates(entries: list[str]) -> list[str]:
    """Drops duplicate targets, treating equivalent IP/CIDR notations as one entry.

    Keeps the first-seen original formatting and order. Hostnames are compared
    as literal strings - no DNS is involved. A CIDR is compared as a whole
    network (e.g. "10.0.0.0/24"), not by its first host, so two distinct
    networks that merely share a first address are never conflated.
    """
    seen: set[str] = set()
    result: list[str] = []
    for entry in entries:
        normalized = _normalize(entry)
        if normalized not in seen:
            seen.add(normalized)
            result.append(entry)
    return result


@dataclass(slots=True)
class TargetPartition:
    """Deduped targets split into public IPs, private IPs (with their source), and pending hostnames."""

    public_ips: list[str] = field(default_factory=list)
    private_ips: dict[str, list[str]] = field(default_factory=dict)
    pending_hostnames: list[str] = field(default_factory=list)


def partition_targets(entries: list[str]) -> TargetPartition:
    """Classifies deduped targets without DNS.

    Each entry is an IP, a CIDR, or (assumed) a hostname. IPs and CIDRs are
    split into public_ips / private_ips directly, recording the source CIDR
    for a private IP found via expansion (None for a standalone private IP).
    Anything else is queued in pending_hostnames for the DNS resolution step.
    """
    partition = TargetPartition()

    def add_private(ip: str, source: str | None) -> None:
        sources = partition.private_ips.setdefault(ip, [])
        if source and source not in sources:
            sources.append(source)

    for entry in entries:
        try:
            ip_address(entry)
            if is_public_ip(entry):
                partition.public_ips.append(entry)
            else:
                add_private(entry, None)
            continue
        except ValueError:
            pass

        if "/" in entry:
            for ip in expand_cidr(entry):
                if is_public_ip(ip):
                    partition.public_ips.append(ip)
                else:
                    add_private(ip, entry)
            continue

        partition.pending_hostnames.append(entry)

    return partition
