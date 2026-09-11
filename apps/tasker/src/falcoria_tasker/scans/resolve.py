"""Impure DNS resolution: resolves hostnames to IPs, concurrently, with retries."""

import asyncio
import logging
from dataclasses import dataclass, field

import aiodns

from falcoria_tasker.dns import get_dns_resolver
from falcoria_tasker.scans.targets import is_public_ip

logger = logging.getLogger("falcoria_tasker")


@dataclass(slots=True)
class ResolvedHostnames:
    """DNS resolution outcome for a batch of pending hostnames."""

    public_ips: list[str] = field(default_factory=list)
    private_ips: dict[str, list[str]] = field(default_factory=dict)
    unresolvable: list[str] = field(default_factory=list)


async def _resolve_hostname(hostname: str, single_resolve: bool) -> list[str]:
    """Returns hostname's A-record IPs, or [] if the DNS query fails."""
    try:
        result = await get_dns_resolver().query(hostname, "A")
    except aiodns.error.DNSError:
        return []
    ips = [record.host for record in result]
    return ips[:1] if single_resolve and ips else ips


async def resolve_targets(
    hostnames: list[str],
    single_resolve: bool,
    semaphore_limit: int,
    *,
    retries: int = 2,
    timeout_seconds: float = 2.0,
    retry_delay_seconds: float = 1.0,
) -> ResolvedHostnames:
    """Resolves hostnames concurrently, classifying results as public/private.

    Each hostname gets up to retries attempts, separated by retry_delay_seconds,
    before being reported as unresolvable. Concurrency is capped at
    semaphore_limit in-flight lookups. A hostname the DNS can't resolve after
    retries is a normal scan outcome, not an error - it's returned, not raised.
    """
    result = ResolvedHostnames()
    semaphore = asyncio.Semaphore(semaphore_limit)

    def add_private(ip: str, source: str) -> None:
        sources = result.private_ips.setdefault(ip, [])
        if source not in sources:
            sources.append(source)

    async def resolve_one(hostname: str) -> None:
        async with semaphore:
            for attempt in range(retries):
                try:
                    ips = await asyncio.wait_for(
                        _resolve_hostname(hostname, single_resolve), timeout=timeout_seconds
                    )
                except TimeoutError:
                    ips = []
                if ips:
                    for ip in ips:
                        if is_public_ip(ip):
                            result.public_ips.append(ip)
                        else:
                            add_private(ip, hostname)
                    return
                if attempt < retries - 1:
                    await asyncio.sleep(retry_delay_seconds)
            logger.warning("Giving up on hostname %s after %d retries.", hostname, retries)
            result.unresolvable.append(hostname)

    await asyncio.gather(*(resolve_one(hostname) for hostname in hostnames))
    return result
