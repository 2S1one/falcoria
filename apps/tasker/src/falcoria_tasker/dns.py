"""Shared DNS resolver: init/get/dispose, initialized once in the app lifespan."""

import aiodns


class _DnsConnection:
    """Holds the process-wide DNS resolver once initialized."""

    def __init__(self) -> None:
        self.resolver: aiodns.DNSResolver | None = None


_connection = _DnsConnection()


def init_dns_resolver() -> aiodns.DNSResolver:
    """Creates and caches the shared resolver; call once from the lifespan."""
    _connection.resolver = aiodns.DNSResolver()
    return _connection.resolver


def get_dns_resolver() -> aiodns.DNSResolver:
    """Returns the shared resolver.

    Raises:
        RuntimeError: init_dns_resolver() has not been called yet.
    """
    if _connection.resolver is None:
        raise RuntimeError("DNS resolver is not initialized; call init_dns_resolver() first.")
    return _connection.resolver


async def dispose_dns_resolver() -> None:
    """Closes the resolver, releasing its resources; called on application shutdown."""
    if _connection.resolver is not None:
        await _connection.resolver.close()
        _connection.resolver = None
