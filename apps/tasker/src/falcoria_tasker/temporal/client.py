"""Lazy Temporal client connection: connect/get/dispose, mirroring database.py's engine pattern.

Client.connect() is itself a coroutine, so unlike get_engine()'s @lru_cache this
holds the connected client on a private singleton instance instead — the
lifespan calls connect_temporal() once at startup, and route code calls
get_temporal_client() to read it.
"""

from falcoria_temporal.converter import pydantic_data_converter
from temporalio.client import Client

from falcoria_tasker.config import get_temporal_settings


class _TemporalConnection:
    """Holds the process-wide Temporal client once connected."""

    def __init__(self) -> None:
        self.client: Client | None = None


_connection = _TemporalConnection()


async def connect_temporal() -> Client:
    """Connects to Temporal and caches the client; call once from the lifespan."""
    settings = get_temporal_settings()
    _connection.client = await Client.connect(
        settings.address,
        namespace=settings.namespace,
        data_converter=pydantic_data_converter,
        tls=settings.tls,
    )
    return _connection.client


def get_temporal_client() -> Client:
    """Returns the connected Temporal client.

    Raises:
        RuntimeError: connect_temporal() has not been awaited yet.
    """
    if _connection.client is None:
        raise RuntimeError("Temporal client is not connected; call connect_temporal() first.")
    return _connection.client


async def dispose_temporal() -> None:
    """Drops the cached client; called on application shutdown.

    The SDK's `Client` has no explicit close/dispose method — dropping the
    reference releases the underlying gRPC channel.
    """
    _connection.client = None
