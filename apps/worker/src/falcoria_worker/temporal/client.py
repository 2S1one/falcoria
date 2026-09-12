"""Temporal client connection, using the shared pinned pydantic data converter."""

from falcoria_temporal.converter import pydantic_data_converter
from temporalio.client import Client

from falcoria_worker.config import get_temporal_settings


async def connect_temporal(identity: str) -> Client:
    """Connects to Temporal using the process's configured address/namespace/TLS."""
    settings = get_temporal_settings()
    return await Client.connect(
        settings.address,
        namespace=settings.namespace,
        data_converter=pydantic_data_converter,
        tls=settings.tls,
        identity=identity,
    )
