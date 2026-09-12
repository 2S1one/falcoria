"""Requires a local Temporal server (``docker compose up -d temporal``)."""

import pytest

from falcoria_worker.config import get_temporal_settings
from falcoria_worker.temporal.client import connect_temporal

pytestmark = [pytest.mark.anyio, pytest.mark.temporal]


async def test_connect_temporal_connects_to_a_running_server(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("WORKER_TEMPORAL_ADDRESS", "localhost:7233")
    get_temporal_settings.cache_clear()
    try:
        client = await connect_temporal("test-identity")
        assert client.namespace == "default"
        assert client.identity == "test-identity"
    finally:
        get_temporal_settings.cache_clear()
