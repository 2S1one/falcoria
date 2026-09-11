"""Requires a local Temporal server (``docker compose up -d temporal``)."""

import pytest

from falcoria_tasker.config import get_temporal_settings
from falcoria_tasker.temporal.client import connect_temporal, dispose_temporal, get_temporal_client

pytestmark = pytest.mark.anyio


async def test_connect_temporal_connects_to_a_running_server(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TASKER_TEMPORAL_ADDRESS", "localhost:7233")
    get_temporal_settings.cache_clear()
    try:
        client = await connect_temporal()
        assert client is get_temporal_client()
        assert client.namespace == "default"
    finally:
        await dispose_temporal()
        get_temporal_settings.cache_clear()
