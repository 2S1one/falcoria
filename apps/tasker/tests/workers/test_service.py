"""Tests for workers/service.py."""

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import SecretStr

from falcoria_contracts.temporal_names import PORT_SCANNER_TASK_QUEUE
from falcoria_tasker.config import AppSettings
from falcoria_tasker.temporal.workflows import PollerSighting
from falcoria_tasker.workers.service import get_workers

pytestmark = pytest.mark.anyio


def _settings(stale_seconds: int = 90) -> AppSettings:
    return AppSettings(
        scanledger_base_url="http://scanledger.test/api",
        scanledger_token=SecretStr("svc-token"),
        worker_poller_stale_seconds=stale_seconds,
    )


def _patch(
    monkeypatch: pytest.MonkeyPatch, sightings: list[PollerSighting], stale_seconds: int = 90
) -> None:
    async def fake_describe(queue_name: str) -> list[PollerSighting]:
        assert queue_name == PORT_SCANNER_TASK_QUEUE
        return sightings

    monkeypatch.setattr(
        "falcoria_tasker.workers.service.describe_task_queue_pollers", fake_describe
    )
    monkeypatch.setattr(
        "falcoria_tasker.workers.service.get_app_settings", lambda: _settings(stale_seconds)
    )


async def test_groups_sightings_by_identity_across_poller_types(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime.now(UTC)
    _patch(
        monkeypatch,
        [
            PollerSighting(
                identity="123@host-1:10.0.0.1", last_access_time=now, poller_type="workflow"
            ),
            PollerSighting(
                identity="123@host-1:10.0.0.1",
                last_access_time=now - timedelta(seconds=5),
                poller_type="activity",
            ),
        ],
    )

    response = await get_workers()

    assert response.available_workers == 1
    worker = response.workers[0]
    assert worker.identity == "host-1:10.0.0.1"
    assert worker.external_ip == "10.0.0.1"
    assert worker.last_access_time == now
    assert set(worker.poller_types) == {"activity", "workflow"}
    assert worker.task_queue == PORT_SCANNER_TASK_QUEUE


async def test_drops_pollers_stale_beyond_the_configured_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime.now(UTC)
    _patch(
        monkeypatch,
        [
            PollerSighting(
                identity="1@stale-host:1.2.3.4",
                last_access_time=now - timedelta(seconds=200),
                poller_type="activity",
            )
        ],
        stale_seconds=90,
    )

    response = await get_workers()

    assert response.workers == []
    assert response.available_workers == 0


async def test_drops_pollers_that_never_reported_a_timestamp(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch(
        monkeypatch,
        [PollerSighting(identity="1@host:1.2.3.4", last_access_time=None, poller_type="activity")],
    )

    response = await get_workers()

    assert response.workers == []


async def test_sorts_most_recently_seen_first(monkeypatch: pytest.MonkeyPatch) -> None:
    now = datetime.now(UTC)
    _patch(
        monkeypatch,
        [
            PollerSighting(
                identity="1@a:1.1.1.1",
                last_access_time=now - timedelta(seconds=10),
                poller_type="activity",
            ),
            PollerSighting(identity="2@b:2.2.2.2", last_access_time=now, poller_type="activity"),
        ],
    )

    response = await get_workers()

    assert [w.identity for w in response.workers] == ["b:2.2.2.2", "a:1.1.1.1"]


async def test_handles_an_identity_with_no_external_ip(monkeypatch: pytest.MonkeyPatch) -> None:
    now = datetime.now(UTC)
    _patch(
        monkeypatch,
        [PollerSighting(identity="1@bare-host", last_access_time=now, poller_type="workflow")],
    )

    response = await get_workers()

    worker = response.workers[0]
    assert worker.identity == "bare-host"
    assert worker.external_ip is None
