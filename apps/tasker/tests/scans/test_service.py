"""Tests for scans/service.py."""

import asyncio
import json
from dataclasses import dataclass
from datetime import timedelta
from uuid import UUID

import aiodns
import httpx
import pytest
from pydantic import SecretStr

import falcoria_tasker.scans.service as service_module
from falcoria_contracts.enums import ImportMode
from falcoria_contracts.scan_io import ScanBatchResult, ScanTask
from falcoria_tasker.config import AppSettings
from falcoria_tasker.scanledger import ScanledgerClient
from falcoria_tasker.scans.schemas import (
    CancelScanRequest,
    OpenPortsOpts,
    RunningTarget,
    RunScanRequest,
    ScanListResponse,
    ScanStatusResponse,
    ServiceOpts,
    ShardingConfig,
)
from falcoria_tasker.scans.service import (
    InsertModeDedup,
    PreparedTargets,
    _build_not_scanned,
    _build_summary,
    _build_tasks,
    _merge_sources,
    _shard_count,
    cancel_scan,
    get_scan_status,
    list_running_scans,
    run_scan,
)
from falcoria_tasker.temporal import workflows as workflows_module

pytestmark = pytest.mark.anyio

PROJECT_ID = UUID("11111111-1111-1111-1111-111111111111")


def _request(
    hosts: list[str],
    mode: ImportMode = ImportMode.INSERT,
    include_services: bool = False,
    sharding: ShardingConfig | None = None,
) -> RunScanRequest:
    return RunScanRequest(
        hosts=hosts,
        open_ports_opts=OpenPortsOpts(ports=["22", "80"]),
        service_opts=ServiceOpts(),
        timeout=30,
        include_services=include_services,
        mode=mode,
        sharding=sharding,
    )


# --- _merge_sources ---


def test_merge_sources_unions_and_dedupes() -> None:
    merged = _merge_sources({"1.1.1.1": ["a"]}, {"1.1.1.1": ["a", "b"], "2.2.2.2": ["c"]})

    assert merged == {"1.1.1.1": ["a", "b"], "2.2.2.2": ["c"]}


# --- _shard_count ---


def test_shard_count_forces_one_in_insert_mode() -> None:
    request = _request(["1.1.1.1"], mode=ImportMode.INSERT, sharding=ShardingConfig(shard_count=5))

    assert _shard_count(request) == 1


def test_shard_count_defaults_to_one_without_sharding_config() -> None:
    request = _request(["1.1.1.1"], mode=ImportMode.REPLACE)

    assert _shard_count(request) == 1


def test_shard_count_uses_config_outside_insert_mode() -> None:
    request = _request(["1.1.1.1"], mode=ImportMode.REPLACE, sharding=ShardingConfig(shard_count=4))

    assert _shard_count(request) == 4


# --- _build_tasks ---


def test_build_tasks_builds_one_task_per_ip_without_sharding() -> None:
    request = _request(["1.1.1.1", "2.2.2.2"])
    to_scan = {"1.1.1.1": ["a.example.com"], "2.2.2.2": []}

    tasks = _build_tasks(to_scan, request)

    assert {t.ip for t in tasks} == {"1.1.1.1", "2.2.2.2"}
    assert all(t.service_args is None for t in tasks)
    by_ip = {t.ip: t for t in tasks}
    assert by_ip["1.1.1.1"].hostnames == ["a.example.com"]


def test_build_tasks_includes_service_args_when_requested() -> None:
    request = _request(["1.1.1.1"], include_services=True)

    tasks = _build_tasks({"1.1.1.1": []}, request)

    assert tasks[0].service_args is not None


def test_build_tasks_shards_ports_outside_insert_mode() -> None:
    request = _request(["1.1.1.1"], mode=ImportMode.REPLACE, sharding=ShardingConfig(shard_count=2))

    tasks = _build_tasks({"1.1.1.1": []}, request)

    assert len(tasks) == 2
    ports_used = {t.open_ports_args.split()[-1] for t in tasks}
    assert ports_used == {"22", "80"}


# --- InsertModeDedup ---


def test_insert_mode_dedup_known_only_excludes_running() -> None:
    dedup = InsertModeDedup(already_known={"1.1.1.1", "2.2.2.2"}, already_running={"2.2.2.2"})

    assert dedup.known_only == {"1.1.1.1"}
    assert dedup.skipped_ips == {"1.1.1.1", "2.2.2.2"}


# --- _build_summary / _build_not_scanned ---


def _prepared(**overrides: object) -> PreparedTargets:
    base: dict[str, object] = {
        "deduped": ["1.1.1.1"],
        "public_ip_hostnames": {"1.1.1.1": []},
        "private_ip_sources": {},
        "unresolvable_hosts": [],
        "pending_hostname_count": 0,
        "resolved_new_ip_count": 0,
    }
    base.update(overrides)
    return PreparedTargets(**base)  # type: ignore[arg-type]


def test_build_summary_basic_accounting() -> None:
    request = _request(["1.1.1.1", "1.1.1.1"])
    prepared = _prepared(deduped=["1.1.1.1"], public_ip_hostnames={"1.1.1.1": []})

    summary = _build_summary(request, prepared, InsertModeDedup(), started=1)

    assert summary.provided == 2
    assert summary.duplicates_removed == 1
    assert summary.resolved_ips == 1
    assert summary.started == 1
    assert summary.skipped.already_known == 0


def test_build_summary_counts_known_only_not_already_running() -> None:
    request = _request(["1.1.1.1", "2.2.2.2", "3.3.3.3"])
    prepared = _prepared(
        deduped=["1.1.1.1", "2.2.2.2", "3.3.3.3"],
        public_ip_hostnames={"1.1.1.1": [], "2.2.2.2": [], "3.3.3.3": []},
    )
    dedup = InsertModeDedup(already_known={"2.2.2.2", "3.3.3.3"}, already_running={"3.3.3.3"})

    summary = _build_summary(request, prepared, dedup, started=1)

    assert summary.skipped.already_known == 1
    assert summary.skipped.already_running == 1
    assert summary.started == 1


def test_build_summary_hostnames_collapsed_to_ip() -> None:
    request = _request(["a.example.com", "b.example.com"])
    prepared = _prepared(
        deduped=["a.example.com", "b.example.com"],
        public_ip_hostnames={"9.9.9.9": ["a.example.com", "b.example.com"]},
        pending_hostname_count=2,
        resolved_new_ip_count=1,
    )

    summary = _build_summary(request, prepared, InsertModeDedup(), started=1)

    assert summary.hostnames_collapsed_to_ip == 1


def test_build_not_scanned_reports_private_and_unresolvable() -> None:
    prepared = _prepared(
        private_ip_sources={"10.0.0.1": ["10.0.0.0/24"]}, unresolvable_hosts=["dead.example.com"]
    )

    not_scanned = _build_not_scanned(prepared)

    assert not_scanned.private_targets == {"10.0.0.1": ["10.0.0.0/24"]}
    assert not_scanned.unresolvable_hosts == ["dead.example.com"]


# --- run_scan (integration) ---


@dataclass
class _FakeRecord:
    host: str


class _FakeResolver:
    def __init__(self, responses: dict[str, list[list[str]] | Exception]) -> None:
        self._responses = responses

    async def query(self, hostname: str, record_type: str) -> list[_FakeRecord]:
        response = self._responses[hostname]
        if isinstance(response, Exception):
            raise response
        return [_FakeRecord(host=ip) for ip in response[0]]


def _patch_resolver(
    monkeypatch: pytest.MonkeyPatch, responses: dict[str, list[list[str]] | Exception]
) -> None:
    resolver = _FakeResolver(responses)
    monkeypatch.setattr("falcoria_tasker.scans.resolve.get_dns_resolver", lambda: resolver)


def _patch_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = AppSettings(
        scanledger_base_url="http://scanledger.test/api",
        scanledger_token=SecretStr("svc-token"),
        dns_resolve_semaphore_limit=10,
    )
    monkeypatch.setattr("falcoria_tasker.scans.service.get_app_settings", lambda: settings)


def _patch_scanledger(monkeypatch: pytest.MonkeyPatch, handler: object) -> None:
    client = ScanledgerClient(
        "http://scanledger.test/api",
        "svc-token",
        transport=httpx.MockTransport(handler),  # type: ignore[arg-type]
    )
    monkeypatch.setattr("falcoria_tasker.scans.service.get_scanledger_client", lambda: client)


def _scanledger_handler(known: set[str], create_calls: list[list[dict[str, object]]]):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/ips/search"):
            body = json.loads(request.content)
            matched = set(body["filter"]["ip_in"]) & known
            items = [
                {"ip": ip, "first_seen": 0, "last_seen": 0, "hostnames": [], "ports": []}
                for ip in matched
            ]
            return httpx.Response(200, json={"items": items, "total": len(items)})
        assert request.url.path.endswith("/ips")
        create_calls.append(json.loads(request.content))
        return httpx.Response(201, json={"created": [], "updated": [], "unchanged": []})

    return handler


@dataclass
class _StartedBatch:
    project_id: UUID
    scan_id: str
    tasks: list[ScanTask]
    mode: ImportMode
    chunk_size: int


def _patch_workflows(
    monkeypatch: pytest.MonkeyPatch, already_running: set[str] | None = None
) -> list[_StartedBatch]:
    started: list[_StartedBatch] = []

    async def fake_already_running_ips(project_id: UUID, ips: list[str]) -> set[str]:
        return already_running or set()

    async def fake_start_batch_workflows(
        project_id: UUID, scan_id: str, tasks: list[ScanTask], mode: ImportMode, chunk_size: int
    ) -> None:
        started.append(_StartedBatch(project_id, scan_id, tasks, mode, chunk_size))

    monkeypatch.setattr(workflows_module, "already_running_ips", fake_already_running_ips)
    monkeypatch.setattr(workflows_module, "start_batch_workflows", fake_start_batch_workflows)
    return started


async def test_run_scan_insert_mode_merges_hostnames_for_known_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_settings(monkeypatch)
    create_calls: list[list[dict[str, object]]] = []
    _patch_scanledger(monkeypatch, _scanledger_handler({"9.9.9.1", "9.9.9.2"}, create_calls))
    started = _patch_workflows(monkeypatch, already_running={"9.9.9.2"})
    _patch_resolver(
        monkeypatch,
        {"known.example.com": [["9.9.9.1"]], "running.example.com": [["9.9.9.2"]]},
    )

    request = _request(["known.example.com", "running.example.com", "9.9.9.3"])

    response = await run_scan(PROJECT_ID, request)

    assert len(create_calls) == 1
    items = create_calls[0]
    assert len(items) == 1
    assert items[0]["ip"] == "9.9.9.1"
    assert items[0]["hostnames"] == ["known.example.com"]
    assert isinstance(items[0]["endtime"], int)

    assert len(started) == 1
    assert [t.ip for t in started[0].tasks] == ["9.9.9.3"]

    assert response.scan_id is not None
    assert response.summary.started == 1
    assert response.summary.skipped.already_known == 1
    assert response.summary.skipped.already_running == 1


async def test_run_scan_non_insert_mode_skips_dedup(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_settings(monkeypatch)

    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("scanledger should not be called outside INSERT mode")

    _patch_scanledger(monkeypatch, handler)
    started = _patch_workflows(monkeypatch)

    request = _request(["1.1.1.1"], mode=ImportMode.REPLACE, sharding=ShardingConfig(shard_count=2))

    response = await run_scan(PROJECT_ID, request)

    assert response.scan_id is not None
    assert len(started[0].tasks) == 2
    assert response.summary.skipped.already_known == 0
    assert response.summary.skipped.already_running == 0


async def test_run_scan_returns_no_scan_id_when_everything_is_skipped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_settings(monkeypatch)
    _patch_scanledger(monkeypatch, _scanledger_handler({"9.9.9.1"}, []))
    started = _patch_workflows(monkeypatch)

    request = _request(["9.9.9.1"])

    response = await run_scan(PROJECT_ID, request)

    assert response.scan_id is None
    assert started == []
    assert response.summary.started == 0


async def test_run_scan_reports_private_and_unresolvable(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_settings(monkeypatch)
    _patch_scanledger(monkeypatch, _scanledger_handler(set(), []))
    _patch_workflows(monkeypatch)
    _patch_resolver(monkeypatch, {"dead.example.com": aiodns.error.DNSError("nope")})

    request = _request(["10.0.0.5", "dead.example.com"], mode=ImportMode.REPLACE)

    response = await run_scan(PROJECT_ID, request)

    assert response.not_scanned.private_targets == {"10.0.0.5": []}
    assert response.not_scanned.unresolvable_hosts == ["dead.example.com"]
    assert response.summary.skipped.private_ip == 1
    assert response.summary.skipped.unresolvable == 1


# --- list_running_scans / get_scan_status ---


async def test_list_running_scans_wraps_and_sorts_scan_ids(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_list_running_scan_ids(project_id: UUID) -> set[str]:
        return {"b", "a"}

    monkeypatch.setattr(workflows_module, "list_running_scan_ids", fake_list_running_scan_ids)

    result = await list_running_scans(PROJECT_ID)

    assert result == ScanListResponse(running=2, scan_ids=["a", "b"])


async def test_get_scan_status_returns_none_for_an_unknown_scan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_scan_progress(project_id: UUID, scan_id: str) -> ScanBatchResult | None:
        return None

    async def fake_running_ips(project_id: UUID, scan_id: str) -> list[tuple[str, str]]:
        return []

    monkeypatch.setattr(workflows_module, "scan_progress", fake_scan_progress)
    monkeypatch.setattr(workflows_module, "running_ips", fake_running_ips)

    assert await get_scan_status(PROJECT_ID, "unknown") is None


async def test_get_scan_status_combines_progress_and_running_targets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_scan_progress(project_id: UUID, scan_id: str) -> ScanBatchResult | None:
        return ScanBatchResult(total=3, completed=1, failed=0)

    async def fake_running_ips(project_id: UUID, scan_id: str) -> list[tuple[str, str]]:
        return [("10.0.0.1", "worker-1")]

    monkeypatch.setattr(workflows_module, "scan_progress", fake_scan_progress)
    monkeypatch.setattr(workflows_module, "running_ips", fake_running_ips)

    status = await get_scan_status(PROJECT_ID, "scan-1")

    assert status == ScanStatusResponse(
        total=3,
        completed=1,
        failed=0,
        running_targets=[RunningTarget(ip="10.0.0.1", worker="worker-1")],
    )


# --- cancel_scan ---


def _patch_grace_period(monkeypatch: pytest.MonkeyPatch, seconds: float = 0) -> None:
    monkeypatch.setattr(
        "falcoria_tasker.scans.service.CANCEL_TERMINATE_WAIT", timedelta(seconds=seconds)
    )


async def test_cancel_scan_by_scan_id_cancels_batches_then_terminates_after_grace_period(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[UUID, str | None]] = []
    terminated: list[str] = []

    async def fake_cancel_running_batches(project_id: UUID, scan_id: str | None) -> list[str]:
        calls.append((project_id, scan_id))
        return ["wf-1"]

    async def fake_terminate_if_still_running(workflow_id: str) -> None:
        terminated.append(workflow_id)

    monkeypatch.setattr(workflows_module, "cancel_running_batches", fake_cancel_running_batches)
    monkeypatch.setattr(
        workflows_module, "terminate_if_still_running", fake_terminate_if_still_running
    )
    _patch_grace_period(monkeypatch)
    before = len(service_module._background_tasks)

    response = await cancel_scan(PROJECT_ID, CancelScanRequest(scan_id="scan-1"))

    assert calls == [(PROJECT_ID, "scan-1")]
    assert response.success is True
    assert len(service_module._background_tasks) == before + 1
    await asyncio.gather(*service_module._background_tasks)
    assert terminated == ["wf-1"]


async def test_cancel_scan_by_ips_cancels_matching_scan_workflows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[UUID, list[str]]] = []

    async def fake_cancel_running_scans_by_ips(project_id: UUID, ips: list[str]) -> list[str]:
        calls.append((project_id, ips))
        return []

    monkeypatch.setattr(
        workflows_module, "cancel_running_scans_by_ips", fake_cancel_running_scans_by_ips
    )

    await cancel_scan(PROJECT_ID, CancelScanRequest(ips=["10.0.0.1"]))

    assert calls == [(PROJECT_ID, ["10.0.0.1"])]


async def test_cancel_scan_with_neither_cancels_every_running_batch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[UUID, str | None]] = []

    async def fake_cancel_running_batches(project_id: UUID, scan_id: str | None) -> list[str]:
        calls.append((project_id, scan_id))
        return []

    monkeypatch.setattr(workflows_module, "cancel_running_batches", fake_cancel_running_batches)

    await cancel_scan(PROJECT_ID, CancelScanRequest())

    assert calls == [(PROJECT_ID, None)]


async def test_cancel_scan_schedules_no_background_task_when_nothing_was_running(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_cancel_running_batches(project_id: UUID, scan_id: str | None) -> list[str]:
        return []

    monkeypatch.setattr(workflows_module, "cancel_running_batches", fake_cancel_running_batches)
    before = len(service_module._background_tasks)

    await cancel_scan(PROJECT_ID, CancelScanRequest())

    assert len(service_module._background_tasks) == before
