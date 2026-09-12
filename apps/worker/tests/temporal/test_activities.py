"""Tests for temporal/activities.py — ScanActivities."""

from typing import Any

import pytest
from temporalio.testing import ActivityEnvironment

from falcoria_contracts.enums import ImportMode
from falcoria_worker.temporal.activities import ScanActivities
from falcoria_worker.temporal.schemas import NmapWorkflowInput

pytestmark = pytest.mark.anyio


class _FakeScanledgerClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, ImportMode, str]] = []

    async def upload_report(
        self, project_id: str, scan_id: str, mode: ImportMode, xml: str
    ) -> dict[str, Any]:
        self.calls.append((project_id, scan_id, mode, xml))
        return {}


def _input(**overrides: Any) -> NmapWorkflowInput:
    defaults: dict[str, Any] = {
        "project_id": "proj-1",
        "scan_id": "scan-1",
        "ip": "10.0.0.1",
        "open_ports_args": "-p 80",
        "timeout": 30,
        "mode": ImportMode.INSERT,
        "hostnames": ["h"],
    }
    return NmapWorkflowInput(**{**defaults, **overrides})


async def test_upload_results_calls_scanledger_with_expected_args() -> None:
    scanledger = _FakeScanledgerClient()
    activities = ScanActivities(scanledger, "nmap", 5.0, 10.0)

    await ActivityEnvironment().run(activities.upload_results, _input(), "<xml/>")

    assert scanledger.calls == [("proj-1", "scan-1", ImportMode.INSERT, "<xml/>")]


async def test_nmap_scan_delegates_to_run_nmap_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    import falcoria_worker.temporal.activities as activities_module

    captured: dict[str, Any] = {}

    async def fake_run_nmap_scan(
        executor: object,
        nmap_path: str,
        target: str,
        open_ports_args: str,
        service_args: str | None,
        timeout: int,
        hostnames: list[str],
        **kwargs: Any,
    ) -> str:
        captured.update(
            nmap_path=nmap_path,
            target=target,
            open_ports_args=open_ports_args,
            service_args=service_args,
            timeout=timeout,
            hostnames=hostnames,
        )
        return "<xml/>"

    monkeypatch.setattr(activities_module, "run_nmap_scan", fake_run_nmap_scan)

    scanledger = _FakeScanledgerClient()
    activities = ScanActivities(scanledger, "/usr/bin/nmap", 5.0, 10.0)

    xml = await ActivityEnvironment().run(activities.nmap_scan, _input())

    assert xml == "<xml/>"
    assert captured["nmap_path"] == "/usr/bin/nmap"
    assert captured["target"] == "10.0.0.1"
    assert captured["hostnames"] == ["h"]
