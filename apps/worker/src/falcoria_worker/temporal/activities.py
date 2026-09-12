"""Activity implementations: nmap execution and scanledger upload.

Executes outside Temporal's workflow sandbox — free to use httpx, tempfile,
subprocess, and other impure dependencies the sandbox would otherwise restrict.
Never imported from `workflows.py`; referenced there by the string names in
`activity_names.py` instead, so those impure imports stay out of the
workflow-defining module's sandboxed import graph.
"""

import asyncio
from typing import Any, Protocol

from temporalio import activity

from falcoria_contracts.enums import ImportMode
from falcoria_worker.nmap.executor import AsyncCommandExecutor
from falcoria_worker.nmap.scanner import run_nmap_scan
from falcoria_worker.temporal.activity_names import NMAP_SCAN_ACTIVITY, UPLOAD_RESULTS_ACTIVITY
from falcoria_worker.temporal.schemas import NmapWorkflowInput


class ScanledgerUploader(Protocol):
    """The subset of ScanledgerClient's interface the upload_results activity depends on."""

    async def upload_report(
        self, project_id: str, scan_id: str, mode: ImportMode, xml: str
    ) -> dict[str, Any]:
        """Uploads an nmap XML report for `project_id`, tagged with `scan_id`."""
        ...


class ScanActivities:
    """Holds the shared executor settings and scanledger client the activities run against."""

    def __init__(
        self,
        scanledger: ScanledgerUploader,
        nmap_path: str,
        command_grace_period_seconds: float,
        heartbeat_interval_seconds: float,
    ) -> None:
        self._scanledger = scanledger
        self._nmap_path = nmap_path
        self._command_grace_period_seconds = command_grace_period_seconds
        self._heartbeat_interval_seconds = heartbeat_interval_seconds

    @activity.defn(name=NMAP_SCAN_ACTIVITY)
    async def nmap_scan(self, input: NmapWorkflowInput) -> str:
        """Runs the two-phase nmap scan for one IP and returns the merged XML."""
        executor = AsyncCommandExecutor(grace_period_seconds=self._command_grace_period_seconds)
        activity.logger.info("Starting scan | ip=%s scan=%s", input.ip, input.scan_id)
        try:
            xml = await run_nmap_scan(
                executor,
                self._nmap_path,
                input.ip,
                input.open_ports_args,
                input.service_args,
                input.timeout,
                input.hostnames,
                heartbeat_fn=activity.heartbeat,
                heartbeat_interval=self._heartbeat_interval_seconds,
            )
        except asyncio.CancelledError:
            activity.logger.info("Scan cancelled | ip=%s", input.ip)
            raise
        activity.logger.info("Scan complete | ip=%s", input.ip)
        return xml

    @activity.defn(name=UPLOAD_RESULTS_ACTIVITY)
    async def upload_results(self, input: NmapWorkflowInput, xml: str) -> None:
        """Uploads one IP's merged scan XML to scanledger."""
        await self._scanledger.upload_report(input.project_id, input.scan_id, input.mode, xml)
