"""Scan-orchestration pipeline: dedup/resolve/shard targets, then start the workflows."""

import asyncio
import logging
import random
import time
from collections.abc import Coroutine
from dataclasses import dataclass, field
from typing import Any
from uuid import UUID, uuid4

from temporalio.service import RPCError

from falcoria_contracts.enums import ImportMode, ScannerFormat
from falcoria_contracts.scan_io import ScanTask
from falcoria_tasker.config import get_app_settings
from falcoria_tasker.constants import (
    CANCEL_BATCH_SIZE,
    CANCEL_TERMINATE_WAIT,
    SCAN_BATCH_CHUNK_SIZE,
)
from falcoria_tasker.scanledger import ScanledgerClient, get_scanledger_client
from falcoria_tasker.scans.resolve import resolve_targets
from falcoria_tasker.scans.scanner_args import build_open_ports_args, build_service_args
from falcoria_tasker.scans.schemas import (
    NotScannedDetails,
    RunningTarget,
    RunScanRequest,
    RunScanResponse,
    ScanListResponse,
    ScanState,
    ScanStatusResponse,
    ScanSummary,
    SkippedCounts,
)
from falcoria_tasker.scans.sharding import shard_ports
from falcoria_tasker.scans.targets import partition_targets, remove_duplicates
from falcoria_tasker.temporal import workflows
from falcoria_tasker.temporal.visibility import (
    running_batch_by_scan_query,
    running_batch_query,
    running_scans_by_ips_query,
)

logger = logging.getLogger(__name__)

_SCANNER = ScannerFormat.NMAP  # the only scanner implemented so far

# Tracked references to fire-and-forget terminate-after-grace-period tasks, so
# they aren't garbage-collected mid-flight (a bare asyncio.create_task(...) with
# no other reference is a known footgun).
_background_tasks: set[asyncio.Task[None]] = set()


@dataclass(slots=True)
class PreparedTargets:
    """Deduped/resolved targets, ready for INSERT-mode dedup and task building."""

    deduped: list[str]
    public_ip_hostnames: dict[str, list[str]]
    private_ip_sources: dict[str, list[str]]
    unresolvable_hosts: list[str]


@dataclass(slots=True)
class InsertModeDedup:
    """Which candidate IPs scanledger already knows, or are running elsewhere."""

    already_known: set[str] = field(default_factory=set)
    already_running: set[str] = field(default_factory=set)

    @property
    def known_only(self) -> set[str]:
        """Known IPs that aren't also currently running (mergeable now)."""
        return self.already_known - self.already_running

    @property
    def skipped_ips(self) -> set[str]:
        """Every IP this scan will not start."""
        return self.already_known | self.already_running


def _merge_sources(*maps: dict[str, list[str]]) -> dict[str, list[str]]:
    """Unions IP -> source-list maps, deduping sources per IP, preserving order."""
    merged: dict[str, list[str]] = {}
    for m in maps:
        for ip, sources in m.items():
            bucket = merged.setdefault(ip, [])
            for source in sources:
                if source not in bucket:
                    bucket.append(source)
    return merged


def _shard_count(request: RunScanRequest) -> int:
    """Returns the port-shard count for request; always 1 in INSERT mode."""
    if request.mode is ImportMode.INSERT or request.sharding is None:
        return 1
    return request.sharding.shard_count


async def _prepare_targets(request: RunScanRequest, semaphore_limit: int) -> PreparedTargets:
    """Dedupes request's hosts, classifies them, and resolves any pending hostnames."""
    deduped = remove_duplicates(request.hosts)
    partition = partition_targets(deduped)
    resolved = await resolve_targets(
        partition.pending_hostnames, request.single_resolve, semaphore_limit
    )
    return PreparedTargets(
        deduped=deduped,
        public_ip_hostnames=_merge_sources(
            {ip: [] for ip in partition.public_ips}, resolved.public_ips
        ),
        private_ip_sources=_merge_sources(partition.private_ips, resolved.private_ips),
        unresolvable_hosts=resolved.unresolvable,
    )


async def _dedupe_insert_mode(
    project_id: UUID, candidates: list[str], scanledger: ScanledgerClient
) -> InsertModeDedup:
    """Read-only: which candidates scanledger already knows, or are already running."""
    if not candidates:
        return InsertModeDedup()
    already_known, already_running = await asyncio.gather(
        scanledger.search_ips(project_id, candidates),
        workflows.already_running_ips(project_id, candidates),
    )
    return InsertModeDedup(already_known, already_running)


async def _merge_known_hostnames(
    project_id: UUID,
    ips: set[str],
    public_ip_hostnames: dict[str, list[str]],
    scanledger: ScanledgerClient,
) -> None:
    """Pushes newly discovered hostnames for skipped-but-known IPs to scanledger.

    Only for IPs scanledger already has on record and that aren't running
    elsewhere right now - see refactor/known-risks.md for the already-running
    case, which is deliberately not covered here.
    """
    now = int(time.time())
    items = [
        {"ip": ip, "hostnames": public_ip_hostnames[ip], "endtime": now}
        for ip in sorted(ips)
        if public_ip_hostnames[ip]
    ]
    await scanledger.create_ips(project_id, items, ImportMode.INSERT)


def _build_tasks(to_scan: dict[str, list[str]], request: RunScanRequest) -> list[ScanTask]:
    """Builds one ScanTask per (IP, port-shard), shuffled for load spread."""
    service_args = (
        build_service_args(
            request.service_opts,
            _SCANNER,
            request.open_ports_opts.transport_protocol,
            request.open_ports_opts.scan_type,
        )
        if request.include_services
        else None
    )
    open_ports_args_per_shard = [
        build_open_ports_args(request.open_ports_opts.model_copy(update={"ports": shard}), _SCANNER)
        for shard in shard_ports(request.open_ports_opts.ports, _shard_count(request))
    ]
    tasks = [
        ScanTask(
            ip=ip,
            open_ports_args=open_ports_args,
            service_args=service_args,
            timeout=request.timeout,
            mode=request.mode,
            hostnames=hostnames,
        )
        for ip, hostnames in to_scan.items()
        for open_ports_args in open_ports_args_per_shard
    ]
    random.shuffle(tasks)
    return tasks


def _build_summary(
    request: RunScanRequest, prepared: PreparedTargets, dedup: InsertModeDedup, started: int
) -> ScanSummary:
    """Assembles the accounting summary from provided hosts down to started targets."""
    attached_hostnames = len(
        {hostname for hostnames in prepared.public_ip_hostnames.values() for hostname in hostnames}
    )
    return ScanSummary(
        provided=len(request.hosts),
        duplicates_removed=len(request.hosts) - len(prepared.deduped),
        target_ips=len(prepared.public_ip_hostnames),
        attached_hostnames=attached_hostnames,
        skipped=SkippedCounts(
            private_ip=len(prepared.private_ip_sources),
            unresolvable=len(prepared.unresolvable_hosts),
            already_known=len(dedup.known_only),
            already_running=len(dedup.already_running),
        ),
        started=started,
    )


def _build_not_scanned(prepared: PreparedTargets) -> NotScannedDetails:
    """Reports the private and unresolvable targets excluded from the scan."""
    return NotScannedDetails(
        private_targets=prepared.private_ip_sources, unresolvable_hosts=prepared.unresolvable_hosts
    )


async def run_scan(project_id: UUID, request: RunScanRequest) -> RunScanResponse:
    """Dedupes/resolves/shards request's hosts and starts one scan campaign.

    INSERT mode additionally skips IPs scanledger already knows or that are
    currently running under another scan in the project, and pushes any newly
    discovered hostname for a skipped-but-known IP to scanledger directly -
    its own scan is never (re-)run, so nothing else would record it.
    """
    settings = get_app_settings()
    scanledger = get_scanledger_client()

    prepared = await _prepare_targets(request, settings.dns_resolve_semaphore_limit)

    dedup = InsertModeDedup()
    if request.mode is ImportMode.INSERT:
        candidates = list(prepared.public_ip_hostnames)
        dedup = await _dedupe_insert_mode(project_id, candidates, scanledger)
        if dedup.known_only:
            await _merge_known_hostnames(
                project_id, dedup.known_only, prepared.public_ip_hostnames, scanledger
            )

    to_scan = {
        ip: hostnames
        for ip, hostnames in prepared.public_ip_hostnames.items()
        if ip not in dedup.skipped_ips
    }

    scan_id: str | None = None
    tasks = _build_tasks(to_scan, request)
    if tasks:
        scan_id = str(uuid4())
        await workflows.start_batch_workflows(
            project_id, scan_id, tasks, request.mode, SCAN_BATCH_CHUNK_SIZE
        )

    summary = _build_summary(request, prepared, dedup, started=len(to_scan))
    return RunScanResponse(
        scan_id=scan_id, summary=summary, not_scanned=_build_not_scanned(prepared)
    )


async def list_running_scans(project_id: UUID) -> ScanListResponse:
    """Lists the project's currently running scans."""
    scan_ids = await workflows.list_running_scan_ids(project_id)
    return ScanListResponse(running=len(scan_ids), scan_ids=sorted(scan_ids))


async def get_scan_status(project_id: UUID, scan_id: str) -> ScanStatusResponse | None:
    """Returns scan_id's task-completion counts, overall state, and running targets.

    Returns None if no batch workflow was ever started for scan_id.
    """
    settings = get_app_settings()
    progress, targets = await asyncio.gather(
        workflows.scan_progress(
            project_id,
            scan_id,
            settings.scan_progress_semaphore_limit,
            settings.scan_progress_query_timeout_seconds,
        ),
        workflows.running_ips(project_id, scan_id),
    )
    if progress is None:
        return None
    return ScanStatusResponse(
        total=progress.total,
        completed=progress.completed,
        failed=progress.failed,
        state=ScanState(progress.state.value),
        running_targets=[RunningTarget(ip=ip, worker=worker) for ip, worker in targets],
    )


async def cancel_batches(project_id: UUID, scan_id: str | None) -> None:
    """Signals a graceful cancel on every running batch workflow, optionally scoped to scan_id."""
    query = (
        running_batch_query(project_id)
        if scan_id is None
        else running_batch_by_scan_query(project_id, scan_id)
    )
    await workflows.start_cancel_batch(query)
    _run_in_background(_terminate_after_grace_period([query]))


async def cancel_by_ips(project_id: UUID, ips: list[str]) -> None:
    """Signals a graceful cancel on every running per-IP scan workflow matching ips.

    Always schedules the terminate-after-grace-period follow-up for every
    chunk, even if one chunk's cancel call failed - a chunk whose cancel
    never went out is still worth force-terminating once the grace period
    expires. Any cancel failure is still raised, for HTTP visibility.
    """
    unique_ips = sorted(set(ips))
    queries = [
        running_scans_by_ips_query(project_id, unique_ips[i : i + CANCEL_BATCH_SIZE])
        for i in range(0, len(unique_ips), CANCEL_BATCH_SIZE)
    ]
    results = await asyncio.gather(
        *(workflows.start_cancel_batch(q) for q in queries), return_exceptions=True
    )
    _run_in_background(_terminate_after_grace_period(queries))
    for result in results:
        if isinstance(result, BaseException):
            raise result


async def _terminate_after_grace_period(queries: list[str]) -> None:
    """Force-terminates, via batch operation, whatever still matches queries after the grace period."""
    await asyncio.sleep(CANCEL_TERMINATE_WAIT.total_seconds())
    for query in queries:
        try:
            await workflows.start_terminate_batch(query)
        except RPCError:
            logger.exception("Failed to start terminate batch operation for query: %s", query)


def _log_background_task_failure(task: asyncio.Task[None]) -> None:
    """Logs a background task's exception; a no-op on success or cancellation."""
    if task.cancelled():
        return
    exc = task.exception()
    if exc is not None:
        logger.error("Background task failed.", exc_info=exc)


def _run_in_background(coro: Coroutine[Any, Any, None]) -> None:
    """Fires coro as a background task, keeping a reference alive until it completes."""
    task = asyncio.create_task(coro)
    _background_tasks.add(task)
    task.add_done_callback(_log_background_task_failure)
    task.add_done_callback(_background_tasks.discard)
