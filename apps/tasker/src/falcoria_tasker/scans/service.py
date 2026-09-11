"""Scan-orchestration pipeline: dedup/resolve/shard targets, then start the workflows."""

import asyncio
import logging
import random
import time
from dataclasses import dataclass, field
from uuid import UUID, uuid4

from temporalio.service import RPCError

from falcoria_contracts.enums import ImportMode, ScannerFormat
from falcoria_contracts.scan_io import ScanTask
from falcoria_tasker.config import get_app_settings
from falcoria_tasker.constants import CANCEL_TERMINATE_WAIT, SCAN_BATCH_CHUNK_SIZE
from falcoria_tasker.scanledger import ScanledgerClient, get_scanledger_client
from falcoria_tasker.scans.resolve import resolve_targets
from falcoria_tasker.scans.scanner_args import build_open_ports_args, build_service_args
from falcoria_tasker.scans.schemas import (
    CancelScanRequest,
    CancelScanResponse,
    NotScannedDetails,
    RunningTarget,
    RunScanRequest,
    RunScanResponse,
    ScanListResponse,
    ScanStatusResponse,
    ScanSummary,
    SkippedCounts,
)
from falcoria_tasker.scans.sharding import shard_ports
from falcoria_tasker.scans.targets import partition_targets, remove_duplicates
from falcoria_tasker.temporal import workflows

logger = logging.getLogger("falcoria_tasker")

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
    pending_hostname_count: int
    resolved_new_ip_count: int


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
        pending_hostname_count=len(partition.pending_hostnames),
        resolved_new_ip_count=len(resolved.public_ips) + len(resolved.private_ips),
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
            request.service_opts, _SCANNER, request.open_ports_opts.transport_protocol
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
    resolved_hostname_count = prepared.pending_hostname_count - len(prepared.unresolvable_hosts)
    hostnames_collapsed_to_ip = max(0, resolved_hostname_count - prepared.resolved_new_ip_count)
    return ScanSummary(
        provided=len(request.hosts),
        duplicates_removed=len(request.hosts) - len(prepared.deduped),
        resolved_ips=len(prepared.public_ip_hostnames),
        hostnames_collapsed_to_ip=hostnames_collapsed_to_ip,
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
    """Returns scan_id's task-completion counts and running targets.

    Returns None if no batch workflow was ever started for scan_id.
    """
    progress, targets = await asyncio.gather(
        workflows.scan_progress(project_id, scan_id),
        workflows.running_ips(project_id, scan_id),
    )
    if progress is None:
        return None
    return ScanStatusResponse(
        total=progress.total,
        completed=progress.completed,
        failed=progress.failed,
        running_targets=[RunningTarget(ip=ip, worker=worker) for ip, worker in targets],
    )


async def _terminate_after_grace_period(workflow_ids: list[str]) -> None:
    """Force-terminates any of workflow_ids still running after the cancel grace period."""
    await asyncio.sleep(CANCEL_TERMINATE_WAIT.total_seconds())
    for workflow_id in workflow_ids:
        try:
            await workflows.terminate_if_still_running(workflow_id)
        except RPCError:
            logger.exception("Failed to terminate workflow %s after cancel.", workflow_id)


def _schedule_terminate_if_running(workflow_ids: list[str]) -> None:
    """Fires the terminate-after-grace-period task, keeping a reference alive."""
    task = asyncio.create_task(_terminate_after_grace_period(workflow_ids))
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)


async def cancel_scan(project_id: UUID, request: CancelScanRequest) -> CancelScanResponse:
    """Signals a graceful cancel, then force-terminates anything still running after a grace period.

    scan_id cancels that scan's batch workflows; ips cancels the matching
    per-IP scan workflows directly (finer-grained than a whole batch); neither
    cancels every running scan in the project.
    """
    if request.scan_id:
        workflow_ids = await workflows.cancel_running_batches(project_id, request.scan_id)
    elif request.ips:
        workflow_ids = await workflows.cancel_running_scans_by_ips(project_id, request.ips)
    else:
        workflow_ids = await workflows.cancel_running_batches(project_id, None)

    if workflow_ids:
        _schedule_terminate_if_running(workflow_ids)
    return CancelScanResponse()
