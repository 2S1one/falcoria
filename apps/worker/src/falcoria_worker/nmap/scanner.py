"""Impure orchestration of one nmap scan: two passes merged into one XML report."""

import os
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Protocol

from falcoria_worker.nmap.xml import enrich_xml, parse_open_ports


class CommandExecutor(Protocol):
    """The subset of AsyncCommandExecutor's interface this module depends on."""

    async def run(
        self,
        command: list[str],
        *,
        timeout: float | None = None,
        heartbeat_fn: Callable[[], None] | None = None,
        heartbeat_interval: float = 10.0,
    ) -> None:
        """Runs `command` to completion."""
        ...


async def run_nmap_scan(
    executor: CommandExecutor,
    nmap_path: str,
    target: str,
    open_ports_args: str,
    service_args: str | None,
    timeout: int,
    hostnames: list[str],
    heartbeat_fn: Callable[[], None] | None = None,
    heartbeat_interval: float = 10.0,
) -> str:
    """Runs the open-ports pass, an optional service-detection pass, and merges them.

    The service-detection pass (when `service_args` is not None) runs only when
    the open-ports pass found at least one open port, restricted to those ports.
    Each pass gets the full `timeout` budget independently.
    """
    base_xml = await _run_nmap_pass(
        executor, nmap_path, open_ports_args, target, timeout, heartbeat_fn, heartbeat_interval
    )
    open_ports = parse_open_ports(base_xml)

    service_xml: str | None = None
    if service_args is not None and open_ports:
        port_str = ",".join(str(port) for port in open_ports)
        service_xml = await _run_nmap_pass(
            executor,
            nmap_path,
            f"-p {port_str} {service_args}",
            target,
            timeout,
            heartbeat_fn,
            heartbeat_interval,
        )

    return enrich_xml(base_xml, target, hostnames, service_xml)


async def _run_nmap_pass(
    executor: CommandExecutor,
    nmap_path: str,
    args: str,
    target: str,
    timeout: int,
    heartbeat_fn: Callable[[], None] | None,
    heartbeat_interval: float,
) -> str:
    """Runs one nmap pass to a temp file and returns its XML content."""
    fd, path_str = tempfile.mkstemp(suffix=".xml")
    os.close(fd)
    output_path = Path(path_str)
    try:
        command = [nmap_path, *args.split(), "-oX", str(output_path), target]
        await executor.run(
            command,
            timeout=timeout,
            heartbeat_fn=heartbeat_fn,
            heartbeat_interval=heartbeat_interval,
        )
        return output_path.read_text(encoding="utf-8")
    finally:
        output_path.unlink(missing_ok=True)
