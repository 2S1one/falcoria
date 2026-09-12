"""Tests for nmap/scanner.py — two-phase orchestration, with a fake executor."""

from collections.abc import Callable
from pathlib import Path

import pytest

from falcoria_worker.nmap.scanner import run_nmap_scan

pytestmark = pytest.mark.anyio

_BASE_XML = """<?xml version="1.0"?>
<nmaprun><host>
  <address addr="10.0.0.1" addrtype="ipv4"/>
  <ports><port protocol="tcp" portid="80"><state state="open"/></port></ports>
</host></nmaprun>
"""

_SERVICE_XML = """<?xml version="1.0"?>
<nmaprun><host>
  <address addr="10.0.0.1" addrtype="ipv4"/>
  <ports>
    <port protocol="tcp" portid="80">
      <state state="open"/>
      <service name="http"/>
    </port>
  </ports>
</host></nmaprun>
"""

_EMPTY_XML = """<?xml version="1.0"?>
<nmaprun><host><address addr="10.0.0.1" addrtype="ipv4"/><ports/></host></nmaprun>
"""


class _FakeExecutor:
    """Writes canned XML to the `-oX <path>` argument instead of running nmap."""

    def __init__(self, outputs: list[str]) -> None:
        self._outputs = outputs
        self.commands: list[list[str]] = []

    async def run(
        self,
        command: list[str],
        *,
        timeout: float | None = None,
        heartbeat_fn: Callable[[], None] | None = None,
        heartbeat_interval: float = 10.0,
    ) -> None:
        self.commands.append(command)
        output_path = Path(command[command.index("-oX") + 1])
        output_path.write_text(self._outputs.pop(0), encoding="utf-8")


async def test_skips_service_phase_when_service_args_is_none() -> None:
    executor = _FakeExecutor([_BASE_XML])

    xml = await run_nmap_scan(executor, "nmap", "10.0.0.1", "-p 1-1000", None, 30, [])

    assert len(executor.commands) == 1
    assert "<service" not in xml


async def test_skips_service_phase_when_no_open_ports() -> None:
    executor = _FakeExecutor([_EMPTY_XML])

    xml = await run_nmap_scan(executor, "nmap", "10.0.0.1", "-p 1-1000", "-sV", 30, [])

    assert len(executor.commands) == 1
    assert "<service" not in xml


async def test_runs_service_phase_restricted_to_open_ports() -> None:
    executor = _FakeExecutor([_BASE_XML, _SERVICE_XML])

    xml = await run_nmap_scan(executor, "nmap", "10.0.0.1", "-p 1-1000", "-sV", 30, [])

    assert len(executor.commands) == 2
    assert "-p" in executor.commands[1]
    assert "80" in " ".join(executor.commands[1])
    assert '<service name="http"' in xml


async def test_builds_expected_command_shape() -> None:
    executor = _FakeExecutor([_BASE_XML])

    await run_nmap_scan(executor, "/usr/bin/nmap", "10.0.0.1", "-p 80", None, 30, [])

    command = executor.commands[0]
    assert command[0] == "/usr/bin/nmap"
    assert command[-1] == "10.0.0.1"
    assert "-oX" in command


async def test_cleans_up_temp_files() -> None:
    executor = _FakeExecutor([_BASE_XML])

    await run_nmap_scan(executor, "nmap", "10.0.0.1", "-p 80", None, 30, [])

    output_path = Path(executor.commands[0][executor.commands[0].index("-oX") + 1])
    assert not output_path.exists()


async def test_merges_hostnames_into_result() -> None:
    executor = _FakeExecutor([_BASE_XML])

    xml = await run_nmap_scan(executor, "nmap", "10.0.0.1", "-p 80", None, 30, ["example.com"])

    assert 'name="example.com"' in xml
