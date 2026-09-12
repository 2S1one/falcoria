"""Tests for nmap/executor.py — real subprocess lifecycle, not mocked.

Uses trivial shell commands (not nmap) — AsyncCommandExecutor is scanner-neutral
and its subprocess/signal-handling behavior is best verified against real
processes rather than a mocked event loop.
"""

import asyncio

import pytest

from falcoria_worker.exceptions import CommandExecutionError, CommandTimeoutError
from falcoria_worker.nmap.executor import AsyncCommandExecutor

pytestmark = pytest.mark.anyio


async def test_run_succeeds_on_zero_exit() -> None:
    await AsyncCommandExecutor().run(["true"])


async def test_run_raises_on_nonzero_exit() -> None:
    with pytest.raises(CommandExecutionError):
        await AsyncCommandExecutor().run(["false"])


async def test_run_includes_stderr_in_the_error() -> None:
    with pytest.raises(CommandExecutionError, match="boom"):
        await AsyncCommandExecutor().run(["sh", "-c", "echo boom >&2; exit 1"])


async def test_run_calls_heartbeat_fn_periodically() -> None:
    calls = 0

    def heartbeat() -> None:
        nonlocal calls
        calls += 1

    await AsyncCommandExecutor().run(
        ["sleep", "0.3"], heartbeat_fn=heartbeat, heartbeat_interval=0.1
    )
    assert calls >= 2


async def test_run_raises_command_timeout_error_on_timeout() -> None:
    executor = AsyncCommandExecutor(grace_period_seconds=0.2)
    with pytest.raises(CommandTimeoutError):
        await executor.run(["sleep", "5"], timeout=0.1)


async def test_run_kills_process_that_ignores_sigterm() -> None:
    executor = AsyncCommandExecutor(grace_period_seconds=0.2)
    with pytest.raises(CommandTimeoutError):
        await executor.run(["sh", "-c", "trap '' TERM; sleep 5"], timeout=0.1)


async def test_run_propagates_cancellation() -> None:
    task = asyncio.ensure_future(AsyncCommandExecutor().run(["sleep", "5"]))
    await asyncio.sleep(0.05)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
