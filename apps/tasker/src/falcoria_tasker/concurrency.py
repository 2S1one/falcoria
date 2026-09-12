"""Generic concurrency helpers shared across tasker."""

import asyncio
from collections.abc import Awaitable, Iterable


async def bounded_gather[T](coros: Iterable[Awaitable[T]], limit: int) -> list[T]:
    """Runs coros concurrently, capping in-flight execution at limit."""
    semaphore = asyncio.Semaphore(limit)

    async def _run(coro: Awaitable[T]) -> T:
        async with semaphore:
            return await coro

    return await asyncio.gather(*(_run(coro) for coro in coros))
