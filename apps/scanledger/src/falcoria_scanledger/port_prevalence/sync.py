"""Sync `port_prevalence` from the vendored nmap-services reference file."""

import asyncio
import logging
from collections.abc import Sequence
from pathlib import Path

from falcoria_logging import configure_logging
from sqlmodel import delete
from sqlmodel.ext.asyncio.session import AsyncSession

from falcoria_scanledger.database import get_sessionmaker
from falcoria_scanledger.port_prevalence.models import PortPrevalenceDB
from falcoria_scanledger.port_prevalence.parser import ParsedPortPrevalence, parse_nmap_services

logger = logging.getLogger(__name__)

_DATA_FILE = Path(__file__).parent / "data" / "nmap-services"


async def sync_port_prevalence(
    session: AsyncSession, entries: Sequence[ParsedPortPrevalence]
) -> int:
    """Replaces `port_prevalence`'s rows with `entries`; returns the count inserted.

    Runs as delete-all then bulk-insert in the caller's transaction: `nmap-services`
    ships as a full replacement on every release, not an incremental diff, and
    nothing holds a foreign key into this table.

    Raises:
        ValueError: `entries` is empty — refuses to leave the table empty from a
            truncated or unparseable source file.
    """
    if not entries:
        raise ValueError("refusing to sync port_prevalence from zero parsed entries")
    connection = await session.connection()
    await connection.execute(delete(PortPrevalenceDB))
    session.add_all(
        PortPrevalenceDB(number=e.number, protocol=e.protocol, score=e.score) for e in entries
    )
    await session.flush()
    return len(entries)


async def _run() -> None:
    configure_logging(level="INFO", json_output=False)
    if not _DATA_FILE.exists():
        raise FileNotFoundError(f"vendored nmap-services file not found: {_DATA_FILE}")

    lines = _DATA_FILE.read_text(encoding="utf-8").splitlines()
    entries = parse_nmap_services(lines)
    logger.info(
        "parsed %d port-prevalence entries from %s (%d lines read)",
        len(entries),
        _DATA_FILE,
        len(lines),
    )

    async with get_sessionmaker()() as session:
        count = await sync_port_prevalence(session, entries)
        await session.commit()
    logger.info("synced %d rows into port_prevalence", count)


def main() -> None:
    """Entry point for `python -m falcoria_scanledger.port_prevalence.sync`."""
    asyncio.run(_run())


if __name__ == "__main__":
    main()
