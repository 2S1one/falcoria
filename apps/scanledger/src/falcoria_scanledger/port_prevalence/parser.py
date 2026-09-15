"""Parse nmap's `nmap-services` port-frequency reference file."""

from collections.abc import Iterable

from pydantic import BaseModel

from falcoria_contracts.enums import PortProtocol

_SUPPORTED_PROTOCOLS = {p.value for p in PortProtocol}


class ParsedPortPrevalence(BaseModel):
    """One port/protocol pair and its observed open frequency, before storage."""

    number: int
    protocol: PortProtocol
    score: float


def parse_nmap_services(lines: Iterable[str]) -> list[ParsedPortPrevalence]:
    """Returns one entry per data line in an `nmap-services` file.

    Skips comment lines (`#`), blank lines, and protocols this system doesn't
    track (e.g. `sctp`) — `PortProtocol` only models `tcp`/`udp`.
    """
    entries = []
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split(maxsplit=3)
        if len(fields) < 3:
            continue
        _, port_proto, score = fields[0], fields[1], fields[2]
        number, _, protocol = port_proto.partition("/")
        if protocol not in _SUPPORTED_PROTOCOLS:
            continue
        entries.append(
            ParsedPortPrevalence(
                number=int(number), protocol=PortProtocol(protocol), score=float(score)
            )
        )
    return entries
