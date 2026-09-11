"""Worker Temporal-client identity string: built by worker, parsed by tasker's fleet view."""

from pydantic import BaseModel


class WorkerIdentity(BaseModel):
    """The parsed pieces of a worker's Temporal client identity string."""

    pid: int | None
    hostname: str
    external_ip: str | None


def build_worker_identity(pid: int, hostname: str, external_ip: str) -> str:
    """Builds the identity string a worker passes to Client.connect(identity=...)."""
    return f"{pid}@{hostname}:{external_ip}"


def parse_worker_identity(identity: str) -> WorkerIdentity:
    """Parses a worker's pid@hostname:external_ip identity string.

    Degrades gracefully on a non-conforming string rather than raising: no "@"
    keeps the whole string as hostname with pid=None; no ":" in the remainder
    keeps external_ip=None.
    """
    pid_part, sep, rest = identity.partition("@")
    if not sep:
        return WorkerIdentity(pid=None, hostname=identity, external_ip=None)
    pid = int(pid_part) if pid_part.isdigit() else None
    hostname, sep, external_ip = rest.rpartition(":")
    if not sep:
        return WorkerIdentity(pid=pid, hostname=rest, external_ip=None)
    return WorkerIdentity(pid=pid, hostname=hostname, external_ip=external_ip or None)
