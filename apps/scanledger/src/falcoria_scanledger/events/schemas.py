"""IP state-change event: the payload stored in the outbox and served by the feed."""

import uuid
from collections.abc import Sequence
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from falcoria_contracts.enums import PortProtocol, ServiceMethod


class PortRef(BaseModel):
    """One port on the IP, identified by number and protocol."""

    model_config = ConfigDict(frozen=True)

    number: int = Field(ge=0, le=65535)
    protocol: PortProtocol


class PortDetail(PortRef):
    """An open port with the service fields a consumer needs to choose what to run.

    A deliberate subset of the stored port: raw fingerprints and script output
    stay behind the IP read API.
    """

    service: str | None = Field(default=None, description="Service name, e.g. 'http'.")
    service_method: ServiceMethod | None = Field(
        default=None,
        description="How the service was identified: probed, or guessed from the port number.",
    )
    product: str | None = Field(default=None, description="Service product, e.g. 'nginx'.")
    version: str | None = Field(default=None, description="Service version, e.g. '1.24.0'.")
    cpe: list[str] = Field(default_factory=list, description="Detected CPE identifiers.")
    tunnel: str | None = Field(default=None, description="Transport wrapper, e.g. 'ssl'.")


def _check_delta(
    old: Sequence[object],
    current: Sequence[object],
    added: Sequence[object],
    removed: Sequence[object],
) -> None:
    """Raises ValueError unless the four lists describe one consistent change.

    Each list has no duplicates, ``added`` holds only items that were not in
    ``old``, ``removed`` holds only items that were in ``old``, and ``current``
    is exactly ``old`` plus ``added`` minus ``removed``.
    """
    for name, items in (("old", old), ("current", current), ("added", added), ("removed", removed)):
        if len(set(items)) != len(items):
            raise ValueError(f"{name} contains duplicates")
    o, c, a, r = set(old), set(current), set(added), set(removed)
    if a & o:
        raise ValueError("added contains items already in old")
    if not r <= o:
        raise ValueError("removed contains items not in old")
    if c != (o | a) - r:
        raise ValueError("current is not old + added - removed")


def _ref(port: PortRef) -> PortRef:
    return PortRef.model_validate(port.model_dump())


class HostnameDelta(BaseModel):
    """Hostnames on the IP before and after the change, and the difference."""

    old: list[str] = Field(description="Hostnames before the change.")
    current: list[str] = Field(description="Hostnames after the change.")
    added: list[str] = Field(description="In current, not in old.")
    removed: list[str] = Field(description="In old, not in current.")

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        _check_delta(self.old, self.current, self.added, self.removed)
        return self


class PortDelta(BaseModel):
    """Open ports on the IP before and after the change, and the difference.

    Only ``current`` carries service details; the other lists identify ports by
    number and protocol. The consistency check compares identities only, so a
    service change on a port never reads as that port being removed and added.
    """

    old: list[PortRef] = Field(description="Open ports before the change.")
    current: list[PortDetail] = Field(description="Open ports after the change, with details.")
    added: list[PortRef] = Field(description="In current, not in old.")
    removed: list[PortRef] = Field(description="In old, not in current.")

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        # PortDetail holds a list (cpe), so it is unhashable; compare by identity.
        _check_delta(self.old, [_ref(p) for p in self.current], self.added, self.removed)
        return self


class ServiceChange(BaseModel):
    """A service field that changed on a port that stayed open."""

    number: int = Field(ge=0, le=65535)
    protocol: PortProtocol
    field: Literal["service", "product", "version"]
    old: str | None = Field(description="Value before the change; null when it was unset.")
    new: str | None = Field(description="Value the scan reported.")


class IPChangedEvent(BaseModel):
    """One IP's state change, as stored in the outbox and served by the event feed."""

    event_id: uuid.UUID = Field(description="Unique per event; consumers deduplicate on it.")
    project_id: uuid.UUID
    ip: str
    scan_id: uuid.UUID | None = Field(
        description="Scan campaign that produced the change; null for a manual upload."
    )
    observed_at: int = Field(description="Unix epoch seconds: the scan's end time.")
    hostnames: HostnameDelta
    ports: PortDelta
    service_changes: list[ServiceChange] = Field(default_factory=list)


class EventPage(BaseModel):
    """One page of the event feed."""

    items: list[IPChangedEvent]
    next_cursor: str = Field(
        description="Pass as `after` to get the next page; unchanged when the page is empty."
    )
