"""Read model for the port-change history endpoints."""

import uuid

from pydantic import BaseModel

from falcoria_contracts.enums import PortChangeType, PortProtocol


class HistoryOut(BaseModel):
    """One recorded port change, as returned by ``GET .../history``."""

    id: int
    ip: str
    port: int
    protocol: PortProtocol
    change_type: PortChangeType
    old_value: str | None = None
    new_value: str | None = None
    observed_state: str | None = None
    reason: str | None = None
    scan_id: uuid.UUID | None = None
    created_at: int
