"""Request and response payloads for the identity API."""

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

_LIFETIME_DESCRIPTION = "Token lifetime in seconds; omit for a token that never expires."


class UserCreate(BaseModel):
    """Fields an admin supplies to create a new API user."""

    username: str = Field(min_length=3, max_length=64, pattern=r"^[a-zA-Z0-9_-]+$")
    is_admin: bool = False
    token_lifetime: int | None = Field(default=None, gt=0, description=_LIFETIME_DESCRIPTION)


class TokenRequest(BaseModel):
    """Options for issuing a fresh bearer token for an existing user."""

    token_lifetime: int | None = Field(default=None, gt=0, description=_LIFETIME_DESCRIPTION)


class UserOut(BaseModel):
    """A user as returned by the identity API — no token material."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    username: str
    is_admin: bool
    token_expires_at: datetime | None


class TokenOut(BaseModel):
    """The plaintext bearer token, returned once when it is issued."""

    token: str
