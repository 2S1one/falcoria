"""Request and response payloads for the projects API."""

import uuid

from pydantic import BaseModel, ConfigDict, Field

_NAME_PATTERN = r"^[a-zA-Z0-9_-]+$"
_COMMENT_MAX_LENGTH = 2000


class ProjectCreate(BaseModel):
    """Fields supplied to create a new project."""

    name: str = Field(min_length=1, max_length=30, pattern=_NAME_PATTERN)
    comment: str | None = Field(default=None, max_length=_COMMENT_MAX_LENGTH)


class ProjectUpdate(BaseModel):
    """Mutable project fields; `name` cannot be changed after creation."""

    comment: str | None = Field(default=None, max_length=_COMMENT_MAX_LENGTH)


class ProjectOut(BaseModel):
    """A project as returned by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    comment: str | None


class MemberAdd(BaseModel):
    """Identifies the user to grant project access to."""

    user_id: uuid.UUID


class MemberOut(BaseModel):
    """A project member — identity fields only, no token material."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    username: str
    is_admin: bool
