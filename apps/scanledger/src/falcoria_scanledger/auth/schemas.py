"""Request and response payloads for the identity API."""

from pydantic import BaseModel, Field


class UserCreate(BaseModel):
    """Fields an admin supplies to create a new API user."""

    username: str = Field(min_length=3, max_length=64, pattern=r"^[a-zA-Z0-9_-]+$")
    is_admin: bool = False
    token_lifetime: int | None = Field(
        default=None,
        gt=0,
        description="Token lifetime in seconds; omit for a token that never expires.",
    )
