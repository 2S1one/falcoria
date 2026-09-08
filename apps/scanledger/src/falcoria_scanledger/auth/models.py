"""Identity table for API clients."""

import uuid
from datetime import datetime

from sqlalchemy import Column, DateTime
from sqlmodel import Field, SQLModel


class UserDB(SQLModel, table=True):
    """One API client identity and the bearer token it authenticates with.

    `hashed_token` is the SHA-256 hex digest of the plaintext token (the token
    itself is never stored). `token_expires_at` is UTC; ``None`` means the token
    does not expire.
    """

    # SQLAlchemy types __tablename__ as declared_attr; a plain str is correct here.
    __tablename__ = "users"  # pyright: ignore[reportAssignmentType]

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    username: str = Field(unique=True)
    is_admin: bool = False
    hashed_token: str | None = Field(default=None, unique=True)
    token_expires_at: datetime | None = Field(
        default=None, sa_column=Column(DateTime(timezone=True))
    )
