"""Bearer-token primitives: generation, hashing, and expiry. No I/O."""

import hashlib
import secrets
import string
from datetime import UTC, datetime, timedelta
from typing import Final

_TOKEN_ALPHABET: Final = string.ascii_letters + string.digits  # base62
_TOKEN_LENGTH: Final = 60


def generate_token(length: int = _TOKEN_LENGTH) -> str:
    """Returns a fresh random token of `length` base62 characters."""
    return "".join(secrets.choice(_TOKEN_ALPHABET) for _ in range(length))


def hash_token(plaintext: str) -> str:
    """Returns the SHA-256 hex digest used to store and look a token up.

    A 60-char base62 token carries ~357 bits of entropy, so an unsalted
    single-round digest is sufficient and intentionally fast — this is not a
    password hash.
    """
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


def expiry_from(lifetime_seconds: int | None, *, now: datetime | None = None) -> datetime | None:
    """Returns the UTC instant `lifetime_seconds` ahead of now, or None for no expiry."""
    if lifetime_seconds is None:
        return None
    return (now or datetime.now(UTC)) + timedelta(seconds=lifetime_seconds)


def is_expired(expires_at: datetime | None, *, now: datetime | None = None) -> bool:
    """True when `expires_at` is at or before now; None means no expiry, never expired."""
    if expires_at is None:
        return False
    return (now or datetime.now(UTC)) >= expires_at
