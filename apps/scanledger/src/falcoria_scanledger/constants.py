"""Cross-cutting constants: values referenced from more than one package."""

from enum import Enum
from typing import Any

from fastapi import status


class Tag(str, Enum):
    """OpenAPI tag groups; one per route package."""

    META = "meta"
    AUTH = "auth"
    PROJECTS = "projects"
    IPS = "ips"
    HISTORY = "history"
    EVENTS = "events"


# OpenAPI `responses=` entries for any router mounted behind an auth dependency.
AUTH_RESPONSES: dict[int | str, dict[str, Any]] = {
    status.HTTP_401_UNAUTHORIZED: {"description": "Missing or invalid bearer token."},
    status.HTTP_403_FORBIDDEN: {"description": "Authenticated, but not permitted."},
}
