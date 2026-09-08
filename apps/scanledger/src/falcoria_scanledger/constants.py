"""Cross-cutting constants: values referenced from more than one package."""

from enum import Enum


class Tag(str, Enum):
    """OpenAPI tag groups; one per route package."""

    META = "meta"
    AUTH = "auth"
    PROJECTS = "projects"
    IPS = "ips"
    HISTORY = "history"
