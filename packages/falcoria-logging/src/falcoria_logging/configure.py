"""Process-wide logging configuration: stdout only, JSON outside local, level from settings."""

import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any

_THIRD_PARTY_QUIET = ("httpx", "httpcore")
_THIRD_PARTY_LEVEL = logging.WARNING


class _JSONFormatter(logging.Formatter):
    """Renders one JSON object per record: timestamp, level, logger name, message, exception."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload)


def configure_logging(*, level: str, json_output: bool) -> None:
    """Configures the root logger: one stdout handler, given level, JSON or plain text.

    Idempotent — safe to call more than once (e.g. an app module re-imported under
    pytest); replaces the handler list instead of stacking duplicates. Raises
    ``ValueError`` immediately if `level` isn't a recognised logging level name.
    """
    numeric_level = logging.getLevelNamesMapping().get(level.upper())
    if numeric_level is None:
        raise ValueError(f"Unknown log level: {level!r}")

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        _JSONFormatter()
        if json_output
        else logging.Formatter("%(asctime)s %(levelname)-8s %(name)s: %(message)s")
    )
    root = logging.getLogger()
    root.setLevel(numeric_level)
    root.handlers = [handler]

    for name in _THIRD_PARTY_QUIET:
        logging.getLogger(name).setLevel(_THIRD_PARTY_LEVEL)
