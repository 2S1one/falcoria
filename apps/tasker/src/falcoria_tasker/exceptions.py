"""Application HTTP exception base classes and the exception-handler registration."""

import logging

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from falcoria_tasker.config import Env, get_app_settings

logger = logging.getLogger(__name__)


class DetailedHTTPException(HTTPException):
    """Base for the application's HTTP errors; subclasses set `STATUS_CODE` and `DETAIL`."""

    STATUS_CODE = status.HTTP_500_INTERNAL_SERVER_ERROR
    DETAIL = "Server error."

    def __init__(self, detail: str | None = None, headers: dict[str, str] | None = None) -> None:
        super().__init__(
            status_code=self.STATUS_CODE, detail=detail or self.DETAIL, headers=headers
        )


class BadRequest(DetailedHTTPException):
    """Raised when the request is malformed or violates a precondition."""

    STATUS_CODE = status.HTTP_400_BAD_REQUEST
    DETAIL = "Bad request."


class Unauthorized(DetailedHTTPException):
    """Raised when authentication is missing or invalid."""

    STATUS_CODE = status.HTTP_401_UNAUTHORIZED
    DETAIL = "Not authenticated."


class PermissionDenied(DetailedHTTPException):
    """Raised when the caller is authenticated but not allowed to act."""

    STATUS_CODE = status.HTTP_403_FORBIDDEN
    DETAIL = "Permission denied."


class NotFound(DetailedHTTPException):
    """Raised when the requested resource does not exist."""

    STATUS_CODE = status.HTTP_404_NOT_FOUND
    DETAIL = "Not found."


class Conflict(DetailedHTTPException):
    """Raised when the request conflicts with the current resource state."""

    STATUS_CODE = status.HTTP_409_CONFLICT
    DETAIL = "Conflict."


class ServiceUnavailable(DetailedHTTPException):
    """Raised when a dependency (scanledger, Temporal) is unreachable or times out."""

    STATUS_CODE = status.HTTP_503_SERVICE_UNAVAILABLE
    DETAIL = "Service unavailable."


def _expose_internal_errors() -> bool:
    """True outside production, where a 500's `str(exc)` is returned to the client too."""
    return get_app_settings().env is not Env.PROD


def register_exception_handlers(app: FastAPI) -> None:
    """Attaches the validation-error and catch-all handlers to `app`.

    Deliberate `HTTPException`s keep FastAPI's default rendering — their messages
    are safe by construction. A 422 always carries the field errors. An unhandled
    exception is always logged; its text reaches the client only outside production.
    """

    @app.exception_handler(RequestValidationError)
    async def _on_validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            content=jsonable_encoder({"detail": exc.errors()}),
        )

    @app.exception_handler(Exception)
    async def _on_unhandled_error(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("Unhandled error on %s %s", request.method, request.url.path)
        detail = str(exc) if _expose_internal_errors() else "Internal server error."
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": detail},
        )
