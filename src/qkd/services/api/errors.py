"""Map every error to {"error": {"code": ..., "message": ...}} with the right status code."""

from __future__ import annotations

from typing import Any, Optional

from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from qkd.services.api.models import ErrorDetail, ErrorResponse
from qkd.services.node import InvalidRequest, LaunchFailed, UnknownPeer
from qkd.services.peer_client import PeerError
from qkd.services.transfer_store import InvalidTransition, TransferExists, TransferNotFound


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


def error_response(status: int, code: str, message: str, details: Optional[list[dict[str, Any]]] = None) -> JSONResponse:
    body = ErrorResponse(error=ErrorDetail(code=code, message=message, details=details))
    return JSONResponse(status_code=status, content=jsonable_encoder(body, exclude_none=True))


# Domain exception -> (status, code). UnknownPeer maps to 422 because peer_id arrives in a
# request body; GET /peers/{peer_id} converts it to a 404 itself.
_DOMAIN_ERRORS: dict[type[Exception], tuple[int, str]] = {
    TransferNotFound: (404, "transfer_not_found"),
    UnknownPeer: (422, "unknown_peer"),
    InvalidTransition: (409, "invalid_transition"),
    TransferExists: (409, "transfer_exists"),
    InvalidRequest: (422, "invalid_request"),
    PeerError: (502, "peer_unreachable"),
    LaunchFailed: (500, "launch_failed"),
}

_HTTP_CODES = {404: "not_found", 405: "method_not_allowed", 400: "bad_request"}

ERROR_RESPONSES: dict[int | str, dict[str, Any]] = {
    status: {"model": ErrorResponse, "description": description}
    for status, description in {
        404: "Unknown id",
        409: "Invalid state transition or duplicate id",
        422: "Validation error",
        502: "The peer node could not be reached",
    }.items()
}


def _domain_message(exc: Exception) -> str:
    if isinstance(exc, TransferNotFound):
        return f"No transfer with id '{exc.args[0]}'"
    if isinstance(exc, UnknownPeer):
        return f"No discovered peer with id '{exc.args[0]}'"
    if isinstance(exc, TransferExists):
        return f"A transfer with id '{exc.args[0]}' already exists"
    return str(exc)


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(ApiError)
    async def _api_error(_: Request, exc: ApiError) -> JSONResponse:
        return error_response(exc.status, exc.code, exc.message)

    @app.exception_handler(RequestValidationError)
    async def _validation(_: Request, exc: RequestValidationError) -> JSONResponse:
        details = [{"loc": list(e.get("loc", ())), "msg": e.get("msg", ""), "type": e.get("type", "")} for e in exc.errors()]
        first = details[0] if details else {"loc": [], "msg": "Invalid request"}
        where = ".".join(str(p) for p in first["loc"] if p not in ("body", "query", "path"))
        return error_response(422, "validation_error", f"{where}: {first['msg']}" if where else first["msg"], details)

    @app.exception_handler(StarletteHTTPException)
    async def _http(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        return error_response(exc.status_code, _HTTP_CODES.get(exc.status_code, "http_error"), str(exc.detail))

    for exc_type, (status, code) in _DOMAIN_ERRORS.items():
        def handler(_: Request, exc: Exception, status: int = status, code: str = code) -> JSONResponse:
            return error_response(status, code, _domain_message(exc))
        app.add_exception_handler(exc_type, handler)
