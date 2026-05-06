"""ASGI middleware: body size limiting + correlation-id error envelopes.

Two middlewares, both wired in server.py:

BodySizeLimitMiddleware
--------------------------------------
Caps inbound HTTP request body size at MAX_REQUEST_BODY_BYTES (50 MiB).
Returns 413 Request Entity Too Large with a curated JSON envelope
when the cap is exceeded. The check happens incrementally as the
ASGI body chunks arrive; we never buffer more than the cap. Requests
that under-report Content-Length and stream past the limit still
trip the cap because we keep a running total.

The 50 MiB ceiling is well above Gmail's 25 MiB attachment cap (the
single largest legitimate request shape) and below typical HTTP
proxy ceilings; it exists to bound an attacker's ability to exhaust
the service's memory by streaming an unbounded body. Pre-decode
attachment cap on send_email runs at a tighter 30 MiB boundary so a
50 MiB request body that happens to be one giant base64 attachment
fails gracefully via the tool layer rather than the middleware.

ErrorEnvelopeMiddleware
--------------------------------------
Generates a per-request `correlation_id` (uuid4 hex), exposes it on
`request.state.correlation_id`, and converts uncaught exceptions
into a 500 JSON envelope that includes the correlation_id but NOT
the exception message. Exception details land in the structured log
at WARNING with `exc_info=True` so operators can correlate the
client-visible 500 with a stack trace.

Why correlation_id
------------------
A medium-severity hardening change: the JSON-RPC -32603 path
previously included the
exception class name (`type(exc).__name__`) and the exception's str
representation in the JSON-RPC error message. The class name is
narrowly informative (`KeyError`, `ValueError`) but a future
exception introduced upstream could embed PII or token material in
its message. Pivoting to a correlation_id moves the burden of
detail onto the log destination (operator-only) and keeps the wire
response generic. The id is short (32 hex chars) and uniformly
random so it carries no information about the exception or actor.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp, Message, Receive, Scope, Send

logger = logging.getLogger(__name__)

# 50 MiB cap on inbound HTTP request bodies. Well above the 25 MiB
# Gmail attachment ceiling (the largest legitimate body shape); the
# 25 MiB delta accounts for base64 inflation and JSON envelope
# overhead.
MAX_REQUEST_BODY_BYTES = 50 * 1024 * 1024


class BodySizeLimitMiddleware:
    """ASGI middleware that 413s when an inbound body exceeds MAX_REQUEST_BODY_BYTES.

    We implement at the raw ASGI layer rather than via
    BaseHTTPMiddleware because BaseHTTPMiddleware buffers the entire
    body before yielding control to downstream handlers, defeating
    the streaming cap. Raw ASGI lets us count bytes as they arrive
    and short-circuit before the body is fully buffered.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Quick fail if Content-Length is set and obviously over.
        # The header is a hint, not a contract: an attacker can set
        # a small Content-Length and still stream more bytes, so the
        # streaming counter below is the real enforcement.
        for name, value in scope.get("headers", []):
            if name == b"content-length":
                try:
                    declared = int(value.decode("latin-1"))
                except (ValueError, UnicodeDecodeError):
                    declared = -1
                if declared > MAX_REQUEST_BODY_BYTES:
                    await self._send_413(send)
                    return
                break

        bytes_so_far = 0
        # 413-state guards: if we've already responded with 413, we
        # must drain the rest of the body without invoking the app
        # so the connection stays valid.
        triggered_limit = {"v": False}

        async def receive_wrapper() -> Message:
            nonlocal bytes_so_far
            message = await receive()
            if triggered_limit["v"]:
                return message
            if message["type"] == "http.request":
                body_chunk = message.get("body", b"") or b""
                bytes_so_far += len(body_chunk)
                if bytes_so_far > MAX_REQUEST_BODY_BYTES:
                    triggered_limit["v"] = True
                    # Return an EOF-shaped message so downstream
                    # handlers see a normal end-of-body. We send our
                    # own 413 below in a second send call.
                    return {"type": "http.request", "body": b"", "more_body": False}
            return message

        if triggered_limit["v"]:
            # Already over via header; we returned above.
            return  # pragma: no cover

        sent_response = {"v": False}

        async def send_wrapper(message: Message) -> None:
            if triggered_limit["v"] and not sent_response["v"]:
                # Replace whatever the app tried to send with our 413.
                sent_response["v"] = True
                await self._send_413(send)
                return
            if not triggered_limit["v"]:
                await send(message)

        await self.app(scope, receive_wrapper, send_wrapper)
        # If the body kept growing AFTER the app already responded,
        # we still need to send our 413 if no other response has gone
        # out. ASGI lets us send a response only once per request, so
        # if sent_response["v"] is True we already covered.
        if triggered_limit["v"] and not sent_response["v"]:
            await self._send_413(send)

    @staticmethod
    async def _send_413(send: Send) -> None:
        body = b'{"error":"request_too_large","detail":"request body exceeds the configured limit"}'
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("ascii")),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body, "more_body": False})


class ErrorEnvelopeMiddleware(BaseHTTPMiddleware):
    """Per-request correlation_id + generic 500 envelope.

    Sets `request.state.correlation_id` for downstream handlers (the
    JSON-RPC -32603 path uses it instead of leaking an exception
    string into the wire). Catches uncaught exceptions and turns
    them into 500 JSON responses without revealing details. Logs
    full traceback at WARNING with exc_info=True.
    """

    async def dispatch(self, request: Request, call_next: Any) -> Any:
        cid = uuid.uuid4().hex
        request.state.correlation_id = cid
        try:
            return await call_next(request)
        except Exception:
            logger.warning("Unhandled exception (correlation_id=%s)", cid, exc_info=True)
            return JSONResponse(
                status_code=500,
                content={
                    "error": "internal_error",
                    "correlation_id": cid,
                },
            )
