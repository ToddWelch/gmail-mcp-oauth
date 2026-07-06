"""POST /attachments/upload: receive raw file bytes for an upload slot.

Second leg of the upload-slot + handle flow (see attachment_upload_store).
The client (Claude Code on the VPS) curls the exact file bytes here,
authenticating with the single-use capability token minted by
create_attachment_upload_slot. The server RECEIVES the bytes; it never
fetches a path or URL, so there is no SSRF / LFI surface.

Auth model
----------
The capability token ONLY. There is deliberately no Auth0 bearer: the
VPS `curl` cannot easily carry the user's bearer, which is the entire
reason the session-minted token exists. The token is 256-bit,
single-use, TTL-bound, and user-bound; the server stores only its
SHA-256, resolves the owning (auth0_sub, account_email) FROM the row,
and files the bytes under that owner.

Token transport
---------------
The token travels in the `X-Upload-Token` request header, never in the
path or query string. uvicorn's access log records the request line
(method + path + query) but not arbitrary headers, and the existing
AccessLogQueryStringScrubber only scrubs `/oauth*` query strings, so a
token in the path or query WOULD be logged. A header keeps it out of
logs entirely. This module logs no header values.

Ordering (token before body)
-----------------------------
1. Require the header (401) with NO body read.
2. Hash + PK lookup + classify -> 404 / 410 / 409 with NO body read.
3. The endpoint's OWN Content-Length > 25 MiB -> 413 with NO body read.
   The outer BodySizeLimitMiddleware (50 MiB) does not bound this
   endpoint to 25 MiB, so the tighter cap is enforced here.
4. Only then stream the body, counting bytes so a lying/absent
   Content-Length cannot exceed the cap; the overflow is caught here
   and returned as 413 (never allowed to propagate to a generic 500).
"""

from __future__ import annotations

import logging
from typing import AsyncIterator
from urllib.parse import unquote

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from . import attachment_upload_store as store
from .crypto import encrypt_bytes
from .db import session_scope
from .gmail_tools.attachment_source import is_safe_filename, is_safe_mime

logger = logging.getLogger(__name__)

router = APIRouter()

_TOKEN_HEADER = "X-Upload-Token"
_FILENAME_HEADER = "X-Attachment-Filename"

# STATUS_* -> (http_status, error_code) for the pre-body reject.
_STATUS_HTTP = {
    store.STATUS_NOT_FOUND: (404, "upload_slot_not_found"),
    store.STATUS_EXPIRED: (410, "upload_slot_expired"),
    store.STATUS_CONSUMED: (410, "upload_slot_consumed"),
    store.STATUS_ALREADY_UPLOADED: (409, "upload_slot_already_uploaded"),
}


class _UploadTooLarge(Exception):
    """Streaming body exceeded MAX_UPLOAD_BYTES."""


async def _read_body_capped(stream: AsyncIterator[bytes], max_bytes: int) -> bytearray:
    """Accumulate the streamed body, raising _UploadTooLarge past the cap.

    Enforces the byte count as chunks arrive so an absent or understated
    Content-Length cannot blow memory: the running total is the real
    guard, checked after every chunk.
    """
    buf = bytearray()
    async for chunk in stream:
        buf += chunk
        if len(buf) > max_bytes:
            raise _UploadTooLarge()
    return buf


def _err(status: int, code: str) -> JSONResponse:
    return JSONResponse({"error": code}, status_code=status)


@router.post("/attachments/upload")
async def upload_attachment(request: Request) -> Response:
    settings = request.app.state.settings

    # (1) Require the capability token header before touching the body.
    token = request.headers.get(_TOKEN_HEADER)
    if not token:
        return _err(401, "missing_upload_token")
    token_hash = store.hash_token(token)

    # (2) Classify by hash with NO body read. Capture the owner so the
    # per-user byte cap can be checked after the body streams in.
    with session_scope() as session:
        row = store.find_slot(session, token_hash)
        status = store.classify_slot(row)
        owner_sub = row.auth0_sub if row is not None else None
    if status != store.STATUS_OK:
        http_status, code = _STATUS_HTTP[status]
        # Log the semantic outcome only; never the token or filename.
        logger.info("upload rejected pre-body: status=%s", status)
        return _err(http_status, code)

    # (3) The endpoint's own hard cap on a declared Content-Length.
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            if int(declared) > store.MAX_UPLOAD_BYTES:
                return _err(413, "request_too_large")
        except ValueError:
            pass  # unparseable header; the streaming guard below covers it.

    # Attachment metadata rides in headers (never the URL). Content-Type
    # is the attachment mime; X-Attachment-Filename is metadata ONLY and
    # is never used as a filesystem path.
    raw_filename = request.headers.get(_FILENAME_HEADER, "")
    filename = unquote(raw_filename).strip()
    # Reject control characters (CR/LF/NUL/...) BEFORE storing: they enable
    # MIME-header injection and make EmailMessage.add_attachment raise at
    # build time (a generic 500 instead of a typed rejection here).
    if len(filename) > 256 or not is_safe_filename(filename):
        return _err(400, "missing_or_invalid_filename")
    mime_type = (request.headers.get("content-type") or "").split(";")[0].strip().lower()
    # Reject control characters (CR/LF/NUL/...) in the mime BEFORE storing:
    # like a control-char filename they enable MIME-header injection and make
    # EmailMessage.add_attachment raise at build time (a generic 500 instead of
    # a typed rejection here). An absent/empty mime defaults to octet-stream
    # (unchanged); a present-but-unsafe mime is a 400 with nothing stored.
    if mime_type and not is_safe_mime(mime_type):
        return _err(400, "invalid_content_type")
    if not mime_type or len(mime_type) > 128:
        mime_type = "application/octet-stream"

    # (4) Stream the body with the hard byte-count guard.
    try:
        raw = await _read_body_capped(request.stream(), store.MAX_UPLOAD_BYTES)
    except _UploadTooLarge:
        # Catch here so ErrorEnvelopeMiddleware cannot mask it as a 500.
        return _err(413, "request_too_large")

    size_bytes = len(raw)
    encrypted = encrypt_bytes(bytes(raw), settings.encryption_key)

    with session_scope() as session:
        # (B5a) Per-user aggregate byte cap (size is known now).
        if owner_sub is not None:
            active = store.sum_active_bytes(session, owner_sub)
            if active + size_bytes > store.MAX_ACTIVE_BYTES_PER_USER:
                return _err(413, "user_storage_quota_exceeded")
        # (B5b) Single-write: conditional store rejects a second upload
        # or a slot that raced into consumed/expired since the classify.
        stored = store.finalize_upload(
            session,
            token_hash=token_hash,
            encrypted=encrypted,
            size_bytes=size_bytes,
            filename=filename,
            mime_type=mime_type,
        )
    if not stored:
        return _err(409, "upload_slot_already_uploaded")

    logger.info("upload stored: size_bytes=%d", size_bytes)
    return JSONResponse({"stored": True, "size_bytes": size_bytes})
