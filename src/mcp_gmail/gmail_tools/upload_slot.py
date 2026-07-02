"""create_attachment_upload_slot: mint a single-use upload slot.

First leg of the upload-slot + handle flow. An authenticated MCP tool
call (scope-checked by the dispatcher as send-capable) mints a
one-time, user-bound capability slot and returns the raw token plus the
upload URL. The client then curls the file bytes to that URL (see
attachment_routes) and later references the token by handle in
send_email / create_draft / update_draft / reply_all.

The raw token is returned to the caller exactly once here; the store
persists only its SHA-256 hash. No bytes pass through the model.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from .. import attachment_upload_store as store
from ..db import session_scope
from .attachment_source import EFFECTIVE_MAX_ATTACHMENT_BYTES
from .errors import bad_request_error

if TYPE_CHECKING:  # pragma: no cover
    from ..config import Settings


_UPLOAD_PATH = "/attachments/upload"


def _upload_url(settings: "Settings") -> str:
    """Build the absolute upload URL from the service ORIGIN.

    Derive scheme://netloc from mcp_resource_url and append the fixed
    path, so any path component on mcp_resource_url is ignored and the
    URL always points at the mounted route regardless of how the
    resource identifier is configured.
    """
    parts = urlsplit(settings.mcp_resource_url)
    return f"{parts.scheme}://{parts.netloc}{_UPLOAD_PATH}"


def create_upload_slot(
    *, auth0_sub: str, account_email: str, settings: "Settings"
) -> dict[str, Any]:
    """Mint an upload slot. Returns the slot descriptor or a bad_request dict.

    Opportunistically purges expired/consumed rows (prompt cleanup) then
    mints, enforcing the per-user active-slot COUNT cap. On cap-exceeded
    returns a bad_request_error naming the limit.
    """
    with session_scope() as session:
        store.purge_expired_and_consumed(session)
        try:
            token, expires_at = store.create_slot(
                session, auth0_sub=auth0_sub, account_email=account_email
            )
        except store.SlotCapExceeded as exc:
            return bad_request_error(str(exc))
    return {
        "upload_token": token,
        "upload_url": _upload_url(settings),
        "expires_at": expires_at.isoformat(),
        # ADVISORY effective send-through cap (~18.5 MiB): raw bytes whose
        # base64 form (incl. RFC 2045 line-wrapping) fits under Gmail's
        # 25 MiB encoded ceiling, ignoring headers. Guidance only; the
        # real gate is the assembled 25 MiB cap enforced at send/draft
        # time on the exact rendered message (an oversize send is rejected
        # without burning the slot). The endpoint still streams up to
        # store.MAX_UPLOAD_BYTES (25 MiB) as its memory/DoS bound.
        "max_bytes": EFFECTIVE_MAX_ATTACHMENT_BYTES,
    }
