"""Pure input validation + shape classification for attachment inputs.

Split out of attachment_source.py (300-LOC + distinct-responsibility rule):
this module is the pure, DB-free half: it validates attachment shape,
decodes inline base64url payloads, and rejects control-char filenames /
mime types BEFORE anything is stored, built, or consumed. attachment_source
owns the DB-backed half (load/decrypt upload slots + consume). It imports
these helpers and re-exports them, so existing references
(`attachment_source.is_safe_filename`, `send._decode_attachment`, etc.)
keep resolving. This module must NOT import attachment_source (no cycle).
"""

from __future__ import annotations

import base64
import binascii
from typing import Any

from .errors import bad_request_error
from .message_format import MAX_ENCODED_BYTES, Attachment


# Pre-decode attachment count cap. Matches the count Gmail's UI exposes
# and the schema-layer maxItems on the attachments array.
MAX_ATTACHMENT_COUNT = 25


def is_safe_filename(name: str) -> bool:
    """True if `name` is non-empty and free of C0/C1/DEL control characters.

    EmailMessage.add_attachment raises ValueError on CR/LF in a filename,
    and CR/LF/NUL enable MIME-header injection; reject them (and the rest
    of the control range) before storing or building rather than crashing
    at render time.
    """
    return bool(name) and not any(ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F for c in name)


def is_safe_mime(value: str) -> bool:
    """True if `value` is non-empty and free of C0/C1/DEL control characters.

    Mirrors is_safe_filename for the attachment mime_type / incoming
    Content-Type. EmailMessage.add_attachment raises ValueError on CR/LF in
    the maintype/subtype, and CR/LF/NUL enable MIME-header injection; reject
    the whole control range before storing or building rather than crashing
    at render time with a generic 500.
    """
    return bool(value) and not any(ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F for c in value)


def _validate_attachments_pre_decode(attachments: list[Any]) -> dict[str, Any] | None:
    """Cheap pre-decode guard: count cap + a rounded-DOWN raw-size estimate
    over inline data_base64url, rejected before any decode allocates
    memory. Not the oversize gate (build_email_message is); fails fast.
    """
    if not isinstance(attachments, list):
        return bad_request_error("attachments must be a list")
    if len(attachments) > MAX_ATTACHMENT_COUNT:
        return bad_request_error(
            f"too many attachments: {len(attachments)} > {MAX_ATTACHMENT_COUNT}"
        )
    estimated_total = 0
    for i, att in enumerate(attachments):
        if not isinstance(att, dict):
            # Detailed validation runs in _decode_attachment; here we
            # only fail-fast on the size estimate. Skip non-dicts so
            # _decode_attachment returns the appropriate per-field error.
            continue
        b64 = att.get("data_base64url")
        if isinstance(b64, str):
            estimated_total += (len(b64) // 4) * 3
            if estimated_total > MAX_ENCODED_BYTES:
                return bad_request_error(
                    f"attachments[{i}] pushes estimated size over the "
                    f"{MAX_ENCODED_BYTES}-byte cap before decode"
                )
    return None


def _decode_attachment(att: dict[str, Any], *, index: int) -> Attachment | dict[str, Any]:
    """Convert an inline attachment dict into an Attachment, or return a
    bad_request_error dict on malformed input (caller checks the type).

    Shape {filename, mime_type, data_base64url}; data_base64url is
    base64url (padding optional; added before decode) to match Gmail's
    `raw` convention, so download_attachment output passes straight in.
    """
    if not isinstance(att, dict):
        return bad_request_error(f"attachments[{index}] must be an object")
    filename = att.get("filename")
    mime_type = att.get("mime_type")
    data_b64 = att.get("data_base64url")
    if not isinstance(filename, str) or not filename:
        return bad_request_error(f"attachments[{index}].filename is required")
    if not is_safe_filename(filename):
        return bad_request_error(f"attachments[{index}].filename contains control characters")
    if not isinstance(mime_type, str) or not mime_type:
        return bad_request_error(f"attachments[{index}].mime_type is required")
    if not is_safe_mime(mime_type):
        return bad_request_error(f"attachments[{index}].mime_type contains control characters")
    if not isinstance(data_b64, str):
        return bad_request_error(f"attachments[{index}].data_base64url must be a string")
    # Add padding then decode. urlsafe_b64decode requires padding.
    padded = data_b64 + "=" * (-len(data_b64) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded)
    except (binascii.Error, ValueError):
        return bad_request_error(f"attachments[{index}].data_base64url is not valid base64url")
    return Attachment(filename=filename, mime_type=mime_type, data=raw)


def _classify(att: Any, *, index: int) -> str | dict[str, Any]:
    """Return "inline" | "upload", or a bad_request_error dict.

    Mirrors download_attachment's exactly-one-selector discipline:
    exactly one of the inline shape (data_base64url) or the upload shape
    (source=upload + upload_token) must be present.
    """
    if not isinstance(att, dict):
        return bad_request_error(f"attachments[{index}] must be an object")
    has_inline = "data_base64url" in att
    has_upload = att.get("source") == "upload" or "upload_token" in att
    if has_inline and has_upload:
        return bad_request_error(
            f"attachments[{index}] must have exactly one of data_base64url "
            "(inline) or source=upload (handle), not both"
        )
    if not has_inline and not has_upload:
        return bad_request_error(
            f"attachments[{index}] must have either data_base64url (inline) "
            "or source=upload with upload_token"
        )
    if has_upload:
        if att.get("source") != "upload":
            return bad_request_error(f"attachments[{index}].source must be 'upload'")
        token = att.get("upload_token")
        if not isinstance(token, str) or not token:
            return bad_request_error(
                f"attachments[{index}].upload_token is required for source=upload"
            )
        return "upload"
    return "inline"
