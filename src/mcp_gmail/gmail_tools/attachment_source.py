"""Resolve tagged attachment inputs into Attachment objects.

Every attachment-accepting write tool (send_email, create_draft,
update_draft, reply_all) accepts each attachment in exactly one of two
shapes: inline ({filename, mime_type, data_base64url}) or upload-handle
({source:"upload", upload_token, filename?, mime_type?}). The JSON
Schema `oneOf` at the dispatch boundary is the primary discriminator;
`_classify` here is the backstop for callers that bypass the schema.

For an upload attachment this module loads the owner's stored bytes,
runs the inflation-aware aggregate-size check BEFORE decrypting or
consuming (so an oversize reference set is rejected without spending a
slot), decrypts, and CONSUMES the slot atomically before the caller's
Gmail POST (airtight single-use; a POST that fails after consume needs
a fresh slot). Inline decode helpers live here too (single home);
send.py re-exports `_decode_attachment` for backward compatibility.
"""

from __future__ import annotations

import base64
import binascii
from typing import Any

from ..crypto import CryptoError, decrypt_bytes
from ..db import session_scope
from .. import attachment_upload_store as store
from .errors import bad_request_error
from .message_format import MAX_ENCODED_BYTES, Attachment


# Pre-decode attachment count cap. Matches the count Gmail's UI exposes
# and the schema-layer maxItems on the attachments array.
MAX_ATTACHMENT_COUNT = 25

# Assembled-size estimation. Base64 inflates binary by 4/3, and the
# RFC-5322 message adds envelope headers + per-part MIME framing. We
# estimate the ENCODED size before consuming any slot so an oversize
# reference set is rejected at reference time (slot NOT spent) rather
# than after consume by build_email_message's OversizeMessage backstop.
_MIME_OVERHEAD_BYTES = 8 * 1024  # envelope headers + boundaries margin
_PER_ATTACHMENT_OVERHEAD = 512  # per-part Content-* headers + boundary

# Effective single-attachment RAW cap advertised to callers: the largest
# raw payload whose base64-expanded form (+ overhead) fits under Gmail's
# 25 MiB encoded ceiling (~18.7 MiB). The upload endpoint keeps its own
# 25 MiB streaming cap (store.MAX_UPLOAD_BYTES) as the memory/DoS bound.
EFFECTIVE_MAX_ATTACHMENT_BYTES = (MAX_ENCODED_BYTES - _MIME_OVERHEAD_BYTES) * 3 // 4


def _b64_encoded_len(raw_len: int) -> int:
    """base64 length for raw_len bytes: ceil(raw_len / 3) * 4."""
    return ((raw_len + 2) // 3) * 4


def _assembled_estimate(raw_lengths: list[int], *, body_len: int) -> int:
    """Conservative estimate of the assembled encoded message size."""
    est = _MIME_OVERHEAD_BYTES + body_len
    for n in raw_lengths:
        est += _b64_encoded_len(n) + _PER_ATTACHMENT_OVERHEAD
    return est


class _ConsumeRace(Exception):
    """A slot was consumed concurrently between load and consume; roll back."""


def _validate_attachments_pre_decode(attachments: list[Any]) -> dict[str, Any] | None:
    """cheap pre-decode checks. Returns error dict on failure or None.

    Two cheap checks run before any base64 decoding:
    1. Count cap: more than MAX_ATTACHMENT_COUNT attachments fails.
    2. Estimated decoded size: each attachment's `data_base64url`
       length / 4 * 3 approximates the decoded bytes. Sum across all
       attachments and reject if the estimate exceeds MAX_ENCODED_BYTES.

    The estimate is intentionally optimistic for the attacker (it
    rounds DOWN: 4 base64 chars -> 3 raw bytes is the upper bound on
    decoded size). A real send still runs the post-build OversizeMessage
    check on the fully-rendered message, which catches the residual.
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
    """Convert an inline attachment input dict into an Attachment dataclass.

    Returns either the constructed Attachment or a bad_request_error
    dict if the input was malformed. Caller must check the return type.

    Input shape:
        {"filename": "...", "mime_type": "...", "data_base64url": "..."}

    `data_base64url` is base64url-encoded bytes (without padding is
    accepted; we add padding before decoding) to match Gmail's `raw`
    field convention, so download_attachment output can pass straight in.
    """
    if not isinstance(att, dict):
        return bad_request_error(f"attachments[{index}] must be an object")
    filename = att.get("filename")
    mime_type = att.get("mime_type")
    data_b64 = att.get("data_base64url")
    if not isinstance(filename, str) or not filename:
        return bad_request_error(f"attachments[{index}].filename is required")
    if not isinstance(mime_type, str) or not mime_type:
        return bad_request_error(f"attachments[{index}].mime_type is required")
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


def resolve_attachments(
    *,
    raw: list[dict[str, Any]] | None,
    auth0_sub: str,
    account_email: str,
    encryption_key: str | None,
    prior_encryption_keys: tuple[str, ...] = (),
    body_len: int = 0,
) -> list[Attachment] | dict[str, Any]:
    """Resolve a mixed inline/upload attachment list into Attachment objects.

    Returns the list (possibly empty) on success, or a bad_request_error
    dict on any malformed / unavailable / oversize input. The oversize
    check is inflation-aware (base64 4/3 + MIME overhead + `body_len`) and
    runs BEFORE consuming any slot, so an oversize reference set is
    rejected at reference time and a corrected retry can still succeed.
    Upload slots are consumed (single-use) only on the fully-successful
    path; any failure rolls back so no slot is partially spent.
    """
    if raw is None:
        return []
    if not isinstance(raw, list):
        return bad_request_error("attachments must be a list")
    # Cheap count + inline base64-estimate guard BEFORE any decode, so an
    # oversize inline payload is rejected without allocating the decoded
    # bytes (the pre-decode DoS mitigation). Upload entries carry no
    # data_base64url and contribute 0 to the estimate.
    pre_err = _validate_attachments_pre_decode(raw)
    if pre_err is not None:
        return pre_err

    kinds: list[str] = []
    for i, att in enumerate(raw):
        kind = _classify(att, index=i)
        if isinstance(kind, dict):
            return kind
        kinds.append(kind)

    # Decode all inline attachments first (no DB, no consume) so an
    # inline error never spends an upload slot. Collect each raw length
    # for the inflation-aware assembled-size estimate below.
    out: list[Attachment | None] = [None] * len(raw)
    raw_lengths: list[int] = []
    for i, att in enumerate(raw):
        if kinds[i] != "inline":
            continue
        dec = _decode_attachment(att, index=i)
        if isinstance(dec, dict):
            return dec
        out[i] = dec
        raw_lengths.append(len(dec.data))

    upload_indexes = [i for i, k in enumerate(kinds) if k == "upload"]
    if not upload_indexes:
        # Inline-only: inflation-aware assembled-size check (no consume).
        if _assembled_estimate(raw_lengths, body_len=body_len) > MAX_ENCODED_BYTES:
            return bad_request_error(f"attachments exceed the {MAX_ENCODED_BYTES}-byte message cap")
        return [a for a in out if a is not None]

    if not encryption_key:
        return bad_request_error("server is not configured to resolve upload attachments")

    # Upload path: load owner-scoped rows, run the inflation-aware size
    # check on stored sizes BEFORE decrypting or consuming (so an oversize
    # reference set is rejected without spending a slot and bounds
    # transient plaintext), decrypt, then consume atomically.
    loaded: dict[int, tuple[str, bytes, str | None, str | None]] = {}
    decrypted: dict[int, bytes] = {}
    try:
        with session_scope() as session:
            for i in upload_indexes:
                token = raw[i]["upload_token"]
                token_hash = store.hash_token(token)
                row = store.load_for_consume(
                    session,
                    token_hash=token_hash,
                    auth0_sub=auth0_sub,
                    account_email=account_email,
                )
                if row is None:
                    return bad_request_error(
                        "an upload slot referenced by this message is not "
                        "available (unknown, expired, already used, or not "
                        "owned by this account); mint a new slot with "
                        "create_attachment_upload_slot"
                    )
                loaded[i] = (token_hash, row.encrypted_bytes, row.filename, row.mime_type)
                raw_lengths.append(row.size_bytes or 0)
            if _assembled_estimate(raw_lengths, body_len=body_len) > MAX_ENCODED_BYTES:
                # No decrypt / consume has run: the slot is not spent, so a
                # corrected retry can succeed.
                return bad_request_error(
                    f"attachments exceed the {MAX_ENCODED_BYTES}-byte message cap"
                )
            for i, (token_hash, enc, _fn, _mt) in loaded.items():
                try:
                    decrypted[i] = decrypt_bytes(enc, encryption_key, *prior_encryption_keys)
                except CryptoError:
                    return bad_request_error(
                        "a stored attachment could not be decrypted; mint a new slot"
                    )
            for i, (token_hash, _enc, _fn, _mt) in loaded.items():
                if not store.consume(
                    session,
                    token_hash=token_hash,
                    auth0_sub=auth0_sub,
                    account_email=account_email,
                ):
                    # Lost a race; roll the whole transaction back so no
                    # slot is partially consumed.
                    raise _ConsumeRace()
    except _ConsumeRace:
        return bad_request_error(
            "an upload slot was consumed concurrently; mint a new slot and retry"
        )

    for i in upload_indexes:
        _th, _enc, stored_name, stored_mime = loaded[i]
        entry = raw[i]
        filename = entry.get("filename") or stored_name
        mime_type = entry.get("mime_type") or stored_mime or "application/octet-stream"
        out[i] = Attachment(
            filename=filename or "attachment", mime_type=mime_type, data=decrypted[i]
        )

    return [a for a in out if a is not None]
