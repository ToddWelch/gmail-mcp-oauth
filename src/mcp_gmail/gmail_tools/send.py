"""Write-side send tool: send_email.

The single most security-sensitive tool in the surface. It moves
data out of the user's mailbox to arbitrary recipients. The build
brief calls out four invariants and this module enforces all four:

1. Use email.message.EmailMessage (not email.mime.*). Enforced
   structurally by importing build_email_message from message_format,
   which uses EmailMessage exclusively.
2. Attachment size cap: 25 MiB on the FINAL encoded message size.
   Enforced by build_email_message via OversizeMessage exception.
3. Idempotency: when an `idempotency_key` is supplied, dedupe in-process
   for 60 seconds keyed by `(auth0_sub, account_email, idempotency_key)`.
   Cache backed by gmail_tools.idempotency.IdempotencyCache.
4. Audit log discipline: send_email NEVER logs subject, recipients,
   body, attachment filenames. The audit() helper at the dispatch
   boundary handles this; we just have to not call audit() ourselves.

TRASH-semantics note
--------------------
The TRASH-semantics design applies to delete tools; send tools are
unaffected. The send-tool foot-gun mitigation that DOES apply is the
"exactly one POST" assertion: the send tool must produce exactly one
Gmail HTTP POST per call, even when an idempotency-cache hit returns
the cached value. The cache hit path returns the cached dict without
calling Gmail at all (zero POSTs). The cache miss path produces
exactly one POST. Tests verify both branches.

Recipient validation
--------------------
We do a lightweight syntactic check on each recipient address (must
contain a single @ and have non-empty local + domain parts). Stricter
RFC 5321 / 5322 validation is brittle and Gmail rejects malformed
addresses anyway. The check exists primarily to fail fast on obvious
caller bugs (e.g. accidentally passing a list of names instead of
addresses).
"""

from __future__ import annotations

import base64
import binascii
from typing import Any

from .errors import bad_request_error
from .gmail_client import GmailClient
from .idempotency import IdempotencyCache, default_cache
from .message_format import (
    MAX_ENCODED_BYTES,
    Attachment,
    OversizeMessage,
    build_email_message,
    message_to_base64url,
)


# : pre-decode attachment caps. Validate
# attachment count and base64-estimated decoded size BEFORE running
# base64.urlsafe_b64decode on each attachment. The decode itself
# allocates memory proportional to the encoded length; without the
# pre-check, an attacker can ship a 50 MiB JSON body containing 100
# fake attachments and force ~50 MiB of allocations before the
# downstream OversizeMessage check fires on the assembled message.
# Cap of 25 attachments matches the count Gmail's UI exposes; the
# size cap mirrors message_format.MAX_ENCODED_BYTES.
MAX_ATTACHMENT_COUNT = 25


# Minimum syntactic check: localpart@domain with at least 1 char each.
# Gmail will reject anything more nuanced; we only catch the obvious.
def _looks_like_email(addr: str) -> bool:
    if not isinstance(addr, str):
        return False
    if addr.count("@") != 1:
        return False
    local, _, domain = addr.partition("@")
    return bool(local) and bool(domain)


def _validate_recipients(recipients: list[str], *, field: str) -> str | None:
    """Return None if every entry looks like an email; an error message otherwise."""
    if not isinstance(recipients, list):
        return f"{field} must be a list of email addresses"
    for i, addr in enumerate(recipients):
        if not _looks_like_email(addr):
            return f"{field}[{i}] is not a valid email address"
    return None


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
    """Convert an attachment input dict into an Attachment dataclass.

    Returns either the constructed Attachment or a bad_request_error
    dict if the input was malformed. Caller must check the return
    type. This lets the send_email function short-circuit on the
    first malformed attachment without raising.

    Input shape:
        {"filename": "...", "mime_type": "...", "data_base64url": "..."}

    `data_base64url` is base64url-encoded bytes (without padding is
    accepted; we add padding before decoding). We chose base64url over
    standard base64 to match Gmail's `raw` field convention; callers
    using download_attachment as input can pass that field directly.
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


# ---------------------------------------------------------------------------
# Tool: send_email
# ---------------------------------------------------------------------------


async def send_email(
    *,
    client: GmailClient,
    auth0_sub: str,
    account_email: str,
    sender: str,
    to: list[str],
    subject: str,
    body_text: str,
    cc: list[str] | None = None,
    bcc: list[str] | None = None,
    attachments: list[dict[str, Any]] | None = None,
    reply_to_message_id: str | None = None,
    reply_to_references: list[str] | None = None,
    idempotency_key: str | None = None,
    cache: IdempotencyCache | None = None,
) -> dict[str, Any]:
    """Send an RFC 5322 message via Gmail's users.messages.send endpoint.

    Required arguments are caller-supplied. The dispatcher passes
    `auth0_sub` and `account_email` through so the idempotency cache
    key includes the actor partition (Decision 2: prevents cross-actor cache hits).

    `cache` is the idempotency cache instance. Defaults to the
    module-level singleton in idempotency.py; tests inject their own
    to avoid coupling cases. When `idempotency_key` is None, the cache
    is bypassed entirely (no read, no write).

    Returns the Gmail send response on success: a dict with `id` (the
    sent message's Gmail ID) and `threadId`. On bad input or oversize,
    returns a bad_request_error dict with no Gmail call.
    """
    # ---- recipient validation (fail fast before message build) ------------
    err = _validate_recipients(to, field="to")
    if err is not None:
        return bad_request_error(err)
    if cc is not None:
        err = _validate_recipients(cc, field="cc")
        if err is not None:
            return bad_request_error(err)
    if bcc is not None:
        err = _validate_recipients(bcc, field="bcc")
        if err is not None:
            return bad_request_error(err)

    # ---- attachments ------------------------------------------------------
    decoded_attachments: list[Attachment] = []
    if attachments is not None:
        # cheap count + estimated-size guard BEFORE we
        # spend memory on base64 decode. Saves the worst-case path
        # where an attacker streams 100 fake attachments of 5 MiB each
        # and forces 500 MiB of allocations before the assembled-
        # message cap trips.
        pre_err = _validate_attachments_pre_decode(attachments)
        if pre_err is not None:
            return pre_err
        for i, raw in enumerate(attachments):
            decoded = _decode_attachment(raw, index=i)
            if isinstance(decoded, dict):  # error dict
                return decoded
            decoded_attachments.append(decoded)

    # ---- idempotency cache (READ side) ------------------------------------
    cache_obj = cache if cache is not None else default_cache
    cache_key: tuple[str, str, str] | None = None
    if idempotency_key is not None:
        if not isinstance(idempotency_key, str) or not idempotency_key:
            return bad_request_error("idempotency_key must be a non-empty string")
        cache_key = (auth0_sub, account_email, idempotency_key)
        cached = cache_obj.get(cache_key)
        if cached is not None:
            # Cache hit. Do NOT call Gmail (M-mitigation: zero POSTs on
            # cache hit). Returning the cached result preserves the
            # dedupe contract: the same idempotency_key from the same
            # actor returns the same message ID for the TTL window.
            return cached

    # ---- build the message ------------------------------------------------
    try:
        msg = build_email_message(
            sender=sender,
            to=to,
            subject=subject,
            body_text=body_text,
            cc=cc,
            bcc=bcc,
            attachments=decoded_attachments or None,
            reply_to_message_id=reply_to_message_id,
            reply_to_references=reply_to_references,
        )
    except OversizeMessage as exc:
        return bad_request_error(str(exc))

    # ---- send (exactly one POST) ------------------------------------------
    raw_b64 = message_to_base64url(msg)
    result = await client.send_message(raw_message=raw_b64)

    # ---- idempotency cache (WRITE side) -----------------------------------
    if cache_key is not None:
        cache_obj.set(cache_key, result)

    return result
