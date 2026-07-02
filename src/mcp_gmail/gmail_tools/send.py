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

from typing import Any

from .attachment_source import resolve_attachments
from .errors import bad_request_error
from .gmail_client import GmailClient
from .idempotency import IdempotencyCache, default_cache
from .message_format import (
    OversizeMessage,
    build_email_message,
    message_to_base64url,
)

# Backward-compat re-exports. The inline-attachment decode helpers moved
# to attachment_source.py (single home for attachment-input handling);
# existing references to `send._decode_attachment` /
# `send.MAX_ATTACHMENT_COUNT` continue to resolve here.
from .attachment_source import (  # noqa: F401
    MAX_ATTACHMENT_COUNT,
    _decode_attachment,
    _validate_attachments_pre_decode,
)


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
    encryption_key: str | None = None,
    prior_encryption_keys: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Send an RFC 5322 message via Gmail's users.messages.send endpoint.

    Required arguments are caller-supplied. The dispatcher passes
    `auth0_sub` and `account_email` through so the idempotency cache
    key includes the actor partition (Decision 2: prevents cross-actor cache hits).

    Attachments accept two shapes per entry: inline
    ({filename, mime_type, data_base64url}) and upload-handle
    ({source:"upload", upload_token}); resolution is delegated to
    attachment_source.resolve_attachments, which decodes inline and
    CONSUMES upload slots. `encryption_key` / `prior_encryption_keys`
    are threaded through from Settings so upload bytes can be decrypted.

    Ordering (single-use safety): the idempotency cache is READ before
    any slot is consumed, so a cache HIT returns the cached result and
    spends NO slot. On a MISS the slots are consumed BEFORE the single
    POST so two concurrent sends with the same handle cannot both
    deliver. If the POST then fails, the slots are already spent; the
    caller must mint fresh slots before retrying (a dead-token retry
    will not work).

    Returns the Gmail send response on success (id + threadId). On bad
    input or oversize, returns a bad_request_error dict with no Gmail call.
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

    # ---- idempotency cache (READ side, BEFORE consuming any slot) ----------
    cache_obj = cache if cache is not None else default_cache
    cache_key: tuple[str, str, str] | None = None
    if idempotency_key is not None:
        if not isinstance(idempotency_key, str) or not idempotency_key:
            return bad_request_error("idempotency_key must be a non-empty string")
        cache_key = (auth0_sub, account_email, idempotency_key)
        cached = cache_obj.get(cache_key)
        if cached is not None:
            # Cache hit. Do NOT call Gmail and do NOT consume any upload
            # slot (zero POSTs, zero consumes on cache hit). The dedupe
            # contract returns the same message ID for the TTL window.
            return cached

    # ---- attachments (decode inline + consume upload slots) ---------------
    resolved = resolve_attachments(
        raw=attachments,
        auth0_sub=auth0_sub,
        account_email=account_email,
        encryption_key=encryption_key,
        prior_encryption_keys=prior_encryption_keys,
        body_len=len(body_text.encode("utf-8")),
    )
    if isinstance(resolved, dict):  # error dict
        return resolved

    # ---- build the message ------------------------------------------------
    try:
        msg = build_email_message(
            sender=sender,
            to=to,
            subject=subject,
            body_text=body_text,
            cc=cc,
            bcc=bcc,
            attachments=resolved or None,
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
