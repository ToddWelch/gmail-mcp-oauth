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

Exactly one POST
----------------
A replay returns the cached dict without calling Gmail (zero POSTs). A
cache miss produces exactly one POST. Tests verify both branches.

Recipient validation
--------------------
A lightweight syntactic check (a single @, non-empty local + domain)
fails fast on obvious caller bugs. Gmail rejects anything subtler.
"""

from __future__ import annotations

import logging
from typing import Any

from .attachment_source import consume_slots, load_attachments
from .errors import bad_request_error
from .gmail_client import GmailApiError, GmailClient
from .idempotency import IdempotencyCache, default_cache, request_fingerprint
from .message_format import (
    InvalidHeaderValue,
    OversizeMessage,
    build_email_message,
    message_to_base64url,
)
from .reply_outcomes import (
    attachment_identity,
    cacheable_send_result,
    replayed_result,
    unknown_outcome_or_raise,
    verify_sent_thread,
)
from .reply_threading import canonical_message_id, resolve_expected_thread

# Backward-compat re-exports; the helpers moved to attachment_source.py.
from .attachment_source import (  # noqa: F401
    MAX_ATTACHMENT_COUNT,
    _decode_attachment,
    _validate_attachments_pre_decode,
)

logger = logging.getLogger(__name__)


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
    body_html: str | None = None,
    attachments: list[dict[str, Any]] | None = None,
    reply_to_message_id: str | None = None,
    reply_to_references: list[str] | None = None,
    idempotency_key: str | None = None,
    cache: IdempotencyCache | None = None,
    encryption_key: str | None = None,
    prior_encryption_keys: tuple[str, ...] = (),
    granted_scope: str = "",
) -> dict[str, Any]:
    """Send an RFC 5322 message via Gmail's users.messages.send endpoint.

    Required arguments are caller-supplied. The dispatcher passes
    `auth0_sub` and `account_email` through so the idempotency cache
    key includes the actor partition (Decision 2: prevents cross-actor cache hits).

    A reply lands in its conversation or does not send: with
    `reply_to_message_id` the server finds the thread by searching this
    mailbox, sets `threadId`, and compares the thread Gmail reports afterward
    (reply_threading.py). A reply needs read access on top of gmail.send, so
    `granted_scope` defaults to empty and fails closed; a new email needs
    no read access and makes no extra call.

    Attachments accept two shapes per entry: inline
    ({filename, mime_type, data_base64url}) and upload-handle
    ({source:"upload", upload_token}). `attachment_source.load_attachments`
    decodes inline and decrypts upload bytes (NO consume);
    `encryption_key` / `prior_encryption_keys` are threaded from Settings
    so upload bytes can be decrypted.

    Ordering (single-use safety): the idempotency cache is READ before any
    load/consume, so a cache HIT returns the cached result and spends NO
    slot. On a MISS the message is BUILT first (an oversize/malformed
    build is rejected with NO slot consumed, so a corrected retry works),
    then the slots are consumed BEFORE the single POST so two concurrent
    sends with the same handle cannot both deliver. If the POST then
    fails, the slots are already spent; mint fresh slots before retrying.

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

    cache_obj = cache if cache is not None else default_cache
    cache_key: tuple[str, str, str] | None = None
    if idempotency_key is not None:
        if not isinstance(idempotency_key, str) or not idempotency_key:
            return bad_request_error("idempotency_key must be a non-empty string")
        cache_key = (auth0_sub, account_email, idempotency_key)
    reply_to_message_id = canonical_message_id(reply_to_message_id)
    fingerprint = ""
    if cache_key is not None:
        fingerprint = request_fingerprint(
            "send_email",
            sender,
            to,
            cc,
            bcc,
            subject,
            reply_to_message_id,
            reply_to_references,
            body_text,
            body_html,
            attachment_identity(attachments),
        )

    async with cache_obj.key_lock(cache_key):
        # ---- idempotency cache (READ side, BEFORE consuming any slot) ------
        # A true replay does NOT call Gmail and does NOT consume any upload
        # slot (zero POSTs, zero consumes). The dedupe contract returns the
        # same message ID for the TTL window.
        replay = replayed_result(cache=cache_obj, key=cache_key, fingerprint=fingerprint)
        if replay is not None:
            return replay

        result = await _send_once(
            client=client,
            auth0_sub=auth0_sub,
            account_email=account_email,
            sender=sender,
            to=to,
            subject=subject,
            body_text=body_text,
            cc=cc,
            bcc=bcc,
            body_html=body_html,
            attachments=attachments,
            reply_to_message_id=reply_to_message_id,
            reply_to_references=reply_to_references,
            encryption_key=encryption_key,
            prior_encryption_keys=prior_encryption_keys,
            granted_scope=granted_scope,
        )

        # ---- idempotency cache (WRITE side) -------------------------------
        if cache_key is not None and cacheable_send_result(result):
            cache_obj.set(cache_key, result, fingerprint=fingerprint)
        return result


async def _send_once(
    *,
    client: GmailClient,
    auth0_sub: str,
    account_email: str,
    sender: str,
    to: list[str],
    subject: str,
    body_text: str,
    cc: list[str] | None,
    bcc: list[str] | None,
    body_html: str | None,
    attachments: list[dict[str, Any]] | None,
    reply_to_message_id: str | None,
    reply_to_references: list[str] | None,
    encryption_key: str | None,
    prior_encryption_keys: tuple[str, ...],
    granted_scope: str,
) -> dict[str, Any]:
    """One real attempt: check threading, build, consume slots, POST, verify."""
    # ---- threading (BEFORE any attachment work; a refusal burns NO slot) ---
    expected_thread = await resolve_expected_thread(
        client=client,
        subject=subject,
        reply_to_message_id=reply_to_message_id,
        reply_to_references=reply_to_references,
        granted_scope=granted_scope,
    )
    if isinstance(expected_thread, dict):  # refusal
        return expected_thread

    # ---- attachments: load + decrypt (NO consume yet) ---------------------
    loaded = load_attachments(
        raw=attachments,
        auth0_sub=auth0_sub,
        account_email=account_email,
        encryption_key=encryption_key,
        prior_encryption_keys=prior_encryption_keys,
    )
    if isinstance(loaded, dict):  # error dict
        return loaded
    resolved, token_hashes = loaded

    # ---- build the message (exact-size gate; oversize burns NO slot) ------
    try:
        msg = build_email_message(
            sender=sender,
            to=to,
            subject=subject,
            body_text=body_text,
            cc=cc,
            bcc=bcc,
            body_html=body_html,
            attachments=resolved or None,
            reply_to_message_id=reply_to_message_id,
            reply_to_references=reply_to_references,
        )
    except OversizeMessage as exc:
        return bad_request_error(str(exc))
    except InvalidHeaderValue as exc:
        # A control character in a specific header field. Typed, field-named
        # bad_request (BEFORE consume, no slot burned). Never log the value.
        logger.warning("send_email rejected a control character in a header field")
        return bad_request_error(f"{exc.field} contains control characters")
    except ValueError:
        # A malformed caller-supplied header/attachment value (e.g. CR/LF in
        # a filename or mime_type that slipped past proactive checks) makes
        # EmailMessage raise ValueError. Map to a typed bad_request; scoped to
        # the build so it stays BEFORE consume (no slot burned) and cannot mask
        # unrelated errors. Never log recipients/filename/bytes.
        logger.warning("send_email message build rejected a malformed header/attachment value")
        return bad_request_error("message could not be built from the provided headers/attachments")

    # ---- consume slots AFTER a successful build, BEFORE the POST ----------
    consume_err = consume_slots(
        token_hashes=token_hashes,
        auth0_sub=auth0_sub,
        account_email=account_email,
    )
    if consume_err is not None:  # lost a race; do NOT send
        return consume_err

    # ---- send (exactly one POST) ------------------------------------------
    raw_b64 = message_to_base64url(msg)
    try:
        result = await client.send_message(raw_message=raw_b64, thread_id=expected_thread)
    except GmailApiError as exc:
        return unknown_outcome_or_raise(exc)
    return verify_sent_thread(result, expected_thread)
