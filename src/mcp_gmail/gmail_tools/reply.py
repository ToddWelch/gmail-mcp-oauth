"""Write-side reply_all tool.

Given a `message_id` already in the linked mailbox, reply to ALL
recipients: To the original `From`; Cc the original `To` + `Cc` minus
the linked account's own address. Threaded by the source message's
threadId on the POST, with `In-Reply-To` / `References` set to its
Message-ID when it has one; built through the same
build_email_message + 25 MiB cap path send_email uses.

Foot-gun mitigations: an empty expanded recipient list ->
bad_request_error (no silent zero-recipient send); recipient set capped
at 100; get_user_profile failure -> upstream_error (no silent
include-everyone fallback).

Idempotency cache is shared with send_email (key = (auth0_sub,
account_email, idempotency_key)); reusing a key across both is refused.
The cache is READ before any upload slot is consumed, so a replay
consumes no slot.
"""

from __future__ import annotations

import logging
from typing import Any

from .attachment_source import consume_slots, load_attachments
from .errors import bad_request_error, upstream_error
from .gmail_client import GmailApiError, GmailClient
from .idempotency import IdempotencyCache, default_cache, request_fingerprint
from .message_format import (
    InvalidHeaderValue,
    OversizeMessage,
    build_email_message,
    message_to_base64url,
)
from .reply_outcomes import (
    REASON_LOOKUP_FAILED,
    attachment_identity,
    cacheable_send_result,
    replayed_result,
    threading_refused_error,
    unknown_outcome_or_raise,
    verify_sent_thread,
)
from .reply_recipients import extract_header, looks_like_email, split_address_list

# Backward-compat re-exports; the helpers moved to reply_recipients.py.
_split_address_list = split_address_list
_extract_header = extract_header
_looks_like_email = looks_like_email

logger = logging.getLogger(__name__)


# Hard cap mirrored from tool_schemas.EMAIL_LIST_PROP.maxItems, so the expanded
# list stays symmetric with send_email's explicit recipient lists.
_MAX_EXPANDED_RECIPIENTS = 100


# ---------------------------------------------------------------------------
# Tool: reply_all
# ---------------------------------------------------------------------------


async def reply_all(
    *,
    client: GmailClient,
    auth0_sub: str,
    account_email: str,
    message_id: str,
    body_text: str,
    body_html: str | None = None,
    attachments: list[dict[str, Any]] | None = None,
    idempotency_key: str | None = None,
    cache: IdempotencyCache | None = None,
    encryption_key: str | None = None,
    prior_encryption_keys: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Reply to all recipients of `message_id`.

    The argument is named `message_id` so dispatch.py's audit harvest
    binds the source-message ID into the audit line. Returns the Gmail
    send response (id + threadId) or a typed error dict on failure
    (bad_request_error, not_found_error via the dispatcher's
    GmailApiError mapping, upstream_error on getProfile failure).

    Recipients: original `From` -> reply To; original `To` + `Cc` minus
    self (resolved via getProfile) -> reply Cc; expanded set capped at
    _MAX_EXPANDED_RECIPIENTS (100). Threading: the source message's threadId
    goes on the POST and is compared with the thread Gmail reports afterward;
    Subject prefixed "Re: " unless already present; In-Reply-To + References
    set to the original Message-ID (appended to any existing References chain).

    optional `body_html` makes the reply multipart/alternative (body_text
    is the plain-text fallback part).
    """
    cache_obj = cache if cache is not None else default_cache
    cache_key: tuple[str, str, str] | None = None
    if idempotency_key is not None:
        if not isinstance(idempotency_key, str) or not idempotency_key:
            return bad_request_error("idempotency_key must be a non-empty string")
        cache_key = (auth0_sub, account_email, idempotency_key)
    fingerprint = ""
    if cache_key is not None:
        fingerprint = request_fingerprint(
            "reply_all", message_id, body_text, body_html, attachment_identity(attachments)
        )

    async with cache_obj.key_lock(cache_key):
        # ---- idempotency cache (READ side) --------------------------------
        replay = replayed_result(cache=cache_obj, key=cache_key, fingerprint=fingerprint)
        if replay is not None:
            return replay

        result = await _reply_once(
            client=client,
            auth0_sub=auth0_sub,
            account_email=account_email,
            message_id=message_id,
            body_text=body_text,
            body_html=body_html,
            attachments=attachments,
            encryption_key=encryption_key,
            prior_encryption_keys=prior_encryption_keys,
        )

        # ---- idempotency cache (WRITE side) -------------------------------
        if cache_key is not None and cacheable_send_result(result):
            cache_obj.set(cache_key, result, fingerprint=fingerprint)
        return result


async def _reply_once(
    *,
    client: GmailClient,
    auth0_sub: str,
    account_email: str,
    message_id: str,
    body_text: str,
    body_html: str | None,
    attachments: list[dict[str, Any]] | None,
    encryption_key: str | None,
    prior_encryption_keys: tuple[str, ...],
) -> dict[str, Any]:
    """One real attempt: read the source, build, consume slots, POST, verify."""
    # ---- fetch original message (metadata is enough for headers) ----------
    # 404 / other Gmail errors propagate to the dispatcher's error mapper
    # (route_tool converts GmailApiError to a typed error dict).
    original = await client.get_message(
        message_id=message_id,
        format="metadata",
    )
    source_thread = original.get("threadId")
    if not isinstance(source_thread, str) or not source_thread:
        return threading_refused_error(
            "The message being replied to came back without a thread id.",
            reason=REASON_LOOKUP_FAILED,
        )

    # ---- fetch self email via getProfile (N1: never silent fallback) ------
    try:
        profile = await client.get_user_profile()
    except GmailApiError as exc:
        # Not a caller-input bug. Treating "self" as empty would let the
        # linked account appear in its own reply Cc list.
        return upstream_error(
            f"could not fetch user profile to compute reply-all recipients: {exc}",
            status=exc.status if exc.status else None,
        )
    self_email = profile.get("emailAddress")
    if not isinstance(self_email, str) or not self_email:
        return upstream_error("getProfile returned no emailAddress")
    self_email_lower = self_email.strip().lower()

    # ---- compute recipients -----------------------------------------------
    from_header = extract_header(original, "From") or ""
    to_header = extract_header(original, "To")
    cc_header = extract_header(original, "Cc")
    subject_header = extract_header(original, "Subject") or ""
    message_id_header = extract_header(original, "Message-ID") or extract_header(
        original, "Message-Id"
    )
    references_header = extract_header(original, "References")

    from_addrs = split_address_list(from_header)
    to_addrs = split_address_list(to_header)
    cc_addrs = split_address_list(cc_header)

    # Build the new recipient sets.
    reply_to: list[str] = []
    seen: set[str] = set()
    for addr in from_addrs:
        key = addr.lower()
        if key == self_email_lower:
            # Replying to one's own outgoing message: skip the self
            # entry; otherwise reply_all would Cc you on your own
            # reply.
            continue
        if key in seen:
            continue
        seen.add(key)
        if looks_like_email(addr):
            reply_to.append(addr)

    reply_cc: list[str] = []
    for addr in to_addrs + cc_addrs:
        key = addr.lower()
        if key == self_email_lower:
            continue
        if key in seen:
            continue
        seen.add(key)
        if looks_like_email(addr):
            reply_cc.append(addr)

    # Cap the expanded set. We cap on the combined size; the tool
    # surface promises at most _MAX_EXPANDED_RECIPIENTS recipients.
    if len(reply_to) + len(reply_cc) > _MAX_EXPANDED_RECIPIENTS:
        # Trim Cc first; To is structurally smaller and more important.
        budget = _MAX_EXPANDED_RECIPIENTS - len(reply_to)
        if budget < 0:
            budget = 0
        reply_cc = reply_cc[:budget]

    if not reply_to and not reply_cc:
        return bad_request_error("no recipients to reply to")

    # ---- build subject / threading headers --------------------------------
    if subject_header.lower().startswith("re:"):
        new_subject = subject_header
    else:
        new_subject = f"Re: {subject_header}" if subject_header else "Re:"

    # References chain: if the original carried References, append the
    # new parent; otherwise the parent IS the chain.
    refs_list: list[str] | None = None
    if message_id_header:
        if references_header:
            refs_list = references_header.split() + [message_id_header]
        else:
            refs_list = [message_id_header]

    # ---- attachments: load + decrypt AFTER the reads succeed (NO consume) --
    # Loading here (not at the top) means a bad message_id or a getProfile
    # failure does not touch a slot; the cache read at the top already
    # short-circuited before any load/consume on a hit.
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
            sender=self_email,
            to=reply_to or [self_email],  # extreme degenerate: reply to self only
            subject=new_subject,
            body_text=body_text,
            cc=reply_cc or None,
            body_html=body_html,
            attachments=resolved or None,
            reply_to_message_id=message_id_header,
            reply_to_references=refs_list,
        )
    except OversizeMessage as exc:
        return bad_request_error(str(exc))
    except InvalidHeaderValue as exc:
        # Control character in a specific header field (e.g. a CR/LF-bearing
        # address expanded from the original message); typed, field-named
        # bad_request, no consume. Never log the value.
        logger.warning("reply_all rejected a control character in a header field")
        return bad_request_error(f"{exc.field} contains control characters")
    except ValueError:
        # Malformed header/attachment value raises in EmailMessage; bad_request, no consume.
        logger.warning("reply_all message build rejected a malformed header/attachment value")
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
        result = await client.send_message(raw_message=raw_b64, thread_id=source_thread)
    except GmailApiError as exc:
        return unknown_outcome_or_raise(exc)
    return verify_sent_thread(result, source_thread)
