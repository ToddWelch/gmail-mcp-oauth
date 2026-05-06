"""Write-side reply_all tool.

Split from send.py to honor the project's 300-LOC per-file ceiling:
send.py is at 214 LOC and adding reply_all inline would push it
past the limit.

What reply_all does
-------------------
Given a `message_id` already in the linked mailbox, reply to ALL
recipients of that message:

  - To the original `From` address.
  - Cc the original `To` and `Cc` addresses, minus the linked account's
    own email address (because Gmail does not show your own reply to
    yourself in the natural inbox flow).

The reply is threaded by setting `In-Reply-To` and `References` to
the original message's RFC 5322 Message-ID header. The send goes
through the same build_email_message + 25 MiB cap path that send_email
uses, and shares the same idempotency cache.

Foot-gun mitigations
-------------------------------------
- "Replies to ALL recipients on the original message (To + Cc minus
  self)" is documented in the tool description.
- Empty expanded recipient list -> bad_request_error("no recipients
  to reply to"). Silent send with zero recipients is forbidden.
- Recipient set capped at 100 (matches EMAIL_LIST_PROP in
  tool_schemas.py).
- get_user_profile failure -> upstream_error (NOT silent fallback to
  "include everyone in the recipient set").
- Threading headers handled by build_email_message via
  reply_to_message_id + reply_to_references; we do not roll our own
  In-Reply-To/References.

Idempotency cache
----------------------------------
Same cache as send_email. Cache key = (auth0_sub, account_email,
idempotency_key). Caller-facing tool description warns that the
cache is shared between send_email and reply_all, so reusing the
same key for both produces a cache hit and skips the second tool.
"""

from __future__ import annotations

from typing import Any

from .errors import bad_request_error, upstream_error
from .gmail_client import GmailApiError, GmailClient
from .idempotency import IdempotencyCache, default_cache
from .message_format import (
    Attachment,
    OversizeMessage,
    build_email_message,
    message_to_base64url,
)


# Hard cap mirrored from tool_schemas.EMAIL_LIST_PROP.maxItems. We
# compute the expanded recipient list from the original message
# headers, which Gmail accepts much larger sets in. Capping at the
# tool surface keeps the contract symmetric with send_email's
# explicit recipient lists.
_MAX_EXPANDED_RECIPIENTS = 100


def _split_address_list(value: str | None) -> list[str]:
    """Split a comma-separated address header into individual entries.

    RFC 5322 address lists are comma-separated and may include angle-
    bracketed forms ("Name <addr@host>"). For reply_all we only need
    the bare addresses. We extract the angle-bracketed value when
    present, otherwise use the trimmed value. Empty or None header
    yields an empty list.
    """
    if not value:
        return []
    out: list[str] = []
    for piece in value.split(","):
        piece = piece.strip()
        if not piece:
            continue
        if "<" in piece and ">" in piece:
            start = piece.find("<")
            end = piece.find(">", start)
            if end > start:
                bare = piece[start + 1 : end].strip()
                if bare:
                    out.append(bare)
                    continue
        out.append(piece)
    return out


def _extract_header(message: dict[str, Any], name: str) -> str | None:
    """Return the value of header `name` from a Gmail message payload, or None.

    Gmail's `payload.headers` is a list of {name, value} dicts. The
    name match is case-insensitive per RFC 5322. Returns the first
    match; duplicate header names (legal for some headers) are
    ignored beyond the first.
    """
    payload = message.get("payload")
    if not isinstance(payload, dict):
        return None
    headers = payload.get("headers")
    if not isinstance(headers, list):
        return None
    target = name.lower()
    for h in headers:
        if not isinstance(h, dict):
            continue
        hname = h.get("name")
        if isinstance(hname, str) and hname.lower() == target:
            v = h.get("value")
            return v if isinstance(v, str) else None
    return None


def _looks_like_email(addr: str) -> bool:
    if not isinstance(addr, str):
        return False
    if addr.count("@") != 1:
        return False
    local, _, domain = addr.partition("@")
    return bool(local) and bool(domain)


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
    attachments: list[Attachment] | None = None,
    idempotency_key: str | None = None,
    cache: IdempotencyCache | None = None,
) -> dict[str, Any]:
    """Reply to all recipients of `message_id`.

    The argument is named `message_id` so dispatch.py's audit harvest
    binds the source-message ID into the audit line. Returns the Gmail
    send response (id + threadId) or a typed error dict on failure
    (bad_request_error, not_found_error via the dispatcher's
    GmailApiError mapping, upstream_error on getProfile failure).

    Recipient computation:
      - From original `From`             -> reply To.
      - From original `To` + `Cc`        -> reply Cc (minus self).
      - Self resolved via getProfile.
      - Expanded recipient set capped at _MAX_EXPANDED_RECIPIENTS
        (100 by default).

    Threading:
      - Subject prefixed with "Re: " unless the original already
        starts with "Re:" (case-insensitive). RFC 5322 does not
        prescribe a strict canonical form; "Re: " is the convention
        every major MUA uses.
      - In-Reply-To set to original Message-ID.
      - References set to original Message-ID (single-element chain
        is the common case; if the original itself had a References
        header we append; otherwise we use Message-ID as the chain).
    """
    # ---- idempotency cache (READ side) ------------------------------------
    cache_obj = cache if cache is not None else default_cache
    cache_key: tuple[str, str, str] | None = None
    if idempotency_key is not None:
        if not isinstance(idempotency_key, str) or not idempotency_key:
            return bad_request_error("idempotency_key must be a non-empty string")
        cache_key = (auth0_sub, account_email, idempotency_key)
        cached = cache_obj.get(cache_key)
        if cached is not None:
            return cached

    # ---- fetch original message (metadata is enough for headers) ----------
    # 404 / other Gmail errors propagate to the dispatcher's error mapper
    # (route_tool catches GmailApiError and converts to a typed error
    # dict). reply_all does not catch them locally because the only
    # behavior we would add is "convert to not_found", and the
    # dispatcher already does that consistently for every tool.
    original = await client.get_message(
        message_id=message_id,
        format="metadata",
    )

    # ---- fetch self email via getProfile (N1: never silent fallback) ------
    try:
        profile = await client.get_user_profile()
    except GmailApiError as exc:
        # getProfile failure is not a caller-input bug; surface it as
        # an upstream error rather than silently treating "self" as
        # the empty string (which would let the linked account
        # appear in its own reply Cc list).
        return upstream_error(
            f"could not fetch user profile to compute reply-all recipients: {exc}",
            status=exc.status if exc.status else None,
        )
    self_email = profile.get("emailAddress")
    if not isinstance(self_email, str) or not self_email:
        return upstream_error("getProfile returned no emailAddress")
    self_email_lower = self_email.strip().lower()

    # ---- compute recipients -----------------------------------------------
    from_header = _extract_header(original, "From") or ""
    to_header = _extract_header(original, "To")
    cc_header = _extract_header(original, "Cc")
    subject_header = _extract_header(original, "Subject") or ""
    message_id_header = _extract_header(original, "Message-ID") or _extract_header(
        original, "Message-Id"
    )
    references_header = _extract_header(original, "References")

    from_addrs = _split_address_list(from_header)
    to_addrs = _split_address_list(to_header)
    cc_addrs = _split_address_list(cc_header)

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
        if _looks_like_email(addr):
            reply_to.append(addr)

    reply_cc: list[str] = []
    for addr in to_addrs + cc_addrs:
        key = addr.lower()
        if key == self_email_lower:
            continue
        if key in seen:
            continue
        seen.add(key)
        if _looks_like_email(addr):
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

    # ---- build the message ------------------------------------------------
    try:
        msg = build_email_message(
            sender=self_email,
            to=reply_to or [self_email],  # extreme degenerate: reply to self only
            subject=new_subject,
            body_text=body_text,
            cc=reply_cc or None,
            attachments=attachments,
            reply_to_message_id=message_id_header,
            reply_to_references=refs_list,
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
