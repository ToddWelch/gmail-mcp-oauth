"""Write-side draft tools: create_draft, update_draft.

Drafts are Gmail's server-side scratch space for messages that have
not been sent. Body construction reuses the same build_email_message
helper as send_email (25 MiB encoded-size cap, threading headers).

The non-building draft lifecycle tools (list_drafts, send_draft,
delete_draft) live in drafts_lifecycle.py and are re-exported here so
`drafts.list_drafts` / `drafts.send_draft` / `drafts.delete_draft` and
the write router keep resolving unchanged.

Scope split: create / update require gmail.compose. Each tool maps Gmail
404 -> not_found_error and lets other Gmail errors propagate to the
dispatcher's error mapper.
"""

from __future__ import annotations

import logging
from typing import Any

from .attachment_source import consume_slots
from .drafts_lifecycle import (  # noqa: F401  re-exported for router + test back-compat
    delete_draft,
    list_drafts,
    send_draft,
)
from .errors import bad_request_error, not_found_error
from .gmail_client import GmailApiError, GmailClient
from .message_format import (
    Attachment,
    InvalidHeaderValue,
    OversizeMessage,
    build_email_message,
    message_to_base64url,
)

logger = logging.getLogger(__name__)


# Helper: build the same shape send_email builds, without idempotency.
def _build_raw_message(
    *,
    sender: str,
    to: list[str],
    subject: str,
    body_text: str,
    cc: list[str] | None,
    bcc: list[str] | None,
    attachments: list[Attachment] | None,
    reply_to_message_id: str | None,
    reply_to_references: list[str] | None,
) -> str | dict[str, Any]:
    """Build an EmailMessage and return its base64url-encoded form, or an error dict."""
    try:
        msg = build_email_message(
            sender=sender,
            to=to,
            subject=subject,
            body_text=body_text,
            cc=cc,
            bcc=bcc,
            attachments=attachments,
            reply_to_message_id=reply_to_message_id,
            reply_to_references=reply_to_references,
        )
    except OversizeMessage as exc:
        return bad_request_error(str(exc))
    except InvalidHeaderValue as exc:
        # Control character in a specific header field (covers both
        # create_draft and update_draft, which route through here). Typed,
        # field-named bad_request BEFORE any consume. Never log the value.
        logger.warning("draft build rejected a control character in a header field")
        return bad_request_error(f"{exc.field} contains control characters")
    except ValueError:
        # A malformed caller-supplied header/attachment value (e.g. CR/LF in
        # a filename or mime_type that slipped past proactive checks) makes
        # EmailMessage raise ValueError. Map to a typed bad_request BEFORE
        # any consume so no slot is burned. Never log recipients/filename/bytes.
        logger.warning("draft message build rejected a malformed header/attachment value")
        return bad_request_error("message could not be built from the provided headers/attachments")
    return message_to_base64url(msg)


# ---------------------------------------------------------------------------
# Tool: create_draft
# ---------------------------------------------------------------------------


async def create_draft(
    *,
    client: GmailClient,
    sender: str,
    to: list[str],
    subject: str,
    body_text: str,
    cc: list[str] | None = None,
    bcc: list[str] | None = None,
    attachments: list[Attachment] | None = None,
    reply_to_message_id: str | None = None,
    reply_to_references: list[str] | None = None,
    thread_id: str | None = None,
    auth0_sub: str = "",
    account_email: str = "",
    consume_token_hashes: list[str] | None = None,
) -> dict[str, Any]:
    """Create a Gmail draft from message-construction inputs.

    Body built via the same EmailMessage helper send_email uses (25 MiB
    cap + threading identical). Returns Gmail's response ({id, message,
    timestamps}). optional `thread_id` sets `message.threadId` (the
    authoritative thread join; header inference is the fallback), shape-
    validated in `client.create_draft` via `gmail_id.validate_gmail_id`.

    Upload-slot attachments are pre-loaded by the router; their
    `consume_token_hashes` are consumed AFTER a successful build and
    BEFORE the Gmail POST, so an oversize draft never burns a slot.
    """
    raw = _build_raw_message(
        sender=sender,
        to=to,
        subject=subject,
        body_text=body_text,
        cc=cc,
        bcc=bcc,
        attachments=attachments,
        reply_to_message_id=reply_to_message_id,
        reply_to_references=reply_to_references,
    )
    if isinstance(raw, dict):  # error dict (oversize/malformed) -> NO slot consumed
        return raw
    consume_err = consume_slots(
        token_hashes=consume_token_hashes or [],
        auth0_sub=auth0_sub,
        account_email=account_email,
    )
    if consume_err is not None:  # lost a race; do NOT create the draft
        return consume_err
    return await client.create_draft(raw_message=raw, thread_id=thread_id)


# ---------------------------------------------------------------------------
# Tool: update_draft
# ---------------------------------------------------------------------------


async def update_draft(
    *,
    client: GmailClient,
    draft_id: str,
    sender: str,
    to: list[str],
    subject: str,
    body_text: str,
    cc: list[str] | None = None,
    bcc: list[str] | None = None,
    attachments: list[Attachment] | None = None,
    reply_to_message_id: str | None = None,
    reply_to_references: list[str] | None = None,
    thread_id: str | None = None,
    auth0_sub: str = "",
    account_email: str = "",
    consume_token_hashes: list[str] | None = None,
) -> dict[str, Any]:
    """Replace an existing draft's contents (full PUT; body wholly
    replaces the prior draft, no partial-update path). On 404 returns
    not_found_error. optional `thread_id` sets `message.threadId`, shape-
    validated in `client.update_draft` via `gmail_id.validate_gmail_id`.
    Upload-slot attachments are consumed AFTER a successful build and
    BEFORE the Gmail PUT (an oversize draft never burns a slot). When
    upload slots are at stake, a not-found existence check runs BEFORE
    consume so a stale draft_id (ordinary caller error) never burns a
    one-time handle.
    """
    raw = _build_raw_message(
        sender=sender,
        to=to,
        subject=subject,
        body_text=body_text,
        cc=cc,
        bcc=bcc,
        attachments=attachments,
        reply_to_message_id=reply_to_message_id,
        reply_to_references=reply_to_references,
    )
    if isinstance(raw, dict):  # error dict (oversize/malformed) -> NO slot consumed
        return raw
    token_hashes = consume_token_hashes or []
    # Rule out draft-not-found BEFORE consuming: a stale/typo'd draft_id
    # is a caller-input error, not the documented post-consume Gmail
    # failure, so it must not burn a one-time upload handle. Only pay the
    # extra GET when there are upload slots to protect.
    if token_hashes:
        try:
            await client.get_draft(draft_id=draft_id)
        except GmailApiError as exc:
            if exc.status == 404:
                return not_found_error(f"draft not found: {draft_id}")
            raise
    consume_err = consume_slots(
        token_hashes=token_hashes,
        auth0_sub=auth0_sub,
        account_email=account_email,
    )
    if consume_err is not None:  # lost a race; do NOT update the draft
        return consume_err
    try:
        return await client.update_draft(
            draft_id=draft_id,
            raw_message=raw,
            thread_id=thread_id,
        )
    except GmailApiError as exc:
        if exc.status == 404:
            return not_found_error(f"draft not found: {draft_id}")
        raise
