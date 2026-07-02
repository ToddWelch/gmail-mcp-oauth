"""Write-side draft tools: create_draft, update_draft, list_drafts, send_draft, delete_draft.

Drafts are Gmail's server-side scratch space for messages that have
not been sent. Body construction reuses the same build_email_message
helper as send_email (25 MiB encoded-size cap, threading headers).

Scope split: create / update / list / delete require gmail.compose;
send_draft requires gmail.send (actually putting a draft on the wire
is a send operation). send_draft also surfaces a handler-level
gmail.modify check for optional post-send actions; see send_draft.

send_draft does NOT take an idempotency_key. The draft itself is the
de-duplication anchor. Each tool maps Gmail 404 -> not_found_error and
lets other Gmail errors propagate to the dispatcher's error mapper.
"""

from __future__ import annotations

from typing import Any

from .attachment_source import consume_slots
from .drafts_post_send import apply_post_send_actions
from .errors import bad_request_error, not_found_error
from .gmail_client import GmailApiError, GmailClient
from .message_format import (
    Attachment,
    OversizeMessage,
    build_email_message,
    message_to_base64url,
)
from .scope_check import SCOPE_MODIFY, granted_scope_satisfies


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
    if isinstance(raw, dict):  # error dict (oversize) -> NO slot consumed
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
    if isinstance(raw, dict):  # error dict (oversize) -> NO slot consumed
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


# ---------------------------------------------------------------------------
# Tool: list_drafts
# ---------------------------------------------------------------------------


async def list_drafts(
    *,
    client: GmailClient,
    q: str | None = None,
    page_token: str | None = None,
    max_results: int | None = None,
) -> dict[str, Any]:
    """List draft messages: Gmail's `users.drafts.list` response verbatim
    (`drafts: [{id, message: {id, threadId}}, ...]` + optional
    `nextPageToken`).
    """
    return await client.list_drafts(
        q=q,
        page_token=page_token,
        max_results=max_results,
    )


# ---------------------------------------------------------------------------
# Tool: send_draft
# ---------------------------------------------------------------------------


async def send_draft(
    *,
    client: GmailClient,
    draft_id: str,
    archive_thread: bool = False,
    add_labels: list[str] | None = None,
    remove_labels: list[str] | None = None,
    granted_scope: str = "",
) -> dict[str, Any]:
    """Send an existing draft (users.drafts.send; requires gmail.send).

    Returns the sent message record (id, threadId, labelIds); the draft
    is consumed by the send. optional `archive_thread` / `add_labels` /
    `remove_labels` apply a follow-up modify_thread to the sent thread:
    send-success + action-fail returns the success record annotated with
    `post_send_actions.applied=false` + `action_failures` (send is NEVER
    retried); send-fail returns the error shape with no actions.

    Post-send actions need gmail.modify on top of gmail.send; a caller
    that requests one without gmail.modify is rejected at handler entry
    (bad_request_error -> /oauth/start), avoiding a needs_reauth AFTER
    the message was sent.
    """
    wants_post_send = bool(archive_thread or add_labels or remove_labels)
    if wants_post_send and not granted_scope_satisfies(
        required=SCOPE_MODIFY, granted_scope=granted_scope
    ):
        return bad_request_error(
            "post-send archive/labels require gmail.modify scope; "
            "re-link the account at /oauth/start to grant a broader "
            "scope, or call send_draft without archive_thread / "
            "add_labels / remove_labels"
        )

    try:
        sent = await client.send_draft(draft_id=draft_id)
    except GmailApiError as exc:
        if exc.status == 404:
            return not_found_error(f"draft not found: {draft_id}")
        raise

    if not wants_post_send:
        return sent

    return await apply_post_send_actions(
        client=client,
        sent_message=sent,
        archive_thread=archive_thread,
        add_labels=add_labels,
        remove_labels=remove_labels,
    )


# ---------------------------------------------------------------------------
# Tool: delete_draft
# ---------------------------------------------------------------------------


async def delete_draft(
    *,
    client: GmailClient,
    draft_id: str,
) -> dict[str, Any]:
    """Delete a draft by ID (permanent, not recoverable; no effect on
    sent messages). Gmail's 204 renders as `{}`.
    """
    try:
        return await client.delete_draft(draft_id=draft_id)
    except GmailApiError as exc:
        if exc.status == 404:
            return not_found_error(f"draft not found: {draft_id}")
        raise
