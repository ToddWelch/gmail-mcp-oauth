"""Write-side draft tools: create_draft, update_draft, list_drafts, send_draft, delete_draft.

Drafts are Gmail's server-side scratch space for messages that have
not been sent. Body construction reuses the same build_email_message
helper as send_email (25 MiB encoded-size cap, threading headers).

Scope split: create / update / list / delete require gmail.compose;
send_draft requires gmail.send (actually putting a draft on the wire
is a send operation). send_draft also surfaces a handler-level
gmail.modify check for optional post-send actions; see send_draft.

send_draft does NOT take an idempotency_key. The draft itself is the
de-duplication anchor: callers wanting once-only delivery either
hold the draft_id once or check list_drafts before re-calling.

Each tool maps Gmail 404 -> not_found_error and lets other Gmail
errors propagate to the dispatcher's error mapper.
"""

from __future__ import annotations

from typing import Any

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
# Drafts and sends share message construction but have different post-
# build behaviors (cache vs upload to drafts collection).
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
) -> dict[str, Any]:
    """Create a Gmail draft from message-construction inputs.

    The draft body is built via the same EmailMessage helper send_email
    uses, so the 25 MiB cap and threading headers behave identically.
    Returns Gmail's response, which has `id` (the draft id), `message`
    (the underlying message stub), and standard timestamps.

    optional `thread_id` sets `message.threadId` on the request
    body, the authoritative thread join per Gmail's threading docs.
    Header inference via `reply_to_message_id` / `reply_to_references`
    remains the fallback path Gmail uses when threadId is absent.
    Validation of the ID shape happens in `client.create_draft` via
    `gmail_id.validate_gmail_id` (defense-in-depth alongside the
    schema-layer regex on `_THREAD_ID_PROP`).
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
    if isinstance(raw, dict):  # error dict
        return raw
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
) -> dict[str, Any]:
    """Replace an existing draft's contents.

    Gmail's update_draft is a full PUT; the body wholly replaces the
    prior draft. There is no partial-update path. Callers that want to
    tweak one field have to re-supply every field they want preserved.

    On 404 (draft no longer exists), returns not_found_error.

    optional `thread_id` sets `message.threadId` on the request
    body, the authoritative thread join per Gmail's threading docs.
    Validation of the ID shape happens in `client.update_draft` via
    `gmail_id.validate_gmail_id` (defense-in-depth alongside the
    schema-layer regex on `_THREAD_ID_PROP`).
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
    if isinstance(raw, dict):  # error dict
        return raw
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
    """List draft messages.

    Returns Gmail's `users.drafts.list` response verbatim: a dict with
    `drafts: [...]` (each entry has `id` and `message: {id, threadId}`)
    and optional `nextPageToken`. A full draft fetch is one Gmail call
    per ID; this listing is the cheap way to enumerate.
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
    """Send an existing draft. Requires gmail.send scope.

    Maps to Gmail's `users.drafts.send` endpoint. Returns the sent
    message record (id, threadId, labelIds). The draft is consumed by
    the send (Gmail moves it from DRAFT to SENT label and the draft id
    no longer resolves).

    optional `archive_thread`, `add_labels`, `remove_labels`
    apply a follow-up modify_thread to the sent message's thread.
    Idempotency: send-success + action-fail returns a success record
    annotated with `post_send_actions.applied=false` and
    `action_failures`; the send is NEVER retried. Send-fail returns
    the existing error shape with no actions attempted.

    Scope: post-send actions need gmail.modify on top of the
    gmail.send the existing send_draft requires. design note
    item 22: when the caller asks for any post-send action AND has
    not granted gmail.modify (subsumed by gmail.modify, full, or
    set directly), reject at handler entry with bad_request_error
    pointing at /oauth/start. This avoids surfacing a needs_reauth
    error AFTER the message was sent.
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
    """Delete a draft by ID.

    Gmail returns 204 (empty body) on success; the GmailClient renders
    that as `{}`. Drafts are not recoverable after delete; this is a
    permanent operation but does not affect any sent messages.
    """
    try:
        return await client.delete_draft(draft_id=draft_id)
    except GmailApiError as exc:
        if exc.status == 404:
            return not_found_error(f"draft not found: {draft_id}")
        raise
