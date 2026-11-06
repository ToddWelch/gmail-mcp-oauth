"""Thread checks on drafts already stored in Gmail.

A draft can reach these tools from anywhere: this connector, an older version of
it, or the Gmail UI. So send_draft and update_draft read what the draft actually
holds instead of trusting how it was made.

Confirmed against real Gmail on 2026-11-06: a new-conversation draft's threadId
equals its message id; a draft with a threadId but no reply headers keeps that
thread and a different message id; update_draft with no thread gives the draft a
brand-new thread (both ids change); and drafts.send returns the draft's threadId
unchanged, so it can be compared afterward.
"""

from __future__ import annotations

from typing import Any

from .errors import not_found_error
from .gmail_client import GmailApiError, GmailClient
from .reply_outcomes import REASON_NO_REPLY_TARGET, threading_refused_error
from .reply_recipients import extract_header
from .reply_threading import lookup_failed, read_scope_refusal, resolve_expected_thread
from .scope_check import SCOPE_COMPOSE, SCOPE_READONLY, granted_scope_satisfies


async def _read_draft_message(
    *, client: GmailClient, draft_id: str
) -> tuple[dict[str, Any], str] | dict[str, Any]:
    """The draft's message and own thread id, or a typed error. Nothing went out."""
    try:
        draft = await client.get_draft(draft_id=draft_id, format="metadata")
    except GmailApiError as exc:
        if exc.status == 404:
            return not_found_error(f"draft not found: {draft_id}")
        return lookup_failed(f"gmail returned {exc.status}", exc=exc)

    message = draft.get("message")
    payload = message.get("payload") if isinstance(message, dict) else None
    headers = payload.get("headers") if isinstance(payload, dict) else None
    own_thread = message.get("threadId") if isinstance(message, dict) else None
    # Absent headers must not read as "not a reply".
    if not headers or not isinstance(own_thread, str) or not own_thread:
        return lookup_failed("draft came back without headers or a thread id")
    return message, own_thread


async def expected_thread_for_draft(
    *, client: GmailClient, draft_id: str, granted_scope: str
) -> str | dict[str, Any]:
    """Check a stored draft before it goes out; return the thread it must land in."""
    can_read_draft = granted_scope_satisfies(
        required=SCOPE_COMPOSE, granted_scope=granted_scope
    ) or granted_scope_satisfies(required=SCOPE_READONLY, granted_scope=granted_scope)
    if not can_read_draft:
        return read_scope_refusal(
            granted_scope=granted_scope, required=SCOPE_COMPOSE, what="send_draft"
        )

    read = await _read_draft_message(client=client, draft_id=draft_id)
    if isinstance(read, dict):
        return read
    message, own_thread = read

    references = extract_header(message, "References")
    expected = await resolve_expected_thread(
        client=client,
        subject=extract_header(message, "Subject") or "",
        reply_to_message_id=extract_header(message, "In-Reply-To"),
        reply_to_references=[references] if references else None,
        granted_scope=granted_scope,
        thread_id=own_thread,
    )
    return expected if isinstance(expected, dict) else own_thread


async def refuse_if_update_drops_thread(
    *, client: GmailClient, draft_id: str
) -> dict[str, Any] | None:
    """Refuse an update that would silently pull a reply draft out of its conversation.

    An update is a full replace, and one carrying no thread gives the draft a new
    thread. With a subject that has no Re:, nothing else would catch it, and the
    reply would go out later as a new conversation with success at both steps.
    Returns None when the draft is already a new conversation.
    """
    read = await _read_draft_message(client=client, draft_id=draft_id)
    if isinstance(read, dict):
        return read
    message, own_thread = read

    in_conversation = (
        own_thread != message.get("id")
        or extract_header(message, "In-Reply-To") is not None
        or extract_header(message, "References") is not None
    )
    if not in_conversation:
        return None
    return threading_refused_error(
        "This draft is a reply, and updating it without reply_to_message_id or thread_id "
        "would pull it out of its conversation. Pass the same reply_to_message_id or "
        "thread_id again. To start a new conversation, delete it and create a new draft.",
        reason=REASON_NO_REPLY_TARGET,
        thread_id=own_thread,
    )
