"""Write-side draft lifecycle tools: list_drafts, send_draft, delete_draft.

Split out of drafts.py (300-LOC + distinct-responsibility rule). These
three tools do NOT build a message body from caller inputs; they operate
on drafts that already exist (list them, put one on the wire, or delete
one). drafts.py keeps the body-building writes (create_draft /
update_draft) and re-exports these three so `drafts.list_drafts` /
`drafts.send_draft` / `drafts.delete_draft` and the router keep resolving.

Scope split: list / delete require gmail.compose; send_draft requires
gmail.send (actually putting a draft on the wire is a send operation) and
surfaces a handler-level gmail.modify check for optional post-send actions
(see send_draft). Each tool maps Gmail 404 -> not_found_error and lets
other Gmail errors propagate to the dispatcher's error mapper.
"""

from __future__ import annotations

from typing import Any

from .drafts_post_send import apply_post_send_actions
from .errors import bad_request_error, not_found_error
from .gmail_client import GmailApiError, GmailClient
from .scope_check import SCOPE_MODIFY, granted_scope_satisfies


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
