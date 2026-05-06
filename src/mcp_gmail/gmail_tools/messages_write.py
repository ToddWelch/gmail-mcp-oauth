"""Write-side message tools: delete_email, batch_delete_emails, modify_email_labels.

The three tools in this module mutate single-message state on Gmail.
They sit beside `messages.py` (read side) and share its conventions:
take a GmailClient, return a JSON-serializable dict, never open a DB
session, never call audit() directly. The dispatcher owns the audit
boundary.

TRASH-semantics design
----------------------
`delete_email` and `batch_delete_emails` both implement TRASH semantics
(recoverable for 30 days), not permanent delete. This is the safer
default:

- `delete_email` calls `client.trash_message`, which posts to
  `users.messages.trash` and requires `gmail.modify` scope.
- `batch_delete_emails` calls `client.batch_modify_messages` with
  `addLabelIds=['TRASH']`, which moves up to 1000 messages to TRASH in
  a single Gmail call and also requires `gmail.modify`. This avoids
  Gmail's permanent `users.messages.batchDelete` endpoint (which
  requires the broader mail.google.com/ scope) entirely.

The raw `client.delete_message` and `client.batch_delete_messages`
methods stay on the mixin in case a future PR opts into hard-delete,
but the TOOL_SCOPE_REQUIREMENTS table maps both tools to
`gmail.modify` to match the trash-semantics behavior shipped here.

`modify_email_labels` is the per-message analog of the existing
`modify_thread` tool. Same shape: an add/remove pair of label ID
lists. Used to move messages into INBOX (add INBOX), archive
(remove INBOX), mark unread (add UNREAD), star (add STARRED), and so
on. Modeled directly on Gmail's `users.messages.modify` endpoint.

Batch size cap
--------------
`batch_delete_emails` accepts up to 1000 message IDs per call (Gmail's
documented `users.messages.batchModify` limit). We enforce this in the
tool layer to fail fast with a `bad_request_error` rather than spending
a Gmail round trip on something Gmail will reject anyway.
"""

from __future__ import annotations

from typing import Any

from .errors import bad_request_error, not_found_error
from .gmail_client import GmailApiError, GmailClient


# Gmail's documented limit on users.messages.batchModify. Same number
# applies to batchDelete; we cap the trash-semantics batch_delete_emails
# tool at this so callers cannot exceed Gmail's contract.
_BATCH_MODIFY_MAX_IDS = 1000

# TRASH is a Gmail system label. Adding it via batchModify implements
# trash semantics (recoverable for 30 days). The label id literal is
# stable across mailboxes; it is not user-renameable.
_TRASH_LABEL = "TRASH"


# ---------------------------------------------------------------------------
# Tool: delete_email
# ---------------------------------------------------------------------------


async def delete_email(
    *,
    client: GmailClient,
    message_id: str,
) -> dict[str, Any]:
    """Move one message to TRASH (recoverable, gmail.modify scope).

    Maps to Gmail's `users.messages.trash` endpoint. The message is
    moved to the TRASH system label and is recoverable for 30 days
    before Gmail purges it. The design chose this over the permanent
    `users.messages.delete` endpoint to keep blast radius small; the
    TOOL_SCOPE_REQUIREMENTS table reflects the gmail.modify requirement.

    On 404 (message ID does not exist or actor cannot see it), returns
    a not_found_error rather than raising.
    """
    try:
        return await client.trash_message(message_id=message_id)
    except GmailApiError as exc:
        if exc.status == 404:
            return not_found_error(f"message not found: {message_id}")
        raise


# ---------------------------------------------------------------------------
# Tool: batch_delete_emails
# ---------------------------------------------------------------------------


async def batch_delete_emails(
    *,
    client: GmailClient,
    message_ids: list[str],
) -> dict[str, Any]:
    """Move up to 1000 messages to TRASH in one call (gmail.modify scope).

    Implementation note (resolution 1A): we use Gmail's
    `users.messages.batchModify` with `addLabelIds=['TRASH']` rather
    than `users.messages.batchDelete`. The two have different scope
    requirements:

      batchModify (TRASH label)  -> gmail.modify        recoverable
      batchDelete                -> mail.google.com/    PERMANENT

    the service ships the recoverable variant by default. The permanent
    `client.batch_delete_messages` mixin method is left in place so a
    future PR can opt in to hard-delete by changing tool wiring without
    a client-surface change.

    Returns Gmail's response body verbatim. Gmail returns 204 (empty
    body) on success; the GmailClient surfaces this as `{}`.
    """
    if not message_ids:
        return bad_request_error("message_ids must be a non-empty list")
    if len(message_ids) > _BATCH_MODIFY_MAX_IDS:
        return bad_request_error(
            f"message_ids exceeds Gmail batchModify cap of {_BATCH_MODIFY_MAX_IDS} ids"
        )
    return await client.batch_modify_messages(
        message_ids=message_ids,
        add_label_ids=[_TRASH_LABEL],
    )


# ---------------------------------------------------------------------------
# Tool: batch_modify_emails
# ---------------------------------------------------------------------------


async def batch_modify_emails(
    *,
    client: GmailClient,
    message_ids: list[str],
    add_label_ids: list[str] | None = None,
    remove_label_ids: list[str] | None = None,
) -> dict[str, Any]:
    """Add and/or remove labels across up to 1000 messages in one call.

    Bulk analog of `modify_email_labels`; same Gmail endpoint as
    `batch_delete_emails` (`users.messages.batchModify`) but without
    the TRASH-label hard-coding. Caller specifies arbitrary add/remove
    label sets. Same `_BATCH_MODIFY_MAX_IDS` cap is enforced.

    At least one of `add_label_ids` or `remove_label_ids` must be
    non-empty. The cleanup-tools design mandates rejecting both-empty as
    bad_request to mirror filters_write's empty-dict policy: a no-op
    bulk call is almost always a caller bug, and the round trip is
    pure noise. (This differs from `modify_email_labels` which still
    calls Gmail on a no-op; we chose a stricter policy for the bulk
    tool because the blast radius scales with `_BATCH_MODIFY_MAX_IDS`.)
    """
    if not message_ids:
        return bad_request_error("message_ids must be a non-empty list")
    if len(message_ids) > _BATCH_MODIFY_MAX_IDS:
        return bad_request_error(
            f"message_ids exceeds Gmail batchModify cap of {_BATCH_MODIFY_MAX_IDS} ids"
        )
    if not add_label_ids and not remove_label_ids:
        return bad_request_error(
            "batch_modify_emails requires at least one of add_label_ids or remove_label_ids"
        )
    return await client.batch_modify_messages(
        message_ids=message_ids,
        add_label_ids=add_label_ids,
        remove_label_ids=remove_label_ids,
    )


# ---------------------------------------------------------------------------
# Tool: modify_email_labels
# ---------------------------------------------------------------------------


async def modify_email_labels(
    *,
    client: GmailClient,
    message_id: str,
    add_label_ids: list[str] | None = None,
    remove_label_ids: list[str] | None = None,
) -> dict[str, Any]:
    """Add and/or remove labels on a single message (gmail.modify scope).

    Per-message analog of `modify_thread`. Same caller pattern: pass
    INBOX in `add_label_ids` to move into the inbox; pass it in
    `remove_label_ids` to archive. Both list arguments are optional
    individually but at least one should be populated for the call to
    do anything meaningful.

    No-op detection: if both lists are empty / None, we still call
    Gmail's modify endpoint. Same reasoning as modify_thread: a noisy
    audit log line for a no-op is more valuable than masking a caller
    bug that would otherwise look like a successful tool call.

    On 404 (message ID does not exist or actor cannot see it), returns
    a not_found_error.
    """
    try:
        return await client.modify_message(
            message_id=message_id,
            add_label_ids=add_label_ids,
            remove_label_ids=remove_label_ids,
        )
    except GmailApiError as exc:
        if exc.status == 404:
            return not_found_error(f"message not found: {message_id}")
        raise
