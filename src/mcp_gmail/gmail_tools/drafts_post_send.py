"""send_draft post-send action helper.

Split out of drafts.py to honor the 300-LOC-per-file rule. The
send_draft tool fans out to (a) Gmail's drafts.send and (b) optionally
a thread-level modify after the send succeeds. Step (b) is encoded
here so drafts.py stays under the 300 LOC ceiling once the new
parameters land.

Idempotency contract
-----------------------------------
- send_draft handler awaits client.send_draft first.
- If send raises GmailApiError 404: return not_found_error. NO
  post-send actions attempted. NO send retry.
- If send raises any other GmailApiError: re-raise (dispatcher's
  error mapper handles it). NO post-send actions attempted.
- If send succeeds: capture the sent message resource. Extract
  threadId. Compose the merged add/remove label lists (caller's
  add_labels / remove_labels; if archive_thread=true, append 'INBOX'
  to the remove list).
- If neither archive nor labels were requested: return the sent
  message resource as-is (back-compat byte-for-byte).
- Otherwise: call client.modify_thread inside a try/except.
- modify_thread success: return success record with
  post_send_actions.applied=true.
- modify_thread failure (any GmailApiError, ValueError, network
  error): return success record with applied=false, action_failures
  detail. The send is NEVER retried, because the message is already
  on the wire.

when archive_thread=true AND caller-supplied
remove_labels=['INBOX'], the merge is deduped before sending to
Gmail to avoid the duplicate-INBOX-in-remove-list edge case.
"""

from __future__ import annotations

from typing import Any

import httpx

from .gmail_client import GmailApiError, GmailClient


def _merged_remove_labels(
    *,
    archive_thread: bool,
    caller_remove_labels: list[str] | None,
) -> list[str] | None:
    """Compose the final remove_label_ids list.

    archive_thread=true means the user wants the source thread out of
    INBOX. We append 'INBOX' to the caller's remove_labels list
    (deduped in case the caller already supplied INBOX).
    archive_thread=false leaves the caller's list untouched.

    Returns None when neither input contributes, so the modify_thread
    request body honors the existing "skip the empty list" convention
    (gmail_client_write/_threads.py only adds the key when the list
    is truthy).
    """
    if not archive_thread:
        return list(caller_remove_labels) if caller_remove_labels else None
    base = list(caller_remove_labels) if caller_remove_labels else []
    if "INBOX" not in base:
        base.append("INBOX")
    return base


async def apply_post_send_actions(
    *,
    client: GmailClient,
    sent_message: dict[str, Any],
    archive_thread: bool,
    add_labels: list[str] | None,
    remove_labels: list[str] | None,
) -> dict[str, Any]:
    """Apply post-send modify_thread actions on the sent message's thread.

    Returns the original sent_message dict, optionally augmented with
    a `post_send_actions` block summarizing the modify_thread outcome.

    The caller (drafts.send_draft) is responsible for the early-exit
    branches:
    - If neither archive nor labels were requested, this function is
      not called (the send result returns as-is).
    - If the send itself failed, this function is not called (no
      retry, no actions).
    """
    thread_id = sent_message.get("threadId")
    final_remove = _merged_remove_labels(
        archive_thread=archive_thread,
        caller_remove_labels=remove_labels,
    )
    final_add = list(add_labels) if add_labels else None

    # Defensive: if the sent message somehow lacks a threadId we
    # cannot post the modify call. Surface as an action_failures
    # record rather than crashing.
    if not isinstance(thread_id, str) or not thread_id:
        out = dict(sent_message)
        out["post_send_actions"] = {
            "applied": False,
            "thread_id": None,
            "action_failures": [
                {
                    "action": "modify_thread",
                    "status": -1,
                    "message": "sent message resource lacked threadId",
                }
            ],
        }
        return out

    try:
        await client.modify_thread(
            thread_id=thread_id,
            add_label_ids=final_add,
            remove_label_ids=final_remove,
        )
    except (GmailApiError, httpx.RequestError, ValueError) as exc:
        out = dict(sent_message)
        out["post_send_actions"] = {
            "applied": False,
            "thread_id": thread_id,
            "action_failures": [_action_failure_record(exc)],
        }
        return out

    out = dict(sent_message)
    out["post_send_actions"] = {
        "applied": True,
        "thread_id": thread_id,
        "action_failures": [],
    }
    return out


def _action_failure_record(exc: BaseException) -> dict[str, Any]:
    """Build a single action_failures entry for a modify_thread exception."""
    record: dict[str, Any] = {"action": "modify_thread"}
    if isinstance(exc, GmailApiError):
        record["status"] = exc.status
        record["message"] = str(exc)
        if exc.retry_after_seconds is not None:
            record["retry_after_seconds"] = exc.retry_after_seconds
    elif isinstance(exc, httpx.RequestError):
        record["status"] = 0
        record["message"] = f"network error: {exc}"
    elif isinstance(exc, ValueError):
        record["status"] = -1
        record["message"] = str(exc)
    else:
        record["status"] = -1
        record["message"] = repr(exc)
    return record
