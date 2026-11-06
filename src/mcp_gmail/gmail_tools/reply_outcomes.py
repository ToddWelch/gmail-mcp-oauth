"""What follows the reply-threading decision: errors, verification, replay and audit.

reply_threading.py decides whether a message may go and which thread it must
land in. This module holds what happens around that decision: the typed errors,
comparing the thread Gmail reports with the expected one, telling a true
idempotent replay from a reused key, and turning those errors into an audit line.

Nothing here logs a subject, recipient or Message-ID. Audit fields are the
closed set of reason codes below plus Gmail's opaque ids.
"""

from __future__ import annotations

import logging
from typing import Any

from .errors import ToolErrorCode, tool_error
from .gmail_client import GmailApiError
from .idempotency import CacheKey, IdempotencyCache

logger = logging.getLogger(__name__)

REASON_NO_REPLY_TARGET = "no_reply_target"
REASON_INVALID_MESSAGE_ID = "invalid_message_id"
REASON_TARGET_NOT_FOUND = "reply_target_not_found"
REASON_TARGET_AMBIGUOUS = "reply_target_ambiguous"
REASON_SUBJECT_MISMATCH = "subject_mismatch"
REASON_THREAD_CONFLICT = "thread_conflict"
REASON_LOOKUP_FAILED = "lookup_failed"
REASON_READ_SCOPE_MISSING = "read_scope_missing"
REASON_IDEMPOTENCY_KEY_REUSED = "idempotency_key_reused"
REASON_THREAD_MISMATCH = "thread_mismatch"
REASON_SEND_OUTCOME_UNKNOWN = "send_outcome_unknown"

_REFUSAL_REASONS = frozenset(
    {
        REASON_NO_REPLY_TARGET,
        REASON_INVALID_MESSAGE_ID,
        REASON_TARGET_NOT_FOUND,
        REASON_TARGET_AMBIGUOUS,
        REASON_SUBJECT_MISMATCH,
        REASON_THREAD_CONFLICT,
        REASON_LOOKUP_FAILED,
        REASON_READ_SCOPE_MISSING,
        REASON_IDEMPOTENCY_KEY_REUSED,
    }
)

# Results that describe a message which left, or may have. A replay must return
# these rather than send again.
_REPLAYED_ERROR_CODES = frozenset(
    {ToolErrorCode.THREAD_MISMATCH, ToolErrorCode.SEND_OUTCOME_UNKNOWN}
)


def threading_refused_error(message: str, *, reason: str, **details: Any) -> dict[str, Any]:
    """A reply that could not be threaded was refused and nothing went out.

    `reason` comes from the closed set above and is what the audit line records.
    `details` go to the caller only, never to a log.
    """
    return tool_error(
        ToolErrorCode.THREADING_REFUSED,
        f"{message} Nothing was sent.",
        error_data={"reason": reason, "nothing_sent": True, **details},
    )


def thread_mismatch_error(
    *,
    expected_thread_id: str,
    actual_thread_id: str | None,
    sent_message_id: str | None = None,
    draft_id: str | None = None,
) -> dict[str, Any]:
    """A message landed outside its thread: an error, so no caller can report success.

    With `sent_message_id` the mail has already gone out, and the message says so
    plainly so nobody retries into a duplicate. With `draft_id` nothing went out.
    """
    if draft_id is not None:
        message = (
            f"Draft {draft_id} was saved in thread {actual_thread_id}, not the expected "
            f"thread {expected_thread_id}. Do not send it."
        )
    else:
        message = (
            f"The message WAS SENT but landed in thread {actual_thread_id}, not the expected "
            f"thread {expected_thread_id}. Do not resend it and do not report it as threaded."
        )
    return tool_error(
        ToolErrorCode.THREAD_MISMATCH,
        message,
        error_data={
            "reason": REASON_THREAD_MISMATCH,
            "expected_thread_id": expected_thread_id,
            "actual_thread_id": actual_thread_id,
            "sent_message_id": sent_message_id,
            "draft_id": draft_id,
        },
    )


def unknown_outcome_or_raise(exc: GmailApiError) -> dict[str, Any]:
    """Classify a failed send POST: raises a definite failure, returns an unknown one.

    A 4xx means Gmail refused the message, so it stays retryable and goes to the
    dispatcher's normal error mapping. A network error or a 5xx may have happened
    after Gmail accepted it, so resending could mail a real person twice. That
    result is returned for the caller to see and for a replay to repeat.
    """
    if 0 < exc.status < 500:
        raise exc
    return tool_error(
        ToolErrorCode.SEND_OUTCOME_UNKNOWN,
        f"Gmail did not confirm this send (status {exc.status}), so it may or may not have "
        "gone out. Check the Sent folder before resending. Retrying with the same "
        "idempotency_key returns this error without sending; a new key sends again.",
        error_data={"reason": REASON_SEND_OUTCOME_UNKNOWN, "status": exc.status},
    )


def verify_sent_thread(result: dict[str, Any], expected_thread_id: str | None) -> dict[str, Any]:
    """After a send: a landing in any other thread is an error, never a success."""
    if expected_thread_id is None:
        return result
    actual = result.get("threadId")
    if actual == expected_thread_id:
        return result
    sent_id = result.get("id")
    logger.error(
        "reply landed outside its thread: expected_thread_id=%s actual_thread_id=%s "
        "sent_message_id=%s",
        expected_thread_id,
        actual,
        sent_id,
    )
    return thread_mismatch_error(
        expected_thread_id=expected_thread_id,
        actual_thread_id=actual if isinstance(actual, str) else None,
        sent_message_id=sent_id if isinstance(sent_id, str) else None,
    )


def verify_draft_thread(result: dict[str, Any], expected_thread_id: str | None) -> dict[str, Any]:
    """After a draft save: a draft filed in the wrong thread must not read as success."""
    if expected_thread_id is None:
        return result
    message = result.get("message")
    actual = message.get("threadId") if isinstance(message, dict) else None
    if actual == expected_thread_id:
        return result
    draft_id = result.get("id")
    logger.error(
        "draft saved outside its thread: expected_thread_id=%s actual_thread_id=%s draft_id=%s",
        expected_thread_id,
        actual,
        draft_id,
    )
    return thread_mismatch_error(
        expected_thread_id=expected_thread_id,
        actual_thread_id=actual if isinstance(actual, str) else None,
        draft_id=draft_id if isinstance(draft_id, str) else "unknown",
    )


def attachment_identity(attachments: Any) -> Any:
    """Attachments as they count toward a replay's fingerprint.

    An upload token is one-time, so a retry after an uncertain send legitimately
    carries a fresh one. It is left out so that retry stays a replay.
    """
    if not attachments or not isinstance(attachments, list):
        return attachments or None
    return [
        {k: v for k, v in a.items() if k != "upload_token"} if isinstance(a, dict) else a
        for a in attachments
    ]


def replayed_result(
    *, cache: IdempotencyCache, key: CacheKey | None, fingerprint: str
) -> dict[str, Any] | None:
    """A cached result only for a true replay of the call that produced it.

    The same key on a different tool, sender, recipient, subject, reply target,
    body or attachment is a different message, and handing back the old result
    would report success for a message that never went out.
    """
    if key is None:
        return None
    cached = cache.get(key)
    if cached is None:
        return None
    if cache.fingerprint_of(key) != fingerprint:
        return threading_refused_error(
            "idempotency_key was already used in the last 60 seconds for a different message. "
            "Use a new key.",
            reason=REASON_IDEMPOTENCY_KEY_REUSED,
        )
    return cached


def cacheable_send_result(result: dict[str, Any]) -> bool:
    """True once a message left or may have: success, wrong thread, or unknown outcome.

    A refusal sent nothing, so a retry deserves a fresh evaluation.
    """
    code = result.get("code")
    return not isinstance(code, int) or code in _REPLAYED_ERROR_CODES


def threading_audit_fields(result: Any) -> dict[str, Any]:
    """Audit overrides for a threading refusal or mismatch; empty for anything else."""
    if not isinstance(result, dict):
        return {}
    data = result.get("data")
    error_data = data.get("error_data") if isinstance(data, dict) else None
    if not isinstance(error_data, dict):
        return {}
    reason = error_data.get("reason")
    if reason == REASON_THREAD_MISMATCH:
        fields: dict[str, Any] = {
            "outcome": "thread_mismatch",
            "reason": reason,
            "thread_id": error_data.get("expected_thread_id"),
            "actual_thread_id": error_data.get("actual_thread_id"),
        }
        if error_data.get("sent_message_id"):
            fields["message_id"] = error_data["sent_message_id"]
        if error_data.get("draft_id"):
            fields["draft_id"] = error_data["draft_id"]
        return fields
    if reason == REASON_SEND_OUTCOME_UNKNOWN:
        return {"outcome": "send_outcome_unknown", "reason": reason}
    if reason in _REFUSAL_REASONS:
        fields = {"outcome": "threading_refused", "reason": reason}
        if error_data.get("thread_id"):
            fields["thread_id"] = error_data["thread_id"]
        return fields
    return {}
