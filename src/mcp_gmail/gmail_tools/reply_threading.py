"""The reply guarantee: a reply lands in its conversation, or it does not send.

Every send-capable tool goes through this module. It exists because of
2026-11-06: a reply with correct In-Reply-To, References and Subject went out
as a new conversation, since a Gmail API send with no `threadId` starts a new
thread whatever the headers say. So the server finds the thread itself, and no
caller can forget it, including a client still holding a cached tool schema.

Facts confirmed against real Gmail on 2026-11-06:
- `rfc822msgid:` matches a whole Message-ID only; a partial id returns nothing.
  Bare, angle-bracketed and quoted forms all match. Quoted is used here so
  characters that mean something to the search syntax stay literal.
- A search with no hits has no `messages` key at all.
- Asking for `Message-ID` returns a header named `Message-Id`, so header lookups
  must be case-insensitive (extract_header is).
- A long non-ASCII subject comes back decoded and unfolded.
- headers + matching Subject without threadId: a new thread (the incident).
- threadId + a different Subject: Gmail still joined the thread. The subject
  refusal below is deliberately stricter than Gmail is: other people's mail
  clients group by subject and headers, and Gmail's docs require the match.

Refusals return a typed error and consume nothing. They are not cached, so a
corrected retry under the same idempotency key still works. draft_threading.py
applies this to stored drafts; reply_outcomes.py holds the errors, the post-send
verification, the replay check and the audit fields.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Any

from .errors import scope_insufficient_error
from .gmail_client import GmailApiError, GmailClient
from .reply_outcomes import (
    REASON_INVALID_MESSAGE_ID,
    REASON_LOOKUP_FAILED,
    REASON_NO_REPLY_TARGET,
    REASON_READ_SCOPE_MISSING,
    REASON_SUBJECT_MISMATCH,
    REASON_TARGET_AMBIGUOUS,
    REASON_TARGET_NOT_FOUND,
    REASON_THREAD_CONFLICT,
    threading_refused_error,
)
from .reply_recipients import extract_header
from .scope_check import SCOPE_READONLY, _sufficient_alternatives, granted_scope_satisfies

# One page. More hits than this could hide a second thread, so overflow refuses.
_MAX_MATCHES = 10

_REPLY_PREFIX = re.compile(r"^\s*re\s*(?:\[\d+\])?\s*:", re.IGNORECASE)
_ANY_PREFIX = re.compile(r"^(?:re|fwd?)\s*(?:\[\d+\])?\s*:\s*", re.IGNORECASE)
_UNSAFE_ID_CHARS = re.compile(r'[\s<>"\x00-\x1f\x7f]')


@dataclass(frozen=True)
class _ReplyTarget:
    thread_id: str
    subject: str


def normalize_subject(subject: str) -> str:
    """Comparable form: no Re:/Fwd: prefixes, collapsed whitespace, casefolded."""
    text = " ".join(unicodedata.normalize("NFC", subject).split())
    while (stripped := _ANY_PREFIX.sub("", text, count=1)) != text:
        text = stripped
    return text.casefold()


def is_reply_subject(subject: str) -> bool:
    return _REPLY_PREFIX.match(subject) is not None


def bare_message_id(value: str) -> str | None:
    """The id without angle brackets, or None when it cannot be a single Message-ID."""
    text = value.strip()
    if text.startswith("<") and text.endswith(">"):
        text = text[1:-1].strip()
    if not text or _UNSAFE_ID_CHARS.search(text):
        return None
    return text


def canonical_message_id(value: str | None) -> str | None:
    """The bracketed header form. A value that cannot be an id is returned as is,
    because the resolver refuses it before any message is built."""
    if value is None:
        return None
    bare = bare_message_id(value)
    return f"<{bare}>" if bare is not None else value


def read_scope_refusal(*, granted_scope: str, required: str, what: str) -> dict[str, Any]:
    err = scope_insufficient_error(
        required_scopes=[required],
        granted_scope=granted_scope,
        sufficient_alternatives=_sufficient_alternatives(required),
    )
    err["message"] = (
        f"{what} needs read access to confirm the conversation, and this linked account "
        "does not have it. Nothing was sent. Re-link the account at /oauth/start."
    )
    err["data"]["error_data"]["reason"] = REASON_READ_SCOPE_MISSING
    return err


def lookup_failed(detail: str, *, exc: GmailApiError | None = None) -> dict[str, Any]:
    details: dict[str, Any] = {}
    next_step = "Retry shortly."
    if exc is not None:
        details["status"] = exc.status
        if exc.retry_after_seconds is not None:
            details["retry_after_seconds"] = exc.retry_after_seconds
        if exc.status in (401, 403):
            next_step = "If this keeps happening, re-link the account at /oauth/start."
    return threading_refused_error(
        f"Could not confirm the conversation for this reply ({detail}). {next_step}",
        reason=REASON_LOOKUP_FAILED,
        **details,
    )


async def _find_reply_target(*, client: GmailClient, bare_id: str) -> _ReplyTarget | dict[str, Any]:
    """Search the mailbox for one Message-ID. Every failure is a refusal."""
    try:
        listing = await client.find_messages_by_rfc822_id(
            rfc822_id=bare_id, max_results=_MAX_MATCHES
        )
        if listing.get("nextPageToken"):
            return threading_refused_error(
                "reply_to_message_id matches more messages than can be checked.",
                reason=REASON_TARGET_AMBIGUOUS,
            )
        matches: list[_ReplyTarget] = []
        for stub in listing.get("messages") or []:
            gmail_id = stub.get("id")
            if not isinstance(gmail_id, str):
                return lookup_failed("search hit had no message id")
            message = await client.get_message(
                message_id=gmail_id,
                format="metadata",
                metadata_headers=["Message-ID", "Subject"],
            )
            # The search narrows; this exact comparison is what decides.
            header = extract_header(message, "Message-ID")
            if header is None or bare_message_id(header) != bare_id:
                continue
            thread_id = message.get("threadId")
            if not isinstance(thread_id, str) or not thread_id:
                return lookup_failed("search hit had no thread id")
            matches.append(_ReplyTarget(thread_id, extract_header(message, "Subject") or ""))
    except GmailApiError as exc:
        return lookup_failed(f"gmail returned {exc.status}", exc=exc)
    except ValueError:
        # validate_gmail_id rejected an id Gmail handed back.
        return lookup_failed("search hit had a malformed message id")

    if not matches:
        return threading_refused_error(
            "reply_to_message_id was not found in this mailbox. It must be the Message-ID "
            "header of the message being replied to (the <id@host> value from read_email "
            "format=metadata), not Gmail's message id. If the message only just arrived, "
            "retry in a minute.",
            reason=REASON_TARGET_NOT_FOUND,
        )
    thread_ids = sorted({m.thread_id for m in matches})
    if len(thread_ids) > 1:
        return threading_refused_error(
            "reply_to_message_id matches messages in more than one conversation.",
            reason=REASON_TARGET_AMBIGUOUS,
            thread_ids=thread_ids,
        )
    return matches[0]


async def resolve_expected_thread(
    *,
    client: GmailClient,
    subject: str,
    reply_to_message_id: str | None,
    reply_to_references: list[str] | None,
    granted_scope: str,
    thread_id: str | None = None,
) -> str | None | dict[str, Any]:
    """The thread this message must land in, None for a new conversation, or a refusal.

    `thread_id` is a caller's explicit join (drafts). With no reply target it is
    returned unchanged; with one it must agree with the thread that target is in.
    """
    if reply_to_message_id is None:
        if is_reply_subject(subject) or reply_to_references:
            return threading_refused_error(
                "This looks like a reply but has no reply_to_message_id, so it would start a "
                "new conversation. Pass the Message-ID of the message being replied to. A "
                "genuinely new email can drop the Re: from its subject.",
                reason=REASON_NO_REPLY_TARGET,
            )
        return thread_id

    if not granted_scope_satisfies(required=SCOPE_READONLY, granted_scope=granted_scope):
        return read_scope_refusal(
            granted_scope=granted_scope, required=SCOPE_READONLY, what="A reply"
        )

    bare_id = bare_message_id(reply_to_message_id)
    if bare_id is None:
        return threading_refused_error(
            "reply_to_message_id is not a single valid Message-ID.",
            reason=REASON_INVALID_MESSAGE_ID,
        )

    target = await _find_reply_target(client=client, bare_id=bare_id)
    if isinstance(target, dict):
        return target

    if normalize_subject(subject) != normalize_subject(target.subject):
        # The replied-to subject is text an outside sender wrote, and agents act on what
        # this message says, so it must never go in the message: a hostile subject would
        # read as the connector's own instruction. It stays a labelled field in error data.
        return threading_refused_error(
            "The subject does not match the message being replied to, so Gmail could start "
            "a new conversation. Read that message and reuse its Subject, with or without Re:.",
            reason=REASON_SUBJECT_MISMATCH,
            expected_subject=target.subject,
            thread_id=target.thread_id,
        )
    if thread_id is not None and thread_id != target.thread_id:
        return threading_refused_error(
            f"thread_id {thread_id} conflicts with reply_to_message_id, which is in thread "
            f"{target.thread_id}.",
            reason=REASON_THREAD_CONFLICT,
            thread_id=target.thread_id,
            requested_thread_id=thread_id,
        )
    return target.thread_id
