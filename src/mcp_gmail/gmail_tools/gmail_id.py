"""Gmail-ID validator (security: rejects path-injection IDs before HTTP interpolation).

Centralizes the regex used to validate Gmail-shaped identifiers
(message IDs, thread IDs, attachment IDs, label IDs, draft IDs, filter
IDs). An earlier security review flagged that Gmail IDs flow into URL
paths and JSON request bodies unvalidated, opening a path-traversal /
parameter-injection seam if a caller (or a compromised tool argument)
ever feeds in a value containing slashes, query separators, or other
URL-meaningful characters.

Three patterns, distinct jobs
-----------------------------
We deliberately use three patterns:

1. `_VALIDATION_PATTERN`  (range 1..256)
   Hard validation. Applied at every Gmail-ID interpolation site
   BEFORE the value reaches httpx (path or JSON body). Rejects any
   character outside the URL-safe alphabet, plus length-bounds the
   value so a 10MB string cannot be sent as a request component.

   The 1..256 range matters: Gmail's documented system labels
   (INBOX, SENT, DRAFT, TRASH, SPAM, IMPORTANT, STARRED, UNREAD,
   CATEGORY_*) are 4-12 chars long. The previous audit-log
   heuristic (16-128) would reject `INBOX`, `TRASH`, etc. as
   path-validation failures, breaking the `batch_delete_emails`
   flow (which posts addLabelIds=['TRASH']) and `modify_thread`
   archive flow (remove_label_ids=['INBOX']). This was caught by
   the first review pass and is now
   guarded by an explicit regression test
   (`test_batch_modify_accepts_trash_in_add_label_ids`).

   Upper bound 256 matches the JSON Schema maxLength on
   `message_id`, `thread_id`, etc. in tool_definitions.py.

2. `_AUDIT_HEURISTIC_PATTERN`  (range 16..128)
   Audit observability heuristic, retained from the
   audit_log.py. A Gmail message-/thread-ID in the wild is an
   opaque base64-ish string in the 16-128 char range; values
   outside that band are likely caller bugs (e.g. someone passing
   a raw subject line). The audit logger promotes such records
   to WARN to surface the bug. This is NOT a validation gate (the
   value has already been validated against the looser pattern),
   it is a quiet caller-bug signal in audit history.

3. `_ATTACHMENT_VALIDATION_PATTERN`  (range 16..2048)
   Hard validation for the attachment_id field only. Gmail
   attachment IDs are base64url blobs that routinely exceed the
   256-char cap used for message/thread/label IDs (observed 300+
   chars), so the attachment_id interpolation site
   (`GmailClient.get_attachment`) validates against this wider
   pattern via `validate_attachment_id`. The alphabet is identical
   to `_VALIDATION_PATTERN` (URL-safe, no slashes / query
   separators / whitespace / unicode); only the upper length bound
   differs (2048 vs 256), which keeps the DoS bound tight while
   admitting real attachment IDs. Every OTHER Gmail ID stays capped
   at 256 by `_VALIDATION_PATTERN`.

`_VALIDATION_PATTERN` and `_AUDIT_HEURISTIC_PATTERN` must stay
separate. Conflating them either:
  - rejects legitimate system-label IDs in path validation (the
    bug review caught), or
  - silences the audit-history caller-bug signal (regressing
    the audit observability).

Centralization
--------------
Before the audit-log refactor, `_GMAIL_ID_PATTERN` was duplicated in
audit_log.py and the attachment-ID pattern was duplicated in the
download tool. Both now live here and are referenced, not
re-duplicated: audit_log.py re-imports `id_looks_valid_audit_heuristic`
verbatim; gmail_client.get_attachment calls `validate_attachment_id`;
and the download_attachment handler (attachment_download.py) references
the canonical `_ATTACHMENT_VALIDATION_PATTERN` for its no-round-trip
early reject rather than compiling its own copy.

Error shape
-----------
`validate_gmail_id` raises `ValueError` rather than returning a
typed bad_request_error dict. The reason: this module is called
from inside the GmailClient (deep in the call stack) and inside
the messages.download_attachment tool (shallower). Raising a
language-level exception lets the dispatcher's existing
ValueError-to-bad_request_error wrapper in tool_router.route_tool
do the translation in one place. Tool modules that already raise
ValueError on invalid inputs (e.g. messages_write's batch-size
check) follow the same convention.
"""

from __future__ import annotations

import re


# Hard validation pattern. Lower bound 1 (system labels can be 4 chars
# but a single character is technically valid Gmail-ID-shape). Upper
# bound 256 matches the maxLength in tool_definitions.py JSON Schemas.
# Alphabet: URL-safe base64 plus underscore plus hyphen. NO slashes,
# NO query separators, NO whitespace, NO unicode.
_VALIDATION_PATTERN = re.compile(r"^[A-Za-z0-9_\-]{1,256}$")


# Audit observability heuristic. Real Gmail message-/thread-IDs in
# production are 16-128 chars; values outside that band are caller-bug
# signals. NOT a validation gate.
_AUDIT_HEURISTIC_PATTERN = re.compile(r"^[A-Za-z0-9_\-]{16,128}$")


# Hard validation pattern for the attachment_id field ONLY. Gmail
# attachment IDs are base64url blobs routinely exceeding 256 chars
# (observed 300+); the general _VALIDATION_PATTERN's 256 cap is too
# tight for them. Alphabet is identical (URL-safe, no slashes / query
# separators / whitespace / unicode); only the upper length bound
# differs. 2048 keeps the DoS bound tight while admitting real IDs.
_ATTACHMENT_VALIDATION_PATTERN = re.compile(r"^[A-Za-z0-9_\-]{16,2048}$")


def validate_gmail_id(value: object, *, field: str) -> str:
    """Hard-validate a Gmail-shaped identifier. Raises ValueError on miss.

    Used at every Gmail-ID interpolation site before the value reaches
    httpx (URL path or JSON body). The `field` argument is the name of
    the tool argument (e.g. "message_id", "draft_id", "label_id") and
    is used verbatim in the error message so the caller learns which
    field failed.

    Returns the validated string unchanged. Returning the value (rather
    than None) lets call sites do `validated_id = validate_gmail_id(x,
    field='message_id')` in one line.
    """
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string, got {type(value).__name__}")
    if not _VALIDATION_PATTERN.match(value):
        # The value is included in the message because callers see the
        # ValueError translated to a bad_request_error dict; the user
        # needs to see what they sent. The dispatcher's audit logger
        # never propagates the bad value into the audit line (the audit
        # outcome is "error" and the error_code is BAD_REQUEST).
        raise ValueError(f"{field} does not match Gmail ID pattern: {value!r}")
    return value


def validate_attachment_id(value: object, *, field: str = "attachment_id") -> str:
    """Hard-validate a Gmail attachment identifier (wider 16..2048 bound).

    Same ValueError contract as `validate_gmail_id` (raises so the
    dispatcher's ValueError-to-bad_request_error wrapper handles it in
    one place), but matches `_ATTACHMENT_VALIDATION_PATTERN` rather than
    `_VALIDATION_PATTERN`. Used at the attachment_id interpolation site
    (`GmailClient.get_attachment`). Real Gmail attachment IDs routinely
    exceed the 256-char cap used for message/thread/label IDs (observed
    300+ chars); this field gets its own wider pattern while every other
    Gmail ID stays capped at 256 by `_VALIDATION_PATTERN`.
    """
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string, got {type(value).__name__}")
    if not _ATTACHMENT_VALIDATION_PATTERN.match(value):
        raise ValueError(f"{field} does not match Gmail attachment ID pattern: {value!r}")
    return value


def id_looks_valid_audit_heuristic(value: str | None) -> bool:
    """Audit-log heuristic: does the value look like a real Gmail ID?

    Returns True for None (the caller did not supply this field) so
    the audit logger can omit it without warning. Returns True for
    values matching the 16-128 char band, False otherwise.

    Behavior preserved verbatim from the original audit_log
    `_id_looks_valid` so existing audit-log tests pass without
    modification (see test_gmail_tools_audit_log.py
    test_audit_warns_on_malformed_message_id and
    test_audit_warns_on_malformed_thread_id).
    """
    if value is None:
        return True
    if not isinstance(value, str):
        return False
    return bool(_AUDIT_HEURISTIC_PATTERN.match(value))
