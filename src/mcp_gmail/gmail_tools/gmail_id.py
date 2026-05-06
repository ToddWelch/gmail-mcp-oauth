"""Gmail-ID validator (security: rejects path-injection IDs before HTTP interpolation).

Centralizes the regex used to validate Gmail-shaped identifiers
(message IDs, thread IDs, attachment IDs, label IDs, draft IDs, filter
IDs). An earlier security review flagged that Gmail IDs flow into URL
paths and JSON request bodies unvalidated, opening a path-traversal /
parameter-injection seam if a caller (or a compromised tool argument)
ever feeds in a value containing slashes, query separators, or other
URL-meaningful characters.

Two patterns, one job
---------------------
We deliberately use two patterns:

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

The two patterns must stay separate. Conflating them either:
  - rejects legitimate system-label IDs in path validation (the
    bug review caught), or
  - silences the audit-history caller-bug signal (regressing
    the audit observability).

Centralization
--------------
Before the audit-log refactor, `_GMAIL_ID_PATTERN` was duplicated in audit_log.py
(L70) and `_ATTACHMENT_ID_PATTERN` was duplicated in messages.py
(L43). we removed those duplicates and routes both through this
module. audit_log.py re-imports `id_looks_valid_audit_heuristic`
verbatim; messages.py re-imports `validate_gmail_id`.

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
