"""Audit logging helper with structurally-enforced field whitelist.

Every Gmail tool dispatch emits exactly one INFO log line via this
helper at outcome (success or failure). The signature accepts ONLY
the fields that have been explicitly approved as audit-safe. Adding
a new field is a deliberate code change, not an accident at the
call site.

Approved fields
---------------------------------------------
- tool: tool name (e.g. "read_email")
- auth0_sub: JWT sub of the human invoking the tool
- account_email: linked Gmail account address
- outcome: "ok" | "error" | "unauthorized" | "not_found" | etc.
- message_id: when the tool operates on a single message
- thread_id: when the tool operates on a thread
- label_id: when the tool operates on a label
- attachment_id: when the tool operates on an attachment
- draft_id: when the tool operates on a draft
- filter_id: when the tool operates on a filter
- mime_type: when an attachment was downloaded (NOT the filename)
- size_bytes: byte length of an attachment payload
- error_code: ToolErrorCode integer when outcome != "ok"

Explicitly NOT in the signature
-------------------------------
- filename: attachments are identified by ID + MIME type. The
  user-supplied filename can leak case/personnel/business info and is
  redacted by exclusion. Passing `filename=` raises TypeError because
  the signature is keyword-only and `filename` is not a parameter.
- subject, recipients, body, snippet, query string, label_name, etc.

The keyword-only signature is the structural enforcement: a typo or
honest-mistake `filename=...` cannot reach the logging output because
Python rejects the call before logging runs. Tests assert this.

Defense in depth
----------------
Even if a logger.info call accidentally includes a token-shaped
substring (e.g. an exception message echoing a refresh_token), the
RedactingFilter installed in server.py rewrites the value to
<redacted> before the record is emitted. This module is the FIRST
line of defense; the redacting filter is the BACKSTOP. Both must
hold.

Malformed message_id handling
-----------------------------
The optional `message_id`, `thread_id`, `label_id`, `attachment_id`
fields ARE included in the audit log when present. We do a lightweight
sanity check on `message_id` shape and emit at WARN (not INFO) level
when it does not look like a Gmail message ID, on the principle that
a malformed identifier is a quiet signal of a caller bug or of input
manipulation. The check accepts the documented Gmail ID alphabet
(alphanumeric + underscore + hyphen, length 16-128); anything else
falls into the WARN bucket.
"""

from __future__ import annotations

import logging

from .gmail_id import id_looks_valid_audit_heuristic as _id_looks_valid

logger = logging.getLogger(__name__)


# Behavior preserved verbatim from  audit_log.py: malformed
# message_id / thread_id (i.e. values outside the 16-128 char URL-safe
# band) promote the audit line to WARN level. The pattern itself now
# lives in gmail_id.py (`_AUDIT_HEURISTIC_PATTERN`) so the audit
# heuristic and the hard-validation pattern can evolve independently.
# See gmail_id.py module docstring for why the two patterns are
# deliberately separate.


def audit(
    *,
    tool: str,
    auth0_sub: str | None,
    account_email: str | None,
    outcome: str,
    message_id: str | None = None,
    thread_id: str | None = None,
    label_id: str | None = None,
    attachment_id: str | None = None,
    draft_id: str | None = None,
    filter_id: str | None = None,
    mime_type: str | None = None,
    size_bytes: int | None = None,
    error_code: int | None = None,
) -> None:
    """Emit one structured audit log line for a tool dispatch.

    Keyword-only signature is non-negotiable. Adding a positional or
    new keyword argument is a code change with review attached. The
    The audit-log contract calls this out structurally because past incidents in
    other systems traced back to a future caller appending `filename=`
    or similar PII to a log call that originally only took safe fields.

    Format (deliberately consistent so log aggregation can parse):
        "tool=<...> sub=<...> email=<...> outcome=<...> [k=v ...]"

    Optional fields are appended only when not None. None placeholders
    are omitted to keep log lines compact.
    """
    pairs: list[str] = [
        f"tool={tool}",
        f"sub={auth0_sub}",
        f"email={account_email}",
        f"outcome={outcome}",
    ]
    if message_id is not None:
        pairs.append(f"message_id={message_id}")
    if thread_id is not None:
        pairs.append(f"thread_id={thread_id}")
    if label_id is not None:
        pairs.append(f"label_id={label_id}")
    if attachment_id is not None:
        pairs.append(f"attachment_id={attachment_id}")
    if draft_id is not None:
        pairs.append(f"draft_id={draft_id}")
    if filter_id is not None:
        pairs.append(f"filter_id={filter_id}")
    if mime_type is not None:
        pairs.append(f"mime_type={mime_type}")
    if size_bytes is not None:
        pairs.append(f"size_bytes={size_bytes}")
    if error_code is not None:
        pairs.append(f"error_code={error_code}")

    line = " ".join(pairs)

    # Promote to WARN if the message_id does not match the documented
    # Gmail ID shape. This is a quiet caller-bug signal: the tool
    # dispatched, we have an outcome, but the ID we recorded looks off.
    # Operators searching for "WARN" in audit history will find these.
    if not _id_looks_valid(message_id):
        logger.warning("%s message_id_shape=invalid", line)
        return
    if not _id_looks_valid(thread_id):
        logger.warning("%s thread_id_shape=invalid", line)
        return

    logger.info("%s", line)
