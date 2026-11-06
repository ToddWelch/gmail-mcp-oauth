"""Shared JSON Schema fragments used across tool_definitions modules.

Centralizing these fragments keeps the per-tool definitions concise
and ensures changes to e.g. the email-list cap propagate through
every tool that takes recipient lists. There is no behavior here;
this module is data-only.

These fragments are used in:
- tool_definitions.py (read-tool manifest)
- tool_definitions_write.py (send + drafts manifest)
- tool_definitions_admin.py (labels + filters + delete manifest)

They are exported as constants (not factory functions) because Python
JSON-Schema dicts are read-only by convention here; sharing the same
object across multiple tool definitions is fine and saves memory.
"""

from __future__ import annotations

from typing import Any


ACCOUNT_EMAIL_PROP: dict[str, Any] = {
    "type": "string",
    "description": (
        "Lowercased email address of the linked Gmail account to act "
        "against. Required. Multiple accounts can be linked per Auth0 "
        "user; this is how the dispatcher picks which one."
    ),
    "format": "email",
    "minLength": 3,
    "maxLength": 320,
}


EMAIL_LIST_PROP: dict[str, Any] = {
    "type": "array",
    "items": {"type": "string", "format": "email"},
    "maxItems": 100,
}


LABEL_ID_LIST_PROP: dict[str, Any] = {
    "type": "array",
    "items": {
        "type": "string",
        # declarative defense-in-depth on every label-ID element.
        # Same regex as gmail_id._VALIDATION_PATTERN. JSON Schema escape
        # (backslash doubled). Consumed by modify_email_labels and
        # batch_modify_emails (each tool declares both add_label_ids
        # and remove_label_ids).
        "pattern": "^[A-Za-z0-9_\\-]{1,256}$",
    },
    "maxItems": 50,
}


# Outbound attachment: a oneOf tagged union of two mutually exclusive
# shapes. The dispatch-boundary validator (_schema_validator._StrictValidator)
# extends Draft202012Validator overriding only `pattern`, so oneOf is
# enforced server-side: an item matching zero or both branches is
# rejected -32602 BEFORE the handler runs. attachment_source._classify
# is a defensive backstop for programmatic callers that bypass the schema.
_ATTACHMENT_INLINE_BRANCH: dict[str, Any] = {
    "type": "object",
    "description": (
        "Inline attachment. `data_base64url` is base64url-encoded raw "
        "bytes (matches Gmail's download_attachment output). Impractical "
        "for large binaries; use the upload-handle shape instead."
    ),
    "properties": {
        "filename": {"type": "string", "minLength": 1, "maxLength": 256},
        "mime_type": {"type": "string", "minLength": 1, "maxLength": 128},
        "data_base64url": {"type": "string"},
    },
    "required": ["filename", "mime_type", "data_base64url"],
    "additionalProperties": False,
}

_ATTACHMENT_UPLOAD_BRANCH: dict[str, Any] = {
    "type": "object",
    "description": (
        "Upload-handle attachment. Reference bytes uploaded out-of-band "
        "via create_attachment_upload_slot + a curl to upload_url. "
        "Single-use: the slot is consumed on send. filename / mime_type "
        "override the values captured at upload time when supplied."
    ),
    "properties": {
        "source": {"type": "string", "enum": ["upload"]},
        "upload_token": {"type": "string", "pattern": "^[A-Za-z0-9_\\-]{16,64}$"},
        "filename": {"type": "string", "minLength": 1, "maxLength": 256},
        "mime_type": {"type": "string", "minLength": 1, "maxLength": 128},
    },
    "required": ["source", "upload_token"],
    "additionalProperties": False,
}

ATTACHMENT_PROP: dict[str, Any] = {
    "description": (
        "Outbound attachment: exactly one of the inline shape "
        "({filename, mime_type, data_base64url}) or the upload-handle "
        "shape ({source:'upload', upload_token})."
    ),
    "oneOf": [_ATTACHMENT_INLINE_BRANCH, _ATTACHMENT_UPLOAD_BRANCH],
}


# Shared by every tool that can put a reply on the wire or store one as a draft.
REPLY_THREADING_NOTE: str = (
    " Replies land in the original conversation or do not go out. For a reply, pass "
    "reply_to_message_id: the Message-ID header of the message being replied to "
    "(<id@host>, from read_email format=metadata), not Gmail's message id. The server "
    "finds the thread itself and sets threadId, so no thread argument is needed. Refused "
    "with nothing sent (error -32007, reason in data.error_data): the message is not in "
    "this mailbox or matches more than one thread; the subject does not match it "
    "(Re:/Fwd: prefixes, spacing and case are ignored); the subject starts with Re: but "
    "there is no reply_to_message_id; the lookup fails; or the account lacks read access "
    "(-32004). A new email with no reply_to_message_id needs no read access."
)

SEND_DRAFT_THREADING_NOTE: str = (
    " Needs gmail.compose or read access to check the draft first, plus read access if it "
    "is a reply. Refused with nothing sent (error -32007) if its In-Reply-To points at a "
    "different thread than the draft's own, the target is not found, the subject does not "
    "match, or the subject starts with Re: with no In-Reply-To. On a -32008 no post-send "
    "action runs."
)

THREAD_MISMATCH_NOTE: str = (
    " If Gmail reports a different thread after sending, the result is error -32008 with "
    "both ids: the mail went out, so do not resend it."
)

SEND_RESULT_NOTE: str = THREAD_MISMATCH_NOTE + (
    " If Gmail does not confirm the send (network error or 5xx), the result is error -32009: "
    "it may have gone out, so check Sent before resending. A retry with the same "
    "idempotency_key returns that error without sending."
)

UPDATE_DRAFT_THREADING_NOTE: str = (
    " Updating a reply draft must pass reply_to_message_id or thread_id again; without "
    "them the update is refused, because it would pull the draft out of its conversation."
)


LABEL_VISIBILITY_ENUM: list[str] = ["labelShow", "labelHide", "labelShowIfUnread"]
MESSAGE_VISIBILITY_ENUM: list[str] = ["show", "hide"]
