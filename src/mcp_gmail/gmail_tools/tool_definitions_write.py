"""TOOL_DEFINITIONS_WRITE: JSON Schema manifest for the write-side tools.

Imported and concatenated by gmail_tools/__init__.py so the public
TOOL_DEFINITIONS list remains a single ordered list. The tools are
split across this file and tool_definitions_admin.py purely to honor
the 300-LOC-per-file rule:

    this file: 7 send/draft tools
        send_email, create_draft, update_draft, list_drafts,
        send_draft, delete_draft, reply_all
    tool_definitions_admin.py: 11 admin tools
        labels + filters + delete (8 originals) plus
        batch_modify_emails, get_or_create_label,
        create_filter_from_template (3 cleanup additions)

Tool names MUST match the names registered in tool_router_write.py and
in scope_check.py's TOOL_SCOPE_REQUIREMENTS table. Any rename or
addition needs to update all three files (the manifest, the
dispatch table, and the scope-requirements table) in the same change.
"""

from __future__ import annotations

from typing import Any

from .tool_definitions_admin import TOOL_DEFINITIONS_ADMIN
from .tool_schemas import (
    ACCOUNT_EMAIL_PROP,
    ATTACHMENT_PROP,
    EMAIL_LIST_PROP,
    LABEL_ID_LIST_PROP,
)


# Send / drafts share the same construction inputs (sender, to,
# subject, body_text, cc, bcc, attachments, threading headers).
_DRAFT_BODY_PROPS: dict[str, Any] = {
    "account_email": ACCOUNT_EMAIL_PROP,
    "sender": {"type": "string", "minLength": 3, "maxLength": 320},
    "to": EMAIL_LIST_PROP,
    "subject": {"type": "string", "maxLength": 998},
    "body_text": {"type": "string"},
    "cc": EMAIL_LIST_PROP,
    "bcc": EMAIL_LIST_PROP,
    "attachments": {
        "type": "array",
        "items": ATTACHMENT_PROP,
        "maxItems": 25,
    },
    "reply_to_message_id": {"type": "string", "maxLength": 998},
    "reply_to_references": {
        "type": "array",
        "items": {"type": "string"},
        "maxItems": 50,
    },
}


# Gmail's authoritative thread join. Per Gmail API threading docs
# (developers.google.com/gmail/api/guides/sending#threading) adding a
# draft to an existing thread requires THREE conditions: the requested
# threadId on the Message resource, the In-Reply-To / References headers
# (set via reply_to_message_id / reply_to_references), and a matching
# Subject. Header inference alone is best-effort fallback; threadId is
# the explicit join. Applied only to create_draft and update_draft (not
# send_email) per the design contract. Schema-layer regex matches
# gmail_id._VALIDATION_PATTERN so the parity sweep auto-covers
# the new field.
_THREAD_ID_PROP: dict[str, Any] = {
    "type": "string",
    "minLength": 1,
    "maxLength": 256,
    "pattern": "^[A-Za-z0-9_\\-]{1,256}$",
}


_SEND_EMAIL_DEF: dict[str, Any] = {
    "name": "send_email",
    "description": (
        "Send a new email via Gmail. Builds an RFC 5322 message, "
        "enforces the 25 MiB encoded-size cap, and POSTs to "
        "users.messages.send. Optional `idempotency_key` dedupes "
        "retries within a 60s window keyed by (account, key)."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            **_DRAFT_BODY_PROPS,
            "idempotency_key": {"type": "string", "minLength": 1, "maxLength": 128},
        },
        "required": ["account_email", "sender", "to", "subject", "body_text"],
        "additionalProperties": False,
    },
}


_CREATE_DRAFT_DEF: dict[str, Any] = {
    "name": "create_draft",
    "description": (
        "Create a Gmail draft. Builds the message via the same "
        "EmailMessage path send_email uses (25 MiB cap enforced). "
        "Returns the draft id. Optional `thread_id` sets the "
        "authoritative thread join on the underlying Gmail message; "
        "header-only threading via reply_to_message_id / "
        "reply_to_references is best-effort fallback."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            **_DRAFT_BODY_PROPS,
            "thread_id": _THREAD_ID_PROP,
        },
        "required": ["account_email", "sender", "to", "subject", "body_text"],
        "additionalProperties": False,
    },
}


_UPDATE_DRAFT_DEF: dict[str, Any] = {
    "name": "update_draft",
    "description": (
        "Replace the contents of an existing draft. Gmail's update "
        "is a full PUT; the body wholly replaces the prior draft. "
        "Optional `thread_id` sets the authoritative thread "
        "join on the underlying Gmail message; header-only threading "
        "via reply_to_message_id / reply_to_references is best-effort "
        "fallback."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "draft_id": {
                "type": "string",
                "minLength": 1,
                "maxLength": 256,
                "pattern": "^[A-Za-z0-9_\\-]{1,256}$",
            },
            **_DRAFT_BODY_PROPS,
            "thread_id": _THREAD_ID_PROP,
        },
        "required": [
            "account_email",
            "draft_id",
            "sender",
            "to",
            "subject",
            "body_text",
        ],
        "additionalProperties": False,
    },
}


_LIST_DRAFTS_DEF: dict[str, Any] = {
    "name": "list_drafts",
    "description": (
        "List draft messages on the linked mailbox. Returns id stubs "
        "with the underlying message id/threadId; follow up with "
        "read_email per id for full content."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "account_email": ACCOUNT_EMAIL_PROP,
            "q": {"type": "string", "maxLength": 1000},
            "page_token": {"type": "string"},
            "max_results": {"type": "integer", "minimum": 1, "maximum": 500},
        },
        "required": ["account_email"],
        "additionalProperties": False,
    },
}


_SEND_DRAFT_DEF: dict[str, Any] = {
    "name": "send_draft",
    "description": (
        "Send an existing draft. Requires gmail.send scope. Consumes "
        "the draft. optional archive_thread, add_labels, "
        "remove_labels apply a follow-up modify_thread to the original "
        "thread AFTER the send succeeds (post-send actions are "
        "best-effort: send-success + action-fail returns the success "
        "record annotated with action_failures, the send is NOT "
        "retried). Send-fail returns the existing error shape with no "
        "actions attempted. Caller must have granted gmail.modify in "
        "addition to gmail.send for post-send actions."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "account_email": ACCOUNT_EMAIL_PROP,
            "draft_id": {
                "type": "string",
                "minLength": 1,
                "maxLength": 256,
                "pattern": "^[A-Za-z0-9_\\-]{1,256}$",
            },
            # optional post-send action params.
            "archive_thread": {"type": "boolean"},
            "add_labels": LABEL_ID_LIST_PROP,
            "remove_labels": LABEL_ID_LIST_PROP,
        },
        "required": ["account_email", "draft_id"],
        "additionalProperties": False,
    },
}


_DELETE_DRAFT_DEF: dict[str, Any] = {
    "name": "delete_draft",
    "description": "Delete a draft by ID. Permanent; not recoverable.",
    "inputSchema": {
        "type": "object",
        "properties": {
            "account_email": ACCOUNT_EMAIL_PROP,
            "draft_id": {
                "type": "string",
                "minLength": 1,
                "maxLength": 256,
                "pattern": "^[A-Za-z0-9_\\-]{1,256}$",
            },
        },
        "required": ["account_email", "draft_id"],
        "additionalProperties": False,
    },
}


_REPLY_ALL_DEF: dict[str, Any] = {
    "name": "reply_all",
    "description": (
        "Replies to ALL recipients on the original message (To + Cc "
        "minus self), NOT just the sender. Use send_email with the "
        "original sender if you want a reply-to-sender. Self is "
        "resolved via Gmail's getProfile so the linked mailbox does "
        "not appear in its own reply Cc list. The expanded recipient "
        "set is capped at 100. Idempotency cache is shared with "
        "send_email; do not reuse the same idempotency_key for both "
        "tools. Subject is prefixed with 'Re: ' unless it already "
        "starts with 'Re:'. Requires gmail.send scope."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "account_email": ACCOUNT_EMAIL_PROP,
            # Field is named `message_id` (not `original_message_id`)
            # so dispatch.py's audit harvest at
            # `_str_or_none("message_id")` records the source-message
            # ID on each reply_all dispatch.
            "message_id": {
                "type": "string",
                "minLength": 1,
                "maxLength": 256,
                "pattern": "^[A-Za-z0-9_\\-]{1,256}$",
            },
            "body_text": {"type": "string"},
            "attachments": {
                "type": "array",
                "items": ATTACHMENT_PROP,
                "maxItems": 25,
            },
            "idempotency_key": {"type": "string", "minLength": 1, "maxLength": 128},
        },
        "required": ["account_email", "message_id", "body_text"],
        "additionalProperties": False,
    },
}


# Public manifest. Order: 6 send/drafts, 1 reply_all,
# then 8 admin + 3 cleanup admin (appended from
# tool_definitions_admin.py).
TOOL_DEFINITIONS_WRITE: list[dict[str, Any]] = [
    _SEND_EMAIL_DEF,
    _CREATE_DRAFT_DEF,
    _UPDATE_DRAFT_DEF,
    _LIST_DRAFTS_DEF,
    _SEND_DRAFT_DEF,
    _DELETE_DRAFT_DEF,
    _REPLY_ALL_DEF,
] + list(TOOL_DEFINITIONS_ADMIN)


assert len(TOOL_DEFINITIONS_WRITE) == 18, (
    f"write manifest must define exactly 18 tools (7 send/draft + 11 admin), "
    f"got {len(TOOL_DEFINITIONS_WRITE)}"
)
