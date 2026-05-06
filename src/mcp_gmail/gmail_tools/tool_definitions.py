"""TOOL_DEFINITIONS: JSON Schema manifest for the 11 Gmail read tools.

The 14 write tools live in tool_definitions_write.py.
__init__.py concatenates both into TOOL_DEFINITIONS (asserts 25 total).
Every Gmail-ID-shaped field has a `pattern` matching
gmail_id._VALIDATION_PATTERN (attachment_id keeps the stricter pattern).
"""

from __future__ import annotations

from typing import Any


_ACCOUNT_EMAIL_PROP: dict[str, Any] = {
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


TOOL_DEFINITIONS: list[dict[str, Any]] = [
    {
        "name": "read_email",
        "description": (
            "Return the full content of one Gmail message by ID. "
            "Default format='full' returns headers, body, and "
            "attachment metadata (but not attachment bytes; use "
            "download_attachment for those). Format='metadata' returns "
            "headers only; 'minimal' returns IDs only; 'raw' returns "
            "the RFC 5322 base64url-encoded message."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "account_email": _ACCOUNT_EMAIL_PROP,
                "message_id": {
                    "type": "string",
                    "description": "Gmail message ID to fetch.",
                    "minLength": 1,
                    "maxLength": 256,
                    "pattern": "^[A-Za-z0-9_\\-]{1,256}$",
                },
                "format": {
                    "type": "string",
                    "description": "Gmail response format. Default 'full'.",
                    "enum": ["full", "metadata", "minimal", "raw"],
                },
            },
            "required": ["account_email", "message_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "search_emails",
        "description": (
            "Search Gmail messages using Gmail's web-search syntax. "
            "Supports operators like from:, to:, subject:, "
            "has:attachment, label:, before:, after:, and free-text. "
            "Returns a page of message stubs (id + threadId only); "
            "follow up with read_email per ID for full content."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "account_email": _ACCOUNT_EMAIL_PROP,
                "q": {
                    "type": "string",
                    "description": "Gmail search query string. Optional.",
                    "maxLength": 1000,
                },
                "label_ids": {
                    "type": "array",
                    "description": "Optional label ID filter. AND semantics.",
                    "items": {"type": "string", "pattern": "^[A-Za-z0-9_\\-]{1,256}$"},
                    "maxItems": 10,
                },
                "page_token": {
                    "type": "string",
                    "description": "Opaque pagination cursor from previous response.",
                },
                "max_results": {
                    "type": "integer",
                    "description": "Max results per page. Gmail caps at 500.",
                    "minimum": 1,
                    "maximum": 500,
                },
            },
            "required": ["account_email"],
            "additionalProperties": False,
        },
    },
    {
        "name": "download_attachment",
        "description": (
            "Return one attachment payload (base64url-encoded) by "
            "message ID + attachment ID. The attachment ID comes from "
            "read_email's payload.parts[*].body.attachmentId."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "account_email": _ACCOUNT_EMAIL_PROP,
                "message_id": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 256,
                    "pattern": "^[A-Za-z0-9_\\-]{1,256}$",
                },
                "attachment_id": {
                    "type": "string",
                    "description": (
                        "Gmail attachment identifier. Validated against "
                        "the documented Gmail ID alphabet (alphanumeric "
                        "plus underscore/hyphen, 16 to 128 chars)."
                    ),
                    "pattern": "^[A-Za-z0-9_\\-]{16,128}$",
                },
            },
            "required": ["account_email", "message_id", "attachment_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "download_email",
        "description": (
            "Return the full RFC 5322 raw bytes of a Gmail message, "
            "base64url-encoded. Useful for archiving as .eml or for "
            "downstream parsers that need the exact wire format."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "account_email": _ACCOUNT_EMAIL_PROP,
                "message_id": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 256,
                    "pattern": "^[A-Za-z0-9_\\-]{1,256}$",
                },
            },
            "required": ["account_email", "message_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "get_thread",
        "description": "Return one Gmail thread by ID with all its messages.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "account_email": _ACCOUNT_EMAIL_PROP,
                "thread_id": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 256,
                    "pattern": "^[A-Za-z0-9_\\-]{1,256}$",
                },
                "format": {
                    "type": "string",
                    "enum": ["full", "metadata", "minimal"],
                },
            },
            "required": ["account_email", "thread_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "list_inbox_threads",
        "description": (
            "List threads currently in the INBOX label. Returns a page "
            "of thread stubs (id + history fields); follow up with "
            "get_thread per ID for full message content. For inbox "
            "summaries with subject/sender/snippet metadata baked in, "
            "use get_inbox_with_threads instead."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "account_email": _ACCOUNT_EMAIL_PROP,
                "page_token": {"type": "string"},
                "max_results": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 500,
                },
            },
            "required": ["account_email"],
            "additionalProperties": False,
        },
    },
    {
        "name": "get_inbox_with_threads",
        "description": (
            "List INBOX threads and expand each into a one-call summary "
            "(thread_id, subject, from_addr, snippet, message_count, "
            "last_message_id). Convenience for an at-a-glance inbox "
            "view without making the model call read_email N times."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "account_email": _ACCOUNT_EMAIL_PROP,
                "max_results": {
                    "type": "integer",
                    "description": "Default 25. Each thread costs an extra Gmail HTTP call.",
                    "minimum": 1,
                    "maximum": 100,
                },
            },
            "required": ["account_email"],
            "additionalProperties": False,
        },
    },
    {
        "name": "modify_thread",
        "description": (
            "Add and/or remove labels on a thread. Requires "
            "gmail.modify scope; readonly-only links will see "
            "scope_insufficient. Returns the updated thread metadata. "
            "INBOX is a label, so moving a thread into the inbox is "
            "`add_label_ids=['INBOX']`; archiving is "
            "`remove_label_ids=['INBOX']`."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "account_email": _ACCOUNT_EMAIL_PROP,
                "thread_id": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 256,
                    "pattern": "^[A-Za-z0-9_\\-]{1,256}$",
                },
                "add_label_ids": {
                    "type": "array",
                    "items": {"type": "string", "pattern": "^[A-Za-z0-9_\\-]{1,256}$"},
                    "maxItems": 50,
                },
                "remove_label_ids": {
                    "type": "array",
                    "items": {"type": "string", "pattern": "^[A-Za-z0-9_\\-]{1,256}$"},
                    "maxItems": 50,
                },
            },
            "required": ["account_email", "thread_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "list_email_labels",
        "description": (
            "List every label on the linked mailbox: system labels "
            "(INBOX, SENT, DRAFT, TRASH, SPAM, IMPORTANT, STARRED, "
            "UNREAD, CATEGORY_*) and user-created labels. Returns id, "
            "name, type, and visibility flags per label."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "account_email": _ACCOUNT_EMAIL_PROP,
            },
            "required": ["account_email"],
            "additionalProperties": False,
        },
    },
    {
        "name": "list_filters",
        "description": (
            "List every Gmail filter on the linked mailbox. Returns "
            "filter id, criteria (matching rules), and action (label "
            "add/remove, archive, mark important, forward to address)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "account_email": _ACCOUNT_EMAIL_PROP,
            },
            "required": ["account_email"],
            "additionalProperties": False,
        },
    },
    {
        "name": "get_filter",
        "description": "Return one Gmail filter by ID.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "account_email": _ACCOUNT_EMAIL_PROP,
                "filter_id": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 256,
                    "pattern": "^[A-Za-z0-9_\\-]{1,256}$",
                },
            },
            "required": ["account_email", "filter_id"],
            "additionalProperties": False,
        },
    },
]


assert len(TOOL_DEFINITIONS) == 11, (
    f"tool_definitions.py read manifest must have 11 entries, got {len(TOOL_DEFINITIONS)}"
)
