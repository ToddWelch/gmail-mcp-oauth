"""TOOL_DEFINITIONS: read manifest, 11 entries (8 native + 3 spliced).

Native here: 8 message and thread tools (read_email, search_emails,
download_attachment, download_email, get_thread, list_inbox_threads,
get_inbox_with_threads, modify_thread). Spliced from
tool_definitions_labels_filters.py: 3 label and filter tools
(list_email_labels, list_filters, get_filter). Split for the 300-LOC
rule. gmail_tools/__init__.py concatenates this read manifest with
the write, bootstrap, and extras manifests for the 32-tool surface.

Every Gmail-ID-shaped field carries a `pattern` matching
gmail_id._VALIDATION_PATTERN. download_attachment.attachment_id
keeps the stricter {16,128} pattern by design.
"""

from __future__ import annotations

from typing import Any

from .tool_definitions_labels_filters import TOOL_DEFINITIONS_LABELS_FILTERS
from .tool_schemas import ACCOUNT_EMAIL_PROP


_READ_EMAIL_DEF: dict[str, Any] = {
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
            "account_email": ACCOUNT_EMAIL_PROP,
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
}


_SEARCH_EMAILS_DEF: dict[str, Any] = {
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
            "account_email": ACCOUNT_EMAIL_PROP,
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
}


_DOWNLOAD_ATTACHMENT_DEF: dict[str, Any] = {
    "name": "download_attachment",
    "description": (
        "Return one attachment payload (base64url-encoded) by "
        "message ID + attachment ID. The attachment ID comes from "
        "read_email's payload.parts[*].body.attachmentId."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "account_email": ACCOUNT_EMAIL_PROP,
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
}


_DOWNLOAD_EMAIL_DEF: dict[str, Any] = {
    "name": "download_email",
    "description": (
        "Return the full RFC 5322 raw bytes of a Gmail message, "
        "base64url-encoded. Useful for archiving as .eml or for "
        "downstream parsers that need the exact wire format."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "account_email": ACCOUNT_EMAIL_PROP,
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
}


_GET_THREAD_DEF: dict[str, Any] = {
    "name": "get_thread",
    "description": "Return one Gmail thread by ID with all its messages.",
    "inputSchema": {
        "type": "object",
        "properties": {
            "account_email": ACCOUNT_EMAIL_PROP,
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
}


_LIST_INBOX_THREADS_DEF: dict[str, Any] = {
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
            "account_email": ACCOUNT_EMAIL_PROP,
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
}


_GET_INBOX_WITH_THREADS_DEF: dict[str, Any] = {
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
            "account_email": ACCOUNT_EMAIL_PROP,
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
}


_MODIFY_THREAD_DEF: dict[str, Any] = {
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
            "account_email": ACCOUNT_EMAIL_PROP,
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
}


# Public list. The 8 message+thread entries first, then 3
# label+filter entries spliced from tool_definitions_labels_filters.py
# to keep this file under 300 LOC. The splice mirrors the precedent
# in tool_definitions_admin.py (which splices in
# tool_definitions_admin_cleanup.py the same way).
TOOL_DEFINITIONS: list[dict[str, Any]] = [
    _READ_EMAIL_DEF,
    _SEARCH_EMAILS_DEF,
    _DOWNLOAD_ATTACHMENT_DEF,
    _DOWNLOAD_EMAIL_DEF,
    _GET_THREAD_DEF,
    _LIST_INBOX_THREADS_DEF,
    _GET_INBOX_WITH_THREADS_DEF,
    _MODIFY_THREAD_DEF,
] + list(TOOL_DEFINITIONS_LABELS_FILTERS)


assert len(TOOL_DEFINITIONS) == 11, (
    f"read manifest must have 11 entries (8 message/thread + "
    f"3 labels/filters), got {len(TOOL_DEFINITIONS)}"
)
