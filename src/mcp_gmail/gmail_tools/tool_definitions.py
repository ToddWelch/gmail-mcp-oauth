"""TOOL_DEFINITIONS: read manifest, 11 entries (5 native + 3 + 3 spliced).

Native here: 5 message and thread tools (read_email, search_emails,
download_attachment, download_email, get_thread). Spliced from
tool_definitions_threads_manage.py: 3 thread-management tools
(list_inbox_threads, get_inbox_with_threads, modify_thread), split out
so this file stays under the 300-LOC rule after the format='text'
description additions. Spliced from tool_definitions_labels_filters.py:
3 label and filter tools (list_email_labels, list_filters, get_filter).
Both splices preserve the original manifest order. Split for the
300-LOC rule. gmail_tools/__init__.py concatenates this read manifest
with the write, bootstrap, and extras manifests for the 33-tool surface.

Every Gmail-ID-shaped field carries a `pattern` matching
gmail_id._VALIDATION_PATTERN ({1,256}). download_attachment.attachment_id
is the one exception: it uses the wider {16,2048} attachment pattern
(gmail_id._ATTACHMENT_VALIDATION_PATTERN) because real Gmail attachment
IDs routinely exceed 256 chars, and it is optional because the tool also
selects an attachment by filename or part_index.
"""

from __future__ import annotations

from typing import Any

from .tool_definitions_labels_filters import TOOL_DEFINITIONS_LABELS_FILTERS
from .tool_definitions_threads_manage import TOOL_DEFINITIONS_THREADS_MANAGE
from .tool_schemas import ACCOUNT_EMAIL_PROP


_READ_EMAIL_DEF: dict[str, Any] = {
    "name": "read_email",
    "description": (
        "Return the full content of one Gmail message by ID. "
        "Default format='full' returns headers, body, and "
        "attachment metadata (but not attachment bytes; use "
        "download_attachment for those). Format='metadata' returns "
        "headers only; 'minimal' returns IDs only; 'raw' returns "
        "the RFC 5322 base64url-encoded message. Format='text' is the "
        "token-efficient read for bloated HTML emails (e.g. Amazon "
        "order/receipt emails that run 170K-250K chars): it returns a "
        "LEAN object with curated headers, the decoded plain-text body "
        "only (prefers the text/plain part; converts text/html when "
        "there is no text/plain), a text_source field, and attachment "
        "metadata (no bytes), dropping the HTML part and inline base64 "
        "so the response stays small. The returned text is capped at "
        "100000 chars; if longer it is truncated with a marker and "
        "text_truncated=true (fall back to format='full' or download for "
        "the complete body). Prefer 'text' over 'full' when you only "
        "need the readable body."
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
                "description": (
                    "Gmail response format. Default 'full'. Use 'text' "
                    "for a lean plain-text read of bloated HTML emails."
                ),
                "enum": ["full", "metadata", "minimal", "raw", "text"],
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
        "follow up with read_email per ID for full content. Set "
        "include_previews=true to enrich each result with "
        "{subject, from, date, snippet, labelIds}; this costs one extra "
        "Gmail metadata fetch per result (an opt-in N+1), so leave it "
        "off when you only need IDs."
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
            "include_previews": {
                "type": "boolean",
                "description": (
                    "When true, enrich each result with preview metadata "
                    "(subject, from, date, snippet, labelIds) at the cost "
                    "of one extra Gmail metadata fetch per result. "
                    "Default false (bare id + threadId stubs)."
                ),
            },
        },
        "required": ["account_email"],
        "additionalProperties": False,
    },
}


_DOWNLOAD_ATTACHMENT_DEF: dict[str, Any] = {
    "name": "download_attachment",
    "description": (
        "Return one attachment from a message, enriched as "
        "{filename, mime_type, size, data} where `data` is "
        "base64url-encoded bytes and `size` is the byte size. Select "
        "the attachment with EXACTLY ONE of three modes: (1) "
        "`attachment_id` (Gmail's opaque reference from read_email's "
        "payload.parts[*].body.attachmentId); (2) `filename` (exact, "
        "case-sensitive; if two attachments share the name it is "
        "rejected, disambiguate with part_index); (3) `part_index` "
        "(0-based document order over every part that has a server-side "
        "attachmentId; a part's filename may be absent for inline "
        "attachments, so filename is null for those; parts with no "
        "attachmentId are not downloadable and are not counted). "
        "Supplying zero or more than one selector is rejected. Prefer "
        "filename or part_index so you never have to handle the long "
        "attachment_id yourself."
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
                    "Gmail attachment identifier. Optional; one of the "
                    "three selection modes. Validated against the Gmail "
                    "ID alphabet (alphanumeric plus underscore/hyphen, "
                    "16 to 2048 chars; real IDs routinely exceed 256)."
                ),
                "pattern": "^[A-Za-z0-9_\\-]{16,2048}$",
            },
            "filename": {
                "type": "string",
                "description": (
                    "Select the attachment by exact, case-sensitive "
                    "filename. Optional; one of the three selection "
                    "modes."
                ),
                "minLength": 1,
                "maxLength": 256,
            },
            "part_index": {
                "type": "integer",
                "description": (
                    "Select the attachment by 0-based index into the "
                    "message's downloadable parts in document order "
                    "(every part that has a server-side attachmentId, "
                    "including nameless inline attachments). Optional; "
                    "one of the three selection modes."
                ),
                "minimum": 0,
            },
        },
        "required": ["account_email", "message_id"],
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
    "description": (
        "Return one Gmail thread by ID with all its messages. "
        "Format='text' is the token-efficient read for threads with "
        "bloated HTML emails: it reduces EACH message to a lean object "
        "(curated headers, decoded plain-text body only, text_source, "
        "and attachment metadata without bytes), dropping every HTML "
        "part and inline base64. Each message's text is capped at "
        "100000 chars (truncated with a marker and text_truncated=true "
        "when longer). The wrapper is {id, messages:[<lean>...]}."
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
            "format": {
                "type": "string",
                "description": (
                    "Thread format. Default 'full'. Use 'text' for a "
                    "lean per-message plain-text read."
                ),
                "enum": ["full", "metadata", "minimal", "text"],
            },
        },
        "required": ["account_email", "thread_id"],
        "additionalProperties": False,
    },
}


# Public list. The 5 native message+thread entries first, then the 3
# thread-management entries spliced from
# tool_definitions_threads_manage.py, then the 3 label+filter entries
# spliced from tool_definitions_labels_filters.py, all to keep this
# file under 300 LOC. Both splices mirror the precedent in
# tool_definitions_admin.py (which splices in
# tool_definitions_admin_cleanup.py the same way). The concatenation
# order reproduces the pre-split manifest order exactly (read_email,
# search_emails, download_attachment, download_email, get_thread,
# list_inbox_threads, get_inbox_with_threads, modify_thread, then
# labels/filters), so no index-dependent assertion is affected.
TOOL_DEFINITIONS: list[dict[str, Any]] = (
    [
        _READ_EMAIL_DEF,
        _SEARCH_EMAILS_DEF,
        _DOWNLOAD_ATTACHMENT_DEF,
        _DOWNLOAD_EMAIL_DEF,
        _GET_THREAD_DEF,
    ]
    + list(TOOL_DEFINITIONS_THREADS_MANAGE)
    + list(TOOL_DEFINITIONS_LABELS_FILTERS)
)


assert len(TOOL_DEFINITIONS) == 11, (
    f"read manifest must have 11 entries (8 message/thread + "
    f"3 labels/filters), got {len(TOOL_DEFINITIONS)}"
)
