"""Thread-management tool defs spliced into the read manifest.

Holds three inbox/thread-management tool definitions
(list_inbox_threads, get_inbox_with_threads, modify_thread) split out
of tool_definitions.py so that file stays under the 300-LOC hard rule
after the format='text' description additions. tool_definitions.py
concatenates `TOOL_DEFINITIONS_THREADS_MANAGE` into `TOOL_DEFINITIONS`
in the SAME position these defs held before the split (after
get_thread, before the labels/filters splice), so the manifest order
and the 11-entry count are unchanged. This mirrors the existing
labels/filters and admin-cleanup splice precedents.
"""

from __future__ import annotations

from typing import Any

from .tool_schemas import ACCOUNT_EMAIL_PROP


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


# Ordered exactly as these three defs appeared in tool_definitions.py
# before the split (list_inbox_threads, get_inbox_with_threads,
# modify_thread) so the concatenated manifest order is identical.
TOOL_DEFINITIONS_THREADS_MANAGE: list[dict[str, Any]] = [
    _LIST_INBOX_THREADS_DEF,
    _GET_INBOX_WITH_THREADS_DEF,
    _MODIFY_THREAD_DEF,
]


assert len(TOOL_DEFINITIONS_THREADS_MANAGE) == 3, (
    f"thread-management manifest must have 3 entries, got {len(TOOL_DEFINITIONS_THREADS_MANAGE)}"
)
