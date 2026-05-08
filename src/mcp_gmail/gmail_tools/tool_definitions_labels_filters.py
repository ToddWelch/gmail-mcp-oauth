"""TOOL_DEFINITIONS_LABELS_FILTERS: 3 label and filter read tools.

Split from tool_definitions.py to honor the 300-LOC ceiling. The
three tools here all operate on Gmail label or filter resources
rather than message bodies. The public TOOL_DEFINITIONS list in
tool_definitions.py splices this list in via list concatenation,
so gmail_tools/__init__.py keeps a single read-manifest import.

Tool names MUST match scope_check.py's TOOL_SCOPE_REQUIREMENTS
table and tool_router_read.py's dispatch branches. Any change to
the tool surface (rename, addition, removal) requires updating all
three files in the same change.
"""

from __future__ import annotations

from typing import Any

from .tool_schemas import ACCOUNT_EMAIL_PROP


_LIST_EMAIL_LABELS_DEF: dict[str, Any] = {
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
            "account_email": ACCOUNT_EMAIL_PROP,
        },
        "required": ["account_email"],
        "additionalProperties": False,
    },
}


_LIST_FILTERS_DEF: dict[str, Any] = {
    "name": "list_filters",
    "description": (
        "List every Gmail filter on the linked mailbox. Returns "
        "filter id, criteria (matching rules), and action (label "
        "add/remove, archive, mark important, forward to address)."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "account_email": ACCOUNT_EMAIL_PROP,
        },
        "required": ["account_email"],
        "additionalProperties": False,
    },
}


_GET_FILTER_DEF: dict[str, Any] = {
    "name": "get_filter",
    "description": "Return one Gmail filter by ID.",
    "inputSchema": {
        "type": "object",
        "properties": {
            "account_email": ACCOUNT_EMAIL_PROP,
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
}


TOOL_DEFINITIONS_LABELS_FILTERS: list[dict[str, Any]] = [
    _LIST_EMAIL_LABELS_DEF,
    _LIST_FILTERS_DEF,
    _GET_FILTER_DEF,
]


assert len(TOOL_DEFINITIONS_LABELS_FILTERS) == 3, (
    f"labels/filters manifest must have 3 entries, got {len(TOOL_DEFINITIONS_LABELS_FILTERS)}"
)
