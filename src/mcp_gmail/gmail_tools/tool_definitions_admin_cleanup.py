"""TOOL_DEFINITIONS_ADMIN_CLEANUP: 3 cleanup-tool definitions.

Split from tool_definitions_admin.py per the 300-LOC-per-file rule:
adding the 3 cleanup admin defs inline pushed tool_definitions_admin.py
past the ceiling. This module holds:

    batch_modify_emails
    get_or_create_label
    create_filter_from_template

The list is consumed by tool_definitions_admin.py and concatenated
into TOOL_DEFINITIONS_ADMIN at import time. Tool order is preserved
for the public TOOL_DEFINITIONS list.
"""

from __future__ import annotations

from typing import Any

from .filter_templates import TEMPLATE_NAMES
from .tool_schemas import (
    ACCOUNT_EMAIL_PROP,
    LABEL_ID_LIST_PROP,
    LABEL_VISIBILITY_ENUM,
    MESSAGE_VISIBILITY_ENUM,
)


_BATCH_MODIFY_EMAILS_DEF: dict[str, Any] = {
    "name": "batch_modify_emails",
    "description": (
        "Add and/or remove labels across up to 1000 messages in one "
        "Gmail call. Bulk analog of modify_email_labels; same Gmail "
        "endpoint as batch_delete_emails (users.messages.batchModify) "
        "but with caller-specified add/remove label sets instead of a "
        "hard-coded TRASH. Requires gmail.modify scope."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "account_email": ACCOUNT_EMAIL_PROP,
            "message_ids": {
                "type": "array",
                "items": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 256,
                    "pattern": "^[A-Za-z0-9_\\-]{1,256}$",
                },
                "minItems": 1,
                "maxItems": 1000,
            },
            "add_label_ids": LABEL_ID_LIST_PROP,
            "remove_label_ids": LABEL_ID_LIST_PROP,
        },
        "required": ["account_email", "message_ids"],
        "additionalProperties": False,
    },
}


_GET_OR_CREATE_LABEL_DEF: dict[str, Any] = {
    "name": "get_or_create_label",
    "description": (
        "Return the existing label with `name`, or create one if "
        "missing. Race caveat: TOCTOU exists between the list call "
        "and the create call; on race, returns Gmail's duplicate-name "
        "409 from the create. Name matching is case-sensitive per "
        "Gmail's behavior ('Important' and 'important' are distinct)."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "account_email": ACCOUNT_EMAIL_PROP,
            "name": {"type": "string", "minLength": 1, "maxLength": 256},
            "label_list_visibility": {"type": "string", "enum": LABEL_VISIBILITY_ENUM},
            "message_list_visibility": {
                "type": "string",
                "enum": MESSAGE_VISIBILITY_ENUM,
            },
            "color": {"type": "object"},
        },
        "required": ["account_email", "name"],
        "additionalProperties": False,
    },
}


_CREATE_FILTER_FROM_TEMPLATE_DEF: dict[str, Any] = {
    "name": "create_filter_from_template",
    "description": (
        "Create a Gmail filter from a named template. Templates: "
        f"{list(TEMPLATE_NAMES)}. The `auto_label_from_keyword` "
        "template applies to ALL future incoming mail matching the "
        "supplied query syntax; overly broad queries (empty, "
        "single-character, whitespace-only) are rejected before any "
        "Gmail call. The `auto_archive_sender` and `auto_label_sender` "
        "templates take a single sender_email; for domain-wide "
        "matching use `auto_label_from_keyword` with `from:*@domain` "
        "syntax. Requires gmail.settings.basic scope."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "account_email": ACCOUNT_EMAIL_PROP,
            "template": {"type": "string", "enum": list(TEMPLATE_NAMES)},
            "sender_email": {"type": "string", "format": "email", "maxLength": 320},
            "query": {"type": "string", "minLength": 2, "maxLength": 1000},
            "label_id": {
                "type": "string",
                "minLength": 1,
                "maxLength": 256,
                "pattern": "^[A-Za-z0-9_\\-]{1,256}$",
            },
        },
        "required": ["account_email", "template"],
        "additionalProperties": False,
    },
}


# Public list, exported for tool_definitions_admin.py to splice into
# TOOL_DEFINITIONS_ADMIN.
TOOL_DEFINITIONS_ADMIN_CLEANUP: list[dict[str, Any]] = [
    _BATCH_MODIFY_EMAILS_DEF,
    _GET_OR_CREATE_LABEL_DEF,
    _CREATE_FILTER_FROM_TEMPLATE_DEF,
]


assert len(TOOL_DEFINITIONS_ADMIN_CLEANUP) == 3, (
    f"cleanup admin manifest must have 3 entries, got {len(TOOL_DEFINITIONS_ADMIN_CLEANUP)}"
)
