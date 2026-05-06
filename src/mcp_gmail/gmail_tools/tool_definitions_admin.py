"""TOOL_DEFINITIONS_ADMIN: admin-side write tools.

Split from tool_definitions_write.py to honor the 300-LOC-per-file
rule. The initial design shipped 8 tools here (4 label, 2 filter,
2 delete). A later batch added 3 more (batch_modify_emails,
get_or_create_label, create_filter_from_template) which live in
tool_definitions_admin_cleanup.py to keep this file under 300 LOC;
the public TOOL_DEFINITIONS_ADMIN list below splices both.
Total: 11.

Tool names MUST match scope_check.py's TOOL_SCOPE_REQUIREMENTS
table and tool_router_write.py's dispatch branches. Any change to
the tool surface (rename, addition, removal) requires updating all
three files in the same change.
"""

from __future__ import annotations

from typing import Any

from .tool_definitions_admin_cleanup import TOOL_DEFINITIONS_ADMIN_CLEANUP
from .tool_schemas import (
    ACCOUNT_EMAIL_PROP,
    LABEL_ID_LIST_PROP,
    LABEL_VISIBILITY_ENUM,
    MESSAGE_VISIBILITY_ENUM,
)


_CREATE_LABEL_DEF: dict[str, Any] = {
    "name": "create_label",
    "description": (
        "Create a new user label. System labels (INBOX, SENT, etc.) are not user-creatable."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "account_email": ACCOUNT_EMAIL_PROP,
            # 225 (NOT 256) to match Gmail's documented label-name cap
            # and the Python-side check in labels_write.create_label.
            "name": {"type": "string", "minLength": 1, "maxLength": 225},
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


_UPDATE_LABEL_DEF: dict[str, Any] = {
    "name": "update_label",
    "description": (
        "Update an existing label. System labels cannot be renamed; Gmail returns 400 in that case."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "account_email": ACCOUNT_EMAIL_PROP,
            "label_id": {
                "type": "string",
                "minLength": 1,
                "maxLength": 256,
                "pattern": "^[A-Za-z0-9_\\-]{1,256}$",
            },
            # 225 (NOT 256) for parity with _CREATE_LABEL_DEF and the
            # Python-side check in labels_write.update_label. Gmail's
            # documented label-name display-length cap.
            "name": {"type": "string", "minLength": 1, "maxLength": 225},
            "label_list_visibility": {"type": "string", "enum": LABEL_VISIBILITY_ENUM},
            "message_list_visibility": {
                "type": "string",
                "enum": MESSAGE_VISIBILITY_ENUM,
            },
            "color": {"type": "object"},
        },
        "required": ["account_email", "label_id"],
        "additionalProperties": False,
    },
}


_DELETE_LABEL_DEF: dict[str, Any] = {
    "name": "delete_label",
    "description": (
        "Delete a user label by ID. The label is removed from every "
        "message and thread that carried it; messages remain in place."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "account_email": ACCOUNT_EMAIL_PROP,
            "label_id": {
                "type": "string",
                "minLength": 1,
                "maxLength": 256,
                "pattern": "^[A-Za-z0-9_\\-]{1,256}$",
            },
        },
        "required": ["account_email", "label_id"],
        "additionalProperties": False,
    },
}


_MODIFY_EMAIL_LABELS_DEF: dict[str, Any] = {
    "name": "modify_email_labels",
    "description": (
        "Add and/or remove labels on a single message. Per-message "
        "analog of modify_thread; same INBOX-as-label semantics for "
        "archive (remove INBOX) and star (add STARRED)."
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
            "add_label_ids": LABEL_ID_LIST_PROP,
            "remove_label_ids": LABEL_ID_LIST_PROP,
        },
        "required": ["account_email", "message_id"],
        "additionalProperties": False,
    },
}


_CREATE_FILTER_DEF: dict[str, Any] = {
    "name": "create_filter",
    "description": (
        "Create a Gmail settings filter. Applies to NEW incoming mail "
        "only; existing messages are not touched. `criteria` and "
        "`action` are passed through to Gmail; see Gmail's "
        "users.settings.filters documentation for valid shapes."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "account_email": ACCOUNT_EMAIL_PROP,
            "criteria": {"type": "object"},
            "action": {"type": "object"},
        },
        "required": ["account_email", "criteria", "action"],
        "additionalProperties": False,
    },
}


_DELETE_FILTER_DEF: dict[str, Any] = {
    "name": "delete_filter",
    "description": (
        "Delete a Gmail filter by ID. Does not undo prior labels or "
        "moves; only stops the filter matching new mail going forward."
    ),
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


_DELETE_EMAIL_DEF: dict[str, Any] = {
    "name": "delete_email",
    "description": (
        "Move a message to TRASH (recoverable for 30 days). Requires "
        "gmail.modify scope. Implemented via users.messages.trash, NOT "
        "users.messages.delete (the latter requires mail.google.com/ "
        "and is permanent)."
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


_BATCH_DELETE_EMAILS_DEF: dict[str, Any] = {
    "name": "batch_delete_emails",
    "description": (
        "Move up to 1000 messages to TRASH in one Gmail call "
        "(recoverable for 30 days). Requires gmail.modify scope. "
        "Implemented via users.messages.batchModify with "
        "addLabelIds=['TRASH']; the permanent batchDelete endpoint is "
        "deliberately NOT used."
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
        },
        "required": ["account_email", "message_ids"],
        "additionalProperties": False,
    },
}


# Public list. The 8 base entries first, then 3 cleanup-batch entries
# spliced from tool_definitions_admin_cleanup.py to keep this file
# under 300 LOC.
TOOL_DEFINITIONS_ADMIN: list[dict[str, Any]] = [
    _CREATE_LABEL_DEF,
    _UPDATE_LABEL_DEF,
    _DELETE_LABEL_DEF,
    _MODIFY_EMAIL_LABELS_DEF,
    _CREATE_FILTER_DEF,
    _DELETE_FILTER_DEF,
    _DELETE_EMAIL_DEF,
    _BATCH_DELETE_EMAILS_DEF,
] + list(TOOL_DEFINITIONS_ADMIN_CLEANUP)


assert len(TOOL_DEFINITIONS_ADMIN) == 11, (
    f"admin manifest must have 11 entries, got {len(TOOL_DEFINITIONS_ADMIN)}"
)
