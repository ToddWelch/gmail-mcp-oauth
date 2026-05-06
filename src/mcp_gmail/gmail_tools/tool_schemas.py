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


ATTACHMENT_PROP: dict[str, Any] = {
    "type": "object",
    "description": (
        "Outbound attachment. `data_base64url` is base64url-encoded "
        "raw bytes (matches Gmail's download_attachment output)."
    ),
    "properties": {
        "filename": {"type": "string", "minLength": 1, "maxLength": 256},
        "mime_type": {"type": "string", "minLength": 1, "maxLength": 128},
        "data_base64url": {"type": "string"},
    },
    "required": ["filename", "mime_type", "data_base64url"],
    "additionalProperties": False,
}


LABEL_VISIBILITY_ENUM: list[str] = ["labelShow", "labelHide", "labelShowIfUnread"]
MESSAGE_VISIBILITY_ENUM: list[str] = ["show", "hide"]
