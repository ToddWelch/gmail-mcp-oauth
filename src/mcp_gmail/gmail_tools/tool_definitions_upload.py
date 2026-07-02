"""JSON Schema manifest fragment for the attachment upload-slot tool.

Kept in its own module and spliced into TOOL_DEFINITIONS_WRITE so
tool_definitions_write.py stays under the 300-LOC rule, mirroring how
the admin defs are spliced in from tool_definitions_admin.py.
"""

from __future__ import annotations

from typing import Any

from .tool_schemas import ACCOUNT_EMAIL_PROP


_CREATE_UPLOAD_SLOT_DEF: dict[str, Any] = {
    "name": "create_attachment_upload_slot",
    "description": (
        "Mint a one-time upload slot for a large attachment so its bytes "
        "are never reproduced as base64 by the model (which corrupts "
        "binaries like barcoded PDFs). Returns {upload_token, upload_url, "
        "expires_at, max_bytes}. The client curls the raw file to "
        "upload_url with the token in the X-Upload-Token header, then "
        "references {source:'upload', upload_token} in a later "
        "send_email / create_draft / update_draft / reply_all. Requires "
        "a send-capable scope (readonly-only -> scope_insufficient). "
        "Single-use and short-lived; if a send fails after the slot was "
        "consumed, mint a fresh slot before retrying."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {"account_email": ACCOUNT_EMAIL_PROP},
        "required": ["account_email"],
        "additionalProperties": False,
    },
}


TOOL_DEFINITIONS_UPLOAD: list[dict[str, Any]] = [_CREATE_UPLOAD_SLOT_DEF]
