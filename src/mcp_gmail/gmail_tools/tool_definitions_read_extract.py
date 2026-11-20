"""TOOL_DEFINITIONS_READ_EXTRACT: the read_attachment_text tool def.

Split from tool_definitions.py to honor the 300-LOC ceiling. Holds the
one read-side extraction tool (read_attachment_text), which extracts the
readable text of a PDF/CSV/XLSX/text attachment SERVER-SIDE. The public
TOOL_DEFINITIONS list in tool_definitions.py splices this list in via
list concatenation (mirroring the tool_definitions_threads_manage.py /
tool_definitions_labels_filters.py splices), so gmail_tools/__init__.py
keeps a single read-manifest import.

Tool names MUST match scope_check.py's TOOL_SCOPE_REQUIREMENTS table and
tool_router.py's dispatch branch. Any change to the tool surface
(rename, addition, removal) requires updating all three files in the
same change.
"""

from __future__ import annotations

from typing import Any

from .tool_schemas import ACCOUNT_EMAIL_PROP


_READ_ATTACHMENT_TEXT_DEF: dict[str, Any] = {
    "name": "read_attachment_text",
    "description": (
        "Extract the readable TEXT of one attachment SERVER-SIDE and "
        "return it directly, so you do not have to decode a PDF or "
        "spreadsheet yourself. Use this for invoice/order PDFs, CSVs, "
        "and XLSX spreadsheets when you need their numbers/text; use "
        "download_attachment instead when you need the raw bytes. "
        "Select the attachment EXACTLY like download_attachment: with "
        "ONE of attachment_id, filename (exact, case-sensitive), or "
        "part_index (0-based document order); zero or more than one "
        "selector is rejected. Extraction method is chosen from the "
        "attachment's mime_type: application/pdf -> pypdf text; "
        "text/csv -> parsed rows; the XLSX spreadsheet type -> cell "
        "values; text/plain and other text/* -> decoded text. When "
        "Gmail reports the generic application/octet-stream, the file "
        "extension (.pdf/.csv/.xlsx) is used as a fallback. Other types "
        "(images, unknown binaries) return a bad_request with "
        "error_data.kind='unsupported'. A malformed or hostile file of "
        "a parsed type returns a bad_request with "
        "error_data.kind='extraction_failed' (never a crash). Returns "
        "{filename, mime_type, extraction_method, text, truncated}; the "
        "text is capped at 100000 chars (truncated with a marker and "
        "truncated=true when longer). Edge case: when selecting by "
        "attachment_id and the message-metadata enrichment cannot resolve "
        "the part's mime_type or filename, extraction cannot dispatch and "
        "returns the unsupported error; select by filename or part_index "
        "(which resolve the part directly) to avoid this."
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
                    "message's downloadable parts in document order. "
                    "Optional; one of the three selection modes."
                ),
                "minimum": 0,
            },
        },
        "required": ["account_email", "message_id"],
        "additionalProperties": False,
    },
}


TOOL_DEFINITIONS_READ_EXTRACT: list[dict[str, Any]] = [_READ_ATTACHMENT_TEXT_DEF]
