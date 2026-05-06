"""TOOL_DEFINITIONS_EXTRAS: the two fanout tools.

multi_search_emails and batch_read_emails ship in their own
manifest module rather than being appended to tool_definitions.py
because that file is already 311 LOC (at the 300 ceiling). Adding
new defs there would compound the violation; the split mirrors the
existing tool_definitions_admin_cleanup.py precedent.

Both tools are scope-wise read-only (gmail.readonly). They are
fanout convenience wrappers over the existing single-shot Gmail
endpoints (users.messages.list and users.messages.get respectively)
that asyncio.gather under one OAuth token to cut MCP-protocol round
trips during the morning-sweep ritual.

Schema-layer validation
-----------------------
- batch_read_emails.message_ids[*] reuses the canonical Gmail-ID
  pattern (^[A-Za-z0-9_\\-]{1,256}$). The Gmail-ID regex parity sweep
  (test_all_gmail_id_field_patterns_match_validation_regex) auto-
  picks this up via the plural-array unwrap, so no test changes are
  needed for parity.
- metadata_headers items carry a strict pattern so CRLF
  / special chars cannot reach Gmail's metadataHeaders= httpx params.
  Header names per RFC 5322 are token chars: ALPHA / DIGIT / hyphen.
"""

from __future__ import annotations

from typing import Any

from .tool_schemas import ACCOUNT_EMAIL_PROP


_MULTI_SEARCH_EMAILS_DEF: dict[str, Any] = {
    "name": "multi_search_emails",
    "description": (
        "Run N Gmail searches concurrently and return the per-query "
        "result lists in one call. Each underlying search uses Gmail's "
        "web-search syntax; behaviour per query matches search_emails. "
        "Tool fans out via asyncio.gather under one OAuth token; "
        "queries that error are surfaced per-query as {error_status, "
        "error_message} entries rather than failing the whole batch "
        "(mirrors get_inbox_with_threads partial-success idiom). "
        "Cap of 25 queries per call keeps quota burst well under "
        "Gmail's per-second limit."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "account_email": ACCOUNT_EMAIL_PROP,
            "queries": {
                "type": "array",
                "description": (
                    "Array of Gmail search query strings. Each entry is "
                    "the same string `q` accepts in search_emails. Empty "
                    "string is permitted (matches every message)."
                ),
                "items": {"type": "string", "minLength": 0, "maxLength": 1000},
                "minItems": 1,
                "maxItems": 25,
            },
            "max_results_per_query": {
                "type": "integer",
                "description": "Max results per individual query. Gmail caps at 500.",
                "minimum": 1,
                "maximum": 500,
            },
            "label_ids": {
                "type": "array",
                "description": ("Optional label ID filter applied to every query. AND semantics."),
                "items": {"type": "string", "pattern": "^[A-Za-z0-9_\\-]{1,256}$"},
                "maxItems": 10,
            },
        },
        "required": ["account_email", "queries"],
        "additionalProperties": False,
    },
}


_BATCH_READ_EMAILS_DEF: dict[str, Any] = {
    "name": "batch_read_emails",
    "description": (
        "Fetch up to 100 messages by ID and return their metadata or "
        "snippets in one call. Fans out via asyncio.gather under one "
        "OAuth token; per-id failures (404, 401, 403) surface as "
        "{message_id, error_status} entries rather than aborting the "
        "batch. format='metadata' returns headers + snippet (default); "
        "format='minimal' returns IDs + label IDs + snippet only. "
        "format='full' is intentionally NOT supported (oversized "
        "response bodies; callers wanting full bodies should call "
        "read_email per id)."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "account_email": ACCOUNT_EMAIL_PROP,
            "message_ids": {
                "type": "array",
                "description": "Gmail message IDs to fetch. Order preserved in response.",
                "items": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 256,
                    "pattern": "^[A-Za-z0-9_\\-]{1,256}$",
                },
                "minItems": 1,
                "maxItems": 100,
            },
            "format": {
                "type": "string",
                "description": (
                    "Gmail response format. Default 'metadata'. "
                    "'full' and 'raw' are intentionally excluded."
                ),
                "enum": ["metadata", "minimal"],
            },
            "metadata_headers": {
                "type": "array",
                "description": (
                    "Gmail header names to include when format=metadata. "
                    "Default ['From', 'Subject', 'Date'] applied at "
                    "handler layer when omitted. Caller-supplied list, "
                    "if any, is passed through verbatim."
                ),
                "items": {
                    "type": "string",
                    "maxLength": 64,
                    # header names per RFC 5322 are token
                    # chars only. Pattern blocks CRLF / special chars
                    # at the schema layer so the value cannot reach
                    # Gmail's `metadataHeaders=` httpx params with
                    # injection content.
                    "pattern": "^[A-Za-z0-9-]+$",
                },
                "maxItems": 16,
            },
        },
        "required": ["account_email", "message_ids"],
        "additionalProperties": False,
    },
}


# Public manifest. Order: multi_search_emails first (the higher-leverage
# tool of the two for the morning-sweep ritual), then batch_read_emails.
TOOL_DEFINITIONS_EXTRAS: list[dict[str, Any]] = [
    _MULTI_SEARCH_EMAILS_DEF,
    _BATCH_READ_EMAILS_DEF,
]


assert len(TOOL_DEFINITIONS_EXTRAS) == 2, (
    f"extras manifest must have 2 entries, got {len(TOOL_DEFINITIONS_EXTRAS)}"
)
