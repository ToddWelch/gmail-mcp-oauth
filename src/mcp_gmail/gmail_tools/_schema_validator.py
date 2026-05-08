"""Per-tool JSON Schema validator cache for the dispatch boundary.

Each tool entry in `TOOL_DEFINITIONS` ships a JSON Schema as its
`inputSchema`. Until now the schema was advisory: Claude validates
against it client-side, the per-handler `require_str` /
`validate_gmail_id` family caught most mismatches at handler entry,
but a malformed shape that bypassed the client could still reach a
handler before the per-field check fired. This module closes that
gap by compiling every tool's `inputSchema` into a
`Draft202012Validator` at module load time and exposing one entry
point, `validate_arguments(tool_name, arguments)`, that the JSON-RPC
dispatcher (`mcp_protocol.handle_jsonrpc`) calls between the
registered-tool check and `dispatch_tool_call`.

Design notes
------------
- Cache: dict keyed by tool name. Built once at import. Drift between
  manifest and validator cache is structurally impossible because both
  come from the same list (`TOOL_DEFINITIONS`).
- `Draft202012Validator.check_schema` runs per entry at build time so a
  malformed manifest fails fast on import (caught by CI).
- No `format_checker`. The schemas use only core keywords (type,
  pattern, enum, minLength, maxLength, minItems, maxItems, required,
  additionalProperties). `format: "email"` annotations stay as
  documentation only; recipient-syntax validation lives at the
  handler layer (`send.py:_looks_like_email`) where it belongs.
- Return value is a coarse JSON Pointer (e.g. `/message_id`) capped at
  200 chars, intended for the structured WARNING log so an operator
  can pivot from a correlation_id. The wire response built by the
  caller MUST NOT echo this value: the offending payload itself never
  leaves the server (DoS / reflected-payload mitigation per the Codex
  finding).
"""

from __future__ import annotations

import logging
from typing import Any

from jsonschema import Draft202012Validator

from . import TOOL_DEFINITIONS

logger = logging.getLogger(__name__)


_FIELD_PATH_MAX = 200


def _build_validators() -> dict[str, Draft202012Validator]:
    """Compile one validator per tool, keyed by tool name.

    Runs `Draft202012Validator.check_schema(inputSchema)` per tool so
    a malformed manifest entry raises a `SchemaError` at import time
    (CI catches it before the build ever ships).
    """
    cache: dict[str, Draft202012Validator] = {}
    for tool in TOOL_DEFINITIONS:
        name = tool["name"]
        schema = tool["inputSchema"]
        # Fail fast on malformed schemas at module load. The
        # SchemaError surfaces in CI rather than as a runtime 500.
        Draft202012Validator.check_schema(schema)
        cache[name] = Draft202012Validator(schema)
    return cache


_VALIDATORS: dict[str, Draft202012Validator] = _build_validators()


def validate_arguments(tool_name: str, arguments: dict[str, Any]) -> str | None:
    """Validate ``arguments`` against the named tool's ``inputSchema``.

    Returns ``None`` on success, or a coarse JSON Pointer of the first
    failing field on failure (capped at ``_FIELD_PATH_MAX`` chars). The
    return value is intended for the dispatcher's structured WARNING
    log; it MUST NOT be echoed in the wire response.

    Unknown tool names return ``None`` (not an error). The dispatcher
    enforces tool-name registration BEFORE calling this function via
    its own manifest check, so an unknown name reaching here would be
    a logic bug; failing closed (`return None`) keeps the dispatcher's
    method-not-found contract intact even in that bug path.
    """
    validator = _VALIDATORS.get(tool_name)
    if validator is None:
        return None
    # `iter_errors` yields every failure; we only need the first.
    for error in validator.iter_errors(arguments):
        # JSON Pointer string built from the absolute path. An empty
        # absolute_path means a root-level failure (e.g. missing a
        # `required` field, additionalProperties violation), surfaced
        # here as the lone "/" prefix.
        path = "/" + "/".join(str(p) for p in error.absolute_path)
        keyword = error.validator
        schema_path = "/".join(str(p) for p in error.absolute_schema_path)
        logger.warning(
            "schema validation failed (tool=%s, field=%s, keyword=%s, schema_path=%s)",
            tool_name,
            path,
            keyword,
            schema_path,
        )
        return path[:_FIELD_PATH_MAX]
    return None


__all__ = ["validate_arguments"]
