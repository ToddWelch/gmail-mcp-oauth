"""Extended Gmail-ID JSON Schema pattern tests.

Split from test_gmail_id_validation.py (which holds runtime-
validator tests) to keep both files under the project's 300-LOC
ceiling. This file exercises the declarative side of the gate: the
JSON Schema `pattern` declared on every Gmail-ID-shaped tool input.

Targets:
- src/mcp_gmail/gmail_tools/tool_definitions.py (5 fields)
- src/mcp_gmail/gmail_tools/tool_definitions_write.py (4 fields)
- src/mcp_gmail/gmail_tools/tool_definitions_admin.py (6 fields)
- src/mcp_gmail/gmail_tools/tool_definitions_admin_cleanup.py (2 fields)
- src/mcp_gmail/gmail_tools/tool_schemas.py (LABEL_ID_LIST_PROP.items)
- src/mcp_gmail/gmail_tools/gmail_id.py (_VALIDATION_PATTERN)

Tests in this file:
1. 9 adversarial-shape rejections at the validator layer
   (parametrized: null byte, CRLF, homoglyph, period, URL-encoded,
   backslash, fragment, semicolon, at sign).
2. A schema-layer probe via re.match (no jsonschema dependency).
3. A regex-parity sweep that walks every known Gmail-ID-shaped
   field and asserts each declared `pattern` matches
   _EXPECTED_PATTERNS. The only documented exception is
   download_attachment.attachment_id, which keeps the stricter
   {16,128} pattern.
"""

from __future__ import annotations

import re

import pytest

from mcp_gmail.gmail_tools import TOOL_DEFINITIONS
from mcp_gmail.gmail_tools.gmail_id import _VALIDATION_PATTERN, validate_gmail_id


# 9 adversarial probes at the validator layer (parametrized)


@pytest.mark.parametrize(
    "bad_value",
    [
        pytest.param("id\x00null", id="null-byte"),
        pytest.param("id\r\nX-Injected: 1", id="crlf-injection"),
        pytest.param("idаbc", id="unicode-homoglyph-cyrillic-a"),
        pytest.param(".", id="lone-period"),
        pytest.param("id%2Fbad", id="url-encoded-slash"),
        pytest.param("id\\bad", id="backslash"),
        pytest.param("id#fragment", id="hash-fragment"),
        pytest.param("id;param=evil", id="semicolon-matrix-param"),
        pytest.param("id@evil.example", id="at-sign-userinfo"),
    ],
)
def test_validate_gmail_id_rejects_adversarial_shapes(bad_value):
    """Every adversarial shape rejected by the validator. CRLF is the
    canonical header-smuggling shape (most security-critical of the
    set); the others close path-traversal and URL-authority seams."""
    with pytest.raises(ValueError) as excinfo:
        validate_gmail_id(bad_value, field="message_id")
    assert "message_id" in str(excinfo.value)


# schema-layer probe (re.match-based; NO jsonschema dependency)


def test_tool_schema_message_id_pattern_rejects_adversarial_at_schema_layer():
    """Proves the read_email.message_id JSON Schema `pattern` rejects
    every adversarial shape BEFORE the dispatcher reaches
    validate_gmail_id. We extract the pattern STRING and run re.match
    directly; `jsonschema` is intentionally not a dependency."""
    read_email_def = next(d for d in TOOL_DEFINITIONS if d["name"] == "read_email")
    pattern_str = read_email_def["inputSchema"]["properties"]["message_id"]["pattern"]
    pattern = re.compile(pattern_str)
    adversarial_inputs = [
        "../etc/passwd",
        "id\x00null",
        "id\r\nX-Injected: 1",
        "id with spaces",
        "idаbc",  # unicode homoglyph
        "id%2Fbad",  # URL-encoded slash
        "id\\bad",  # backslash
        "id#fragment",
        "id;param=evil",
        "id@evil.example",
    ]
    for value in adversarial_inputs:
        assert pattern.match(value) is None, (
            f"schema pattern unexpectedly matched adversarial value: {value!r}"
        )


# regex-parity sweep across every Gmail-ID-shaped field.
# attachment_id is the only documented exception: real Gmail
# attachment IDs sit in {16,128}, and aligning the heuristic and
# declared pattern is deliberate.


_EXPECTED_PATTERNS: dict[str, str] = {
    "message_id": _VALIDATION_PATTERN.pattern,
    "thread_id": _VALIDATION_PATTERN.pattern,
    "label_id": _VALIDATION_PATTERN.pattern,
    "filter_id": _VALIDATION_PATTERN.pattern,
    "draft_id": _VALIDATION_PATTERN.pattern,
    "attachment_id": r"^[A-Za-z0-9_\-]{16,128}$",
}


def _walk_id_shaped_fields(tool_def: dict) -> list[tuple[str, str | None]]:
    """Yield (field_name, declared_pattern) for each Gmail-ID-shaped
    property in `tool_def` whose name appears in _EXPECTED_PATTERNS.
    Plural `*_ids` arrays are unwrapped to the singular form so the
    expected-pattern lookup is uniform across scalar and items cases."""
    out: list[tuple[str, str | None]] = []
    props = tool_def.get("inputSchema", {}).get("properties", {})
    for name, prop in props.items():
        if name in _EXPECTED_PATTERNS:
            out.append((name, prop.get("pattern")))
        if name.endswith("_ids") and prop.get("type") == "array":
            singular = name[:-1]  # "message_ids" -> "message_id"
            if singular in _EXPECTED_PATTERNS:
                items = prop.get("items", {})
                if isinstance(items, dict):
                    out.append((singular, items.get("pattern")))
    return out


def test_all_gmail_id_field_patterns_match_validation_regex():
    """Every Gmail-ID-shaped field in TOOL_DEFINITIONS must declare a
    `pattern` matching _EXPECTED_PATTERNS. Catches drift on BOTH sides:
    validation regex tightening AND documented-exception loosening.
    A field that is in scope but missing the pattern is a failure;
    a divergent pattern is a failure. Inline arrays not in the
    parity sweep (search_emails.label_ids,
    modify_thread.add/remove_label_ids) are silently skipped by the
    walker by design."""
    failures: list[str] = []
    seen_count = 0
    for tool_def in TOOL_DEFINITIONS:
        for field_name, declared in _walk_id_shaped_fields(tool_def):
            seen_count += 1
            expected = _EXPECTED_PATTERNS[field_name]
            if declared is None:
                failures.append(
                    f"{tool_def['name']}.{field_name} has no `pattern` (expected {expected!r})"
                )
                continue
            if declared != expected:
                failures.append(
                    f"{tool_def['name']}.{field_name} pattern drift: "
                    f"declared={declared!r} expected={expected!r}"
                )
    assert seen_count >= len(_EXPECTED_PATTERNS), (
        f"walker found only {seen_count} Gmail-ID-shaped fields; "
        f"expected at least {len(_EXPECTED_PATTERNS)} (one per known name)"
    )
    assert not failures, "Gmail-ID pattern drift detected:\n  " + "\n  ".join(failures)


# ---------------------------------------------------------------------------
# schema-layer pattern coverage for create_draft / update_draft
# thread_id. The parity sweep above already auto-asserts the pattern
# string matches _VALIDATION_PATTERN; these tests prove the JSON Schema
# pattern actually rejects adversarial inputs at the schema layer
# BEFORE the dispatcher reaches validate_gmail_id.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_name", ["create_draft", "update_draft"])
def test_thread_id_schema_pattern_rejects_adversarial(tool_name):
    """Both create_draft and update_draft declare a thread_id property
    with a pattern that rejects every adversarial probe."""
    tool_def = next(d for d in TOOL_DEFINITIONS if d["name"] == tool_name)
    thread_id_prop = tool_def["inputSchema"]["properties"]["thread_id"]
    pattern_str = thread_id_prop["pattern"]
    pattern = re.compile(pattern_str)
    adversarial_inputs = [
        "../etc/passwd",
        "id\x00null",
        "id\r\nX-Injected: 1",
        "id with spaces",
        "idаbc",  # unicode homoglyph
        "id%2Fbad",  # URL-encoded slash
        "id\\bad",  # backslash
        "id#fragment",
        "id;param=evil",
        "id@evil.example",
        "T" * 257,  # oversized
    ]
    for value in adversarial_inputs:
        assert pattern.match(value) is None, (
            f"{tool_name}.thread_id schema pattern unexpectedly matched "
            f"adversarial value: {value!r}"
        )


@pytest.mark.parametrize("tool_name", ["create_draft", "update_draft"])
def test_pr3l_thread_id_schema_pattern_accepts_realistic_values(tool_name):
    """Sanity check: realistic Gmail thread IDs match the schema pattern.
    Real Gmail thread IDs are URL-safe base64 in the 16-32 char band.
    Without this guard the regex tightening would silently break
    every legitimate caller."""
    tool_def = next(d for d in TOOL_DEFINITIONS if d["name"] == tool_name)
    thread_id_prop = tool_def["inputSchema"]["properties"]["thread_id"]
    pattern = re.compile(thread_id_prop["pattern"])
    realistic = [
        "18a1f2b3c4d5e6f7",
        "thread-id-with-hyphens",
        "thread_id_with_underscores",
        "abc",  # short but valid shape
        "T" * 256,  # exactly at the cap
    ]
    for value in realistic:
        assert pattern.match(value) is not None, (
            f"{tool_name}.thread_id schema pattern unexpectedly rejected realistic value: {value!r}"
        )
