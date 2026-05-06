"""Tests for gmail_tools.gmail_id (Gmail-ID validation against path-interpolation injection).

Targets:
- mcp-gmail/src/mcp_gmail/gmail_tools/gmail_id.py
- mcp-gmail/src/mcp_gmail/gmail_tools/audit_log.py (re-imports the
  audit heuristic; preserves WARN behavior verbatim)
- mcp-gmail/src/mcp_gmail/gmail_tools/gmail_client.py (5 path-
  interpolation sites)
- mcp-gmail/src/mcp_gmail/gmail_tools/gmail_client_write.py (9 path-
  interpolation sites + 3 JSON-body ID sites)

Two patterns are intentionally separate (see gmail_id.py docstring):
- Hard validation: 1..256 char URL-safe alphabet.
- Audit heuristic: 16..128 char URL-safe alphabet.

The system labels (INBOX, TRASH, UNREAD, STARRED, IMPORTANT, SENT,
DRAFT, SPAM, CATEGORY_*) are 4-12 chars and pass the validation
pattern but DO NOT pass the audit heuristic. This test suite
asserts both behaviors and the boundary between them.

Tool definitions add the declarative-JSON-Schema-`pattern` half of the gate.
Those tests live in test_gmail_id_validation_extended.py (split out to
keep this file under the project's 300-LOC ceiling).
"""

from __future__ import annotations

import logging

import httpx
import pytest
import respx

from mcp_gmail.gmail_tools.audit_log import audit
from mcp_gmail.gmail_tools.gmail_client import GMAIL_API_BASE, GmailClient
from mcp_gmail.gmail_tools.gmail_id import (
    id_looks_valid_audit_heuristic,
    validate_gmail_id,
)


# ---------------------------------------------------------------------------
# 5 system-label acceptance tests (regression guard against tightening
# the validation pattern back to the audit heuristic, which would break
# the batch_delete_emails flow)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "system_label",
    ["INBOX", "TRASH", "SPAM", "DRAFT", "UNREAD"],
)
def test_validate_gmail_id_accepts_short_system_labels(system_label):
    """Regression guard for the validation pattern.
    is the LOOSER {1,256} range, not the audit-heuristic {16,128}.
    Tightening it would reject the system labels Gmail uses for
    INBOX / TRASH / SPAM / DRAFT / UNREAD operations."""
    # No exception means the value passes validation.
    validated = validate_gmail_id(system_label, field="label_id")
    assert validated == system_label


@pytest.mark.asyncio
async def test_batch_modify_accepts_trash_in_add_label_ids():
    """CRITICAL regression guard for the batch_delete_emails flow.

    the batch_delete_emails calls batch_modify_messages with
    addLabelIds=['TRASH']. The previous design iteration applied
    the {16,128} audit-heuristic pattern at this site, which rejected
    'TRASH' (5 chars) as a path-validation failure and broke the flow.

    This was caught on first review. The fix is to use the
    looser {1,256} validation pattern. This test holds the line."""
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        route = router.post("/users/me/messages/batchModify").mock(return_value=httpx.Response(204))
        async with GmailClient(access_token="test-token") as client:
            # The 16-char min IDs match the audit heuristic; the
            # 5-char 'TRASH' label only matches the validation pattern.
            await client.batch_modify_messages(
                message_ids=["abc123def456ghi7", "abc123def456ghi8"],
                add_label_ids=["TRASH"],
            )
        assert route.called, "batch_modify_messages should have hit Gmail"


# ---------------------------------------------------------------------------
# 7 path-traversal rejection tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad_value",
    [
        "../../etc/passwd",
        "msg/../../delete",
        "id/with/slashes",
        "id?query=injection",
        "id&inject=1",
        "id with space",
        "id\nwith\nnewlines",
    ],
)
def test_validate_gmail_id_rejects_path_traversal_shapes(bad_value):
    """every interpolation-unsafe character is rejected."""
    with pytest.raises(ValueError) as excinfo:
        validate_gmail_id(bad_value, field="message_id")
    assert "message_id" in str(excinfo.value)


def test_validate_gmail_id_rejects_empty_string():
    """An empty string fails (lower bound is 1 char)."""
    with pytest.raises(ValueError):
        validate_gmail_id("", field="message_id")


def test_validate_gmail_id_rejects_overlong_string():
    """A 257-char string fails (upper bound is 256)."""
    with pytest.raises(ValueError):
        validate_gmail_id("a" * 257, field="thread_id")


def test_validate_gmail_id_rejects_non_string():
    """Non-string types fail before regex evaluation."""
    with pytest.raises(ValueError) as excinfo:
        validate_gmail_id(12345, field="filter_id")  # type: ignore[arg-type]
    assert "filter_id" in str(excinfo.value)
    assert "string" in str(excinfo.value)


def test_validate_gmail_id_field_name_appears_in_error():
    """The error message names the failing field for caller debugging."""
    with pytest.raises(ValueError) as excinfo:
        validate_gmail_id("bad/path", field="draft_id")
    assert "draft_id" in str(excinfo.value)


# ---------------------------------------------------------------------------
# 2 audit-heuristic preservation tests (verbatim  behavior)
# ---------------------------------------------------------------------------


def test_audit_log_warns_on_short_id():
    """Audit observability heuristic preserved verbatim.

    A short value like 'TRASH' (5 chars) PASSES the validation
    pattern (so labels work) but FAILS the audit heuristic (so an
    audit record carrying a 'TRASH' message_id is promoted to WARN
    as a caller-bug signal). The two patterns coexist: validation
    gates URL/JSON safety, the heuristic gates observability."""
    assert id_looks_valid_audit_heuristic("TRASH") is False
    assert id_looks_valid_audit_heuristic(None) is True
    assert id_looks_valid_audit_heuristic("abc123def456ghi7") is True


def test_audit_log_still_warns_on_malformed_message_id():
    """End-to-end:  audit-log behavior preserved. A short
    or otherwise non-Gmail-shape message_id promotes the audit line
    to WARN level (this is what audit_log_warns_on_short_id asserts
    at the predicate level; here we exercise the full audit() call
    path)."""
    import io

    handler = logging.StreamHandler(io.StringIO())
    handler.setLevel(logging.DEBUG)
    audit_logger = logging.getLogger("mcp_gmail.gmail_tools.audit_log")
    prev_level = audit_logger.level
    audit_logger.setLevel(logging.DEBUG)
    audit_logger.addHandler(handler)
    try:
        audit(
            tool="read_email",
            auth0_sub="user-abc",
            account_email="x@example.com",
            outcome="ok",
            message_id="oops",  # too short for the audit heuristic
        )
    finally:
        audit_logger.removeHandler(handler)
        audit_logger.setLevel(prev_level)
    output = handler.stream.getvalue()  # type: ignore[attr-defined]
    assert "message_id_shape=invalid" in output


# ---------------------------------------------------------------------------
# Validator returns the value verbatim on success
# ---------------------------------------------------------------------------


def test_validate_gmail_id_returns_value_unchanged():
    """The validator returns the input on success so callers can
    write `id = validate_gmail_id(x, field='msg')` in one line."""
    valid = "abc123def456ghi7"
    assert validate_gmail_id(valid, field="message_id") == valid


def test_validate_gmail_id_accepts_full_alphabet():
    """The full URL-safe alphabet (alphanumeric + underscore + hyphen)
    is accepted at any length 1..256."""
    sample = "AaZz09_-AaZz09_-"
    assert validate_gmail_id(sample, field="message_id") == sample
