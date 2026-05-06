"""Tests for gmail_tools.audit_log.audit (audit observability + filename rejection).

Critical structural property: the audit() helper signature must REJECT
a `filename` keyword argument because filenames are user-supplied data
that can leak case/personnel/business identifiers via log lines.
"""

from __future__ import annotations

import logging

import pytest

from mcp_gmail.gmail_tools.audit_log import audit


VALID_GMAIL_ID = "abc123def456ghi7"  # 16 chars, matches _GMAIL_ID_PATTERN


def test_audit_rejects_filename_kwarg_structurally():
    """Audit-allowlist: audit() must NOT accept `filename`. Passing it is a TypeError."""
    with pytest.raises(TypeError) as excinfo:
        audit(  # type: ignore[call-arg]
            tool="read_email",
            auth0_sub="user-abc",
            account_email="x@example.com",
            outcome="ok",
            filename="leaky.pdf",
        )
    assert "filename" in str(excinfo.value)


def test_audit_emits_required_fields(caplog):
    """Every call records tool, sub, email, outcome at INFO level."""
    with caplog.at_level(logging.INFO, logger="mcp_gmail.gmail_tools.audit_log"):
        audit(
            tool="read_email",
            auth0_sub="user-abc",
            account_email="x@example.com",
            outcome="ok",
        )
    # Find the audit record (ignore unrelated logs).
    records = [r for r in caplog.records if r.name == "mcp_gmail.gmail_tools.audit_log"]
    assert len(records) == 1
    msg = records[0].getMessage()
    assert "tool=read_email" in msg
    assert "sub=user-abc" in msg
    assert "email=x@example.com" in msg
    assert "outcome=ok" in msg


def test_audit_includes_optional_fields_when_supplied(caplog):
    with caplog.at_level(logging.INFO, logger="mcp_gmail.gmail_tools.audit_log"):
        audit(
            tool="download_attachment",
            auth0_sub="user-abc",
            account_email="x@example.com",
            outcome="ok",
            message_id=VALID_GMAIL_ID,
            attachment_id=VALID_GMAIL_ID + "ATT",
            mime_type="application/pdf",
            size_bytes=12345,
        )
    records = [r for r in caplog.records if r.name == "mcp_gmail.gmail_tools.audit_log"]
    msg = records[0].getMessage()
    assert "message_id=" + VALID_GMAIL_ID in msg
    assert "attachment_id=" + VALID_GMAIL_ID + "ATT" in msg
    assert "mime_type=application/pdf" in msg
    assert "size_bytes=12345" in msg


def test_audit_omits_unspecified_fields(caplog):
    """None-valued optional fields do not appear in the log line."""
    with caplog.at_level(logging.INFO, logger="mcp_gmail.gmail_tools.audit_log"):
        audit(
            tool="list_email_labels",
            auth0_sub="user-abc",
            account_email="x@example.com",
            outcome="ok",
        )
    msg = caplog.records[-1].getMessage()
    assert "message_id=" not in msg
    assert "thread_id=" not in msg
    assert "attachment_id=" not in msg


def test_audit_warns_on_malformed_message_id(caplog):
    """Malformed message_id promotes the line to WARN level."""
    with caplog.at_level(logging.DEBUG, logger="mcp_gmail.gmail_tools.audit_log"):
        audit(
            tool="read_email",
            auth0_sub="user-abc",
            account_email="x@example.com",
            outcome="ok",
            message_id="not-an-id",  # too short, fails regex
        )
    records = [r for r in caplog.records if r.name == "mcp_gmail.gmail_tools.audit_log"]
    assert any(r.levelno == logging.WARNING for r in records)


def test_audit_warns_on_malformed_thread_id(caplog):
    with caplog.at_level(logging.DEBUG, logger="mcp_gmail.gmail_tools.audit_log"):
        audit(
            tool="get_thread",
            auth0_sub="user-abc",
            account_email="x@example.com",
            outcome="ok",
            thread_id="bad",
        )
    records = [r for r in caplog.records if r.name == "mcp_gmail.gmail_tools.audit_log"]
    assert any(r.levelno == logging.WARNING for r in records)


def test_audit_records_error_code(caplog):
    with caplog.at_level(logging.INFO, logger="mcp_gmail.gmail_tools.audit_log"):
        audit(
            tool="read_email",
            auth0_sub="user-abc",
            account_email="x@example.com",
            outcome="needs_reauth",
            error_code=-32003,
        )
    msg = caplog.records[-1].getMessage()
    assert "error_code=-32003" in msg
    assert "outcome=needs_reauth" in msg


def test_audit_signature_is_keyword_only():
    """All parameters are keyword-only; positional-only call raises TypeError."""
    with pytest.raises(TypeError):
        audit("read_email", "sub", "email", "ok")  # type: ignore[misc]


def test_audit_does_not_log_subject_or_body(caplog):
    """Sanity: only whitelisted fields can be passed; if a caller tries
    to inject subject= or body= the call fails before logging.
    """
    with pytest.raises(TypeError):
        audit(  # type: ignore[call-arg]
            tool="read_email",
            auth0_sub="user-abc",
            account_email="x@example.com",
            outcome="ok",
            subject="urgent: re: confidential",
        )
    with pytest.raises(TypeError):
        audit(  # type: ignore[call-arg]
            tool="read_email",
            auth0_sub="user-abc",
            account_email="x@example.com",
            outcome="ok",
            body="hello world",
        )


# ---------------------------------------------------------------------------
# Additive fields
# ---------------------------------------------------------------------------


def test_audit_includes_draft_id_when_supplied(caplog):
    """draft_id is an approved field for the draft tools."""
    with caplog.at_level(logging.INFO, logger="mcp_gmail.gmail_tools.audit_log"):
        audit(
            tool="send_draft",
            auth0_sub="user-abc",
            account_email="x@example.com",
            outcome="ok",
            draft_id="r123",
        )
    msg = caplog.records[-1].getMessage()
    assert "draft_id=r123" in msg


def test_audit_includes_filter_id_when_supplied(caplog):
    """filter_id is an approved field for filter tools."""
    with caplog.at_level(logging.INFO, logger="mcp_gmail.gmail_tools.audit_log"):
        audit(
            tool="delete_filter",
            auth0_sub="user-abc",
            account_email="x@example.com",
            outcome="ok",
            filter_id="F1",
        )
    msg = caplog.records[-1].getMessage()
    assert "filter_id=F1" in msg


def test_audit_omits_draft_and_filter_when_not_set(caplog):
    """When the new optional fields are None, they don't appear in the line."""
    with caplog.at_level(logging.INFO, logger="mcp_gmail.gmail_tools.audit_log"):
        audit(
            tool="read_email",
            auth0_sub="user-abc",
            account_email="x@example.com",
            outcome="ok",
        )
    msg = caplog.records[-1].getMessage()
    assert "draft_id=" not in msg
    assert "filter_id=" not in msg


def test_audit_still_rejects_filename_after_pr3b_extension():
    """Regression: adding draft_id/filter_id must not weaken the
    audit-allowlist filename rejection. The keyword-only signature
    still has no `filename` parameter."""
    with pytest.raises(TypeError) as excinfo:
        audit(  # type: ignore[call-arg]
            tool="send_email",
            auth0_sub="user-abc",
            account_email="x@example.com",
            outcome="ok",
            draft_id="d1",
            filename="leaky.pdf",
        )
    assert "filename" in str(excinfo.value)
