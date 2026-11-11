"""Regression tests for issues #35 and #36 in logging_filters.

#36: the redacting filter collapsed uvicorn access records' args, so uvicorn's
AccessFormatter failed to unpack its five fields. Every request printed a
traceback and lost its access line (seen in production, 2026-11-06).

#35: KV_FORM matched `code=` inside `error_code=`, so the audit line's error
code was logged as `<redacted>`.

These run the filters exactly as install_redacting_filter wires them, through
uvicorn's real formatter, because the bugs lived in that interaction.
"""

from __future__ import annotations

import io
import logging

import pytest
from uvicorn.logging import AccessFormatter

from mcp_gmail import logging_filters
from mcp_gmail.logging_filters import (
    REDACTED,
    ArgPreservingRedactingFilter,
    RedactingFilter,
    _redact,
    install_redacting_filter,
)

ACCESS_FORMAT = '%(client_addr)s - "%(request_line)s" %(status_code)s'


@pytest.fixture
def access_log():
    """A uvicorn.access logger with uvicorn's own formatter, filters installed
    by the app's real install function. Restores the logger afterward."""
    access = logging.getLogger("uvicorn.access")
    saved = (access.level, access.propagate, list(access.filters), list(access.handlers))
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(AccessFormatter(ACCESS_FORMAT, use_colors=False))
    access.handlers = [handler]
    access.filters = []
    access.setLevel(logging.INFO)
    access.propagate = False
    install_redacting_filter()
    yield access, stream
    access.setLevel(saved[0])
    access.propagate = saved[1]
    access.filters = saved[2]
    access.handlers = saved[3]


def _log_request(access, path: str, status: int = 200) -> None:
    access.info('%s - "%s %s HTTP/%s" %d', "203.0.113.5:40000", "GET", path, "1.1", status)


def test_access_lines_format_without_a_logging_error(access_log, capsys):
    access, stream = access_log
    _log_request(access, "/health")

    assert stream.getvalue().strip() == '203.0.113.5:40000 - "GET /health HTTP/1.1" 200 OK'
    assert "Logging error" not in capsys.readouterr().err


def test_the_collapsing_filter_is_what_broke_access_lines():
    """Pins the mechanism behind #36, so nobody swaps the parent filter back in."""
    record = logging.LogRecord(
        "uvicorn.access",
        logging.INFO,
        __file__,
        1,
        '%s - "%s %s HTTP/%s" %d',
        ("203.0.113.5:1", "GET", "/health", "1.1", 200),
        None,
    )
    RedactingFilter().filter(record)

    with pytest.raises(ValueError, match="not enough values to unpack"):
        AccessFormatter(ACCESS_FORMAT, use_colors=False).format(record)


def test_oauth_query_strings_are_still_scrubbed_from_access_lines(access_log):
    access, stream = access_log
    _log_request(access, "/oauth2callback?code=4/secretcode&state=signednonce")

    line = stream.getvalue()
    assert 'GET /oauth2callback HTTP/1.1" 200' in line
    assert "secretcode" not in line
    assert "signednonce" not in line


def test_secrets_in_other_access_paths_are_redacted_inside_their_arg(access_log):
    access, stream = access_log
    _log_request(access, "/mcp?access_token=leakedvalue123")

    line = stream.getvalue()
    assert "leakedvalue123" not in line
    assert f"access_token={REDACTED}" in line


def test_arg_preserving_filter_keeps_the_tuple_shape():
    record = logging.LogRecord(
        "uvicorn.access",
        logging.INFO,
        __file__,
        1,
        '%s - "%s %s HTTP/%s" %d',
        ("203.0.113.5:1", "GET", "/x?refresh_token=abc12345", "1.1", 200),
        None,
    )
    ArgPreservingRedactingFilter().filter(record)

    assert len(record.args) == 5
    assert record.args[4] == 200
    assert record.args[2] == f"/x?refresh_token={REDACTED}"


def test_arg_preserving_filter_fails_safe(monkeypatch):
    def boom(_text):
        raise RuntimeError("redaction broke")

    monkeypatch.setattr(logging_filters, "_redact", boom)
    record = logging.LogRecord(
        "uvicorn.access", logging.INFO, __file__, 1, "%s", ("code=abc",), None
    )
    ArgPreservingRedactingFilter().filter(record)

    assert record.msg == "<redaction-error>"
    assert record.args == ()


def test_audit_error_code_survives_the_installed_filter():
    """The exact audit line shape, through the filter production installs."""
    record = logging.LogRecord(
        "mcp_gmail.gmail_tools.audit_log",
        logging.INFO,
        __file__,
        1,
        "%s",
        ("tool=send_email sub=u email=e outcome=threading_refused error_code=-32007 reason=x",),
        None,
    )
    RedactingFilter().filter(record)

    assert "error_code=-32007" in record.msg
    assert REDACTED not in record.msg


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ("code=abc123", "abc123"),
        ("/oauth2callback?code=abc123&state=nonce456", "abc123"),
        ("/oauth2callback?code=abc123&state=nonce456", "nonce456"),
        ("auth_code=abc123", "abc123"),
        ("Code=abc123", "abc123"),
    ],
)
def test_real_codes_are_still_redacted(text, secret):
    assert secret not in _redact(text)


@pytest.mark.parametrize("text", ["error_code=-32007", "status_code=200", "ERROR_CODE=-32007"])
def test_named_non_secret_codes_are_kept(text):
    assert _redact(text) == text
