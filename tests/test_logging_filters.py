"""Defense-in-depth log redaction.

Targets: mcp-gmail/src/mcp_gmail/logging_filters.py:RedactingFilter
Targets: mcp-gmail/src/mcp_gmail/logging_filters.py:install_redacting_filter
Targets: mcp-gmail/src/mcp_gmail/logging_filters.py:_redact

Seven cases per the agreed test matrix. Each maps to a distinct
secret-shape that must be redacted before reaching any handler.
"""

from __future__ import annotations

import logging

import pytest

from mcp_gmail.logging_filters import (
    REDACTED,
    RedactingFilter,
    _redact,
    install_redacting_filter,
)


@pytest.fixture
def caplog_with_filter(caplog):
    """caplog with a RedactingFilter attached at handler level.

    pytest's caplog fixture installs a LogCaptureHandler on the root
    logger and attaches a propagate handler. To intercept records
    BEFORE caplog captures their formatted message, we attach the
    RedactingFilter to caplog's handler directly. This mirrors how
    `install_redacting_filter()` attaches handler-level filters in
    production: filters on a Logger object only fire for records
    emitted at that logger, not for propagated records from named
    children.
    """
    f = RedactingFilter()
    caplog.handler.addFilter(f)
    try:
        yield caplog
    finally:
        caplog.handler.removeFilter(f)


# Case 1: Bearer header.
def test_redacts_bearer_token(caplog_with_filter):
    logger = logging.getLogger("test_bearer")
    with caplog_with_filter.at_level(logging.INFO):
        logger.info("Authorization: Bearer abcDEF123ghi.JKL_456-mno")
    record = caplog_with_filter.records[-1]
    msg = record.getMessage()
    assert "abcDEF123ghi" not in msg
    assert "Bearer" in msg
    assert REDACTED in msg


# Case 2: Google refresh token shape.
def test_redacts_google_refresh_token(caplog_with_filter):
    logger = logging.getLogger("test_google_rt")
    fake_rt = "1//0eABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij_klmnop-qrst"
    with caplog_with_filter.at_level(logging.INFO):
        logger.info("got refresh_token=%s from google", fake_rt)
    record = caplog_with_filter.records[-1]
    msg = record.getMessage()
    assert "0eABCDEFGHIJKLMNOPQRSTUVWXYZ" not in msg
    assert REDACTED in msg


# Case 3: JWT-shaped token (three dot-separated base64 segments).
def test_redacts_jwt_shaped_string(caplog_with_filter):
    logger = logging.getLogger("test_jwt")
    fake_jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.signaturePart_HERE"
    with caplog_with_filter.at_level(logging.INFO):
        logger.info("token: %s", fake_jwt)
    record = caplog_with_filter.records[-1]
    msg = record.getMessage()
    assert "eyJhbGciOiJSUzI1NiJ9" not in msg
    assert REDACTED in msg


# Case 4: key=value form. adds `state` to
# SENSITIVE_KEYS so the body-level redacting filter scrubs OAuth state
# nonce shapes wherever they appear. The  expectation
# (state= passes through) is now flipped: state= IS redacted.
def test_redacts_kv_form_pairs():
    src = "code=4/0AdLIrYf-supersecretvalue&state=abcSignedNonce123"
    out = _redact(src)
    assert "supersecretvalue" not in out
    assert "code=" + REDACTED in out
    # state= is now in SENSITIVE_KEYS.
    assert "abcSignedNonce123" not in out
    assert "state=" + REDACTED in out


# Case 5: JSON-ish "key": "value" form.
def test_redacts_kv_json_pairs():
    src = '{"refresh_token": "1//rt-secret-abc", "scope": "read"}'
    out = _redact(src)
    assert "rt-secret-abc" not in out
    assert '"refresh_token": "<redacted>"' in out
    # scope is not sensitive, must pass through.
    assert '"scope": "read"' in out


# Case 6: Filter never crashes the pipeline; on internal error returns
# a safe placeholder rather than the original message.
def test_filter_swallows_redaction_errors_safely(monkeypatch):
    """If _redact raises, the filter must not propagate the error."""
    f = RedactingFilter()

    # Monkeypatch the module-level _redact to blow up.
    from mcp_gmail import logging_filters

    def boom(_text):
        raise RuntimeError("synthetic")

    monkeypatch.setattr(logging_filters, "_redact", boom)

    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="Bearer abc.def.ghi",
        args=(),
        exc_info=None,
    )
    # Filter must return True (don't drop the record) and replace msg.
    assert f.filter(record) is True
    assert record.msg == "<redaction-error>"


# Case 7: install_redacting_filter is idempotent and covers root + handlers.
def test_install_redacting_filter_idempotent():
    root = logging.getLogger()
    # Ensure we have at least one handler so the handler path exercises.
    test_handler = logging.StreamHandler()
    root.addHandler(test_handler)
    # Clean any leftover filters from earlier tests.
    for existing in [f for f in root.filters if isinstance(f, RedactingFilter)]:
        root.removeFilter(existing)
    for existing in [f for f in test_handler.filters if isinstance(f, RedactingFilter)]:
        test_handler.removeFilter(existing)

    try:
        install_redacting_filter()
        install_redacting_filter()  # second call must not double-attach

        root_redacting = [f for f in root.filters if isinstance(f, RedactingFilter)]
        handler_redacting = [f for f in test_handler.filters if isinstance(f, RedactingFilter)]
        assert len(root_redacting) == 1
        assert len(handler_redacting) == 1
    finally:
        # Cleanup so the rest of the test suite doesn't see this filter.
        for f in [f for f in root.filters if isinstance(f, RedactingFilter)]:
            root.removeFilter(f)
        # Also strip filters added to uvicorn loggers by install_redacting_filter
        for logger_name in ("uvicorn.access", "uvicorn.error"):
            lg = logging.getLogger(logger_name)
            for f in list(lg.filters):
                lg.removeFilter(f)
        root.removeHandler(test_handler)


# ---------------------------------------------------------------------------
# : AccessLogQueryStringScrubber tests.
#
# Uvicorn's access logger emits records with this 5-arg shape:
#   record.args = (client_addr, method, path_with_query, http_version, status)
# The third positional (index 2) is the path?query. /oauth2callback hits
# carry the OAuth code + signed state nonce in the query string; before
# Previously these were emitted verbatim in access logs. Tests below build
# records with the real shape and assert the scrubber strips the query
# string ONLY when the path begins with /oauth.
# ---------------------------------------------------------------------------


from mcp_gmail.logging_filters import AccessLogQueryStringScrubber  # noqa: E402


def _make_uvicorn_access_record(path_with_query: str) -> logging.LogRecord:
    """Build a LogRecord with uvicorn.access's 5-arg positional shape."""
    return logging.LogRecord(
        name="uvicorn.access",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg='%s - "%s %s HTTP/%s" %d',
        args=("127.0.0.1:5000", "GET", path_with_query, "1.1", 200),
        exc_info=None,
    )


def test_scrubber_strips_oauth_query_string():
    """Critical regression net for Item 1: state= and code= must not survive."""
    f = AccessLogQueryStringScrubber()
    record = _make_uvicorn_access_record(
        "/oauth2callback?code=4/0AbCdEf&state=signedNoncePayload.abc"
    )
    assert f.filter(record) is True
    msg = record.getMessage()
    assert "code=" not in msg
    assert "state=" not in msg
    assert "/oauth2callback" in msg
    # Status code, method, addr remain visible.
    assert "200" in msg
    assert "GET" in msg


def test_scrubber_leaves_non_oauth_paths_alone():
    """Non-/oauth paths must pass through untouched (e.g. /mcp, /health)."""
    f = AccessLogQueryStringScrubber()
    record = _make_uvicorn_access_record("/mcp?diagnostic=true")
    assert f.filter(record) is True
    msg = record.getMessage()
    assert "/mcp?diagnostic=true" in msg


def test_scrubber_handles_oauth_path_without_query():
    """No query string -> no-op."""
    f = AccessLogQueryStringScrubber()
    record = _make_uvicorn_access_record("/oauth/start")
    assert f.filter(record) is True
    msg = record.getMessage()
    assert "/oauth/start" in msg


def test_scrubber_handles_short_args_safely():
    """A record with fewer than 3 positional args is left alone."""
    f = AccessLogQueryStringScrubber()
    record = logging.LogRecord(
        name="uvicorn.access",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="something happened: %s",
        args=("only-one-arg",),
        exc_info=None,
    )
    assert f.filter(record) is True


def test_scrubber_handles_non_string_path_safely():
    """A record where args[2] is not a str passes through unchanged."""
    f = AccessLogQueryStringScrubber()
    record = logging.LogRecord(
        name="uvicorn.access",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="%s %s %s %s %s",
        args=("addr", "GET", 12345, "1.1", 200),
        exc_info=None,
    )
    assert f.filter(record) is True
    # args[2] still 12345, no AttributeError raised.
    assert record.args[2] == 12345


def test_scrubber_preserves_method_and_status():
    """The other access-log positionals must be untouched after scrubbing."""
    f = AccessLogQueryStringScrubber()
    record = _make_uvicorn_access_record("/oauth/start?account_email=x@y.com")
    f.filter(record)
    # Args order: (addr, method, path, version, status)
    assert record.args[0] == "127.0.0.1:5000"
    assert record.args[1] == "GET"
    assert record.args[2] == "/oauth/start"
    assert record.args[3] == "1.1"
    assert record.args[4] == 200


def test_install_attaches_scrubber_to_uvicorn_access_logger():
    """install_redacting_filter wires the scrubber onto uvicorn.access."""
    access = logging.getLogger("uvicorn.access")
    # Strip any leftover filters from earlier tests.
    for existing in list(access.filters):
        access.removeFilter(existing)
    try:
        install_redacting_filter()
        scrubbers = [f for f in access.filters if isinstance(f, AccessLogQueryStringScrubber)]
        redactors = [f for f in access.filters if isinstance(f, RedactingFilter)]
        assert len(scrubbers) == 1
        assert len(redactors) == 1
    finally:
        for f in list(access.filters):
            access.removeFilter(f)
