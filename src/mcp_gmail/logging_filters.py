"""Defense-in-depth log redaction for OAuth token material.

The first line of defense is "do not pass tokens to logger.* in the
first place." Every callsite in this service MUST avoid logging:

- Refresh tokens (Google's `1//...` long opaque strings)
- Access tokens
- ID tokens
- OAuth authorization codes
- Authorization headers
- Any value that round-trips through Fernet

This module is the second line of defense. A `logging.Filter` that
walks every log record's message and arguments and rewrites obvious
secret-shaped substrings to `<redacted>` before the record is emitted
by any handler. If a future patch accidentally interpolates a secret
into a log call, the filter catches it. The filter is mounted via
`install_redacting_filter()` from server.py at startup, after
`logging.basicConfig` and before `init_engine`, so every record
produced by any logger in the process passes through it.

Why a filter, not a formatter
-----------------------------
A formatter only sees the final string. A filter sees the raw record
including `record.args`, which lets us redact BEFORE percent-format
expansion. That matters because some logging configurations capture
records into structured backends (Sentry, journald) that bypass the
formatter.

Patterns covered
----------------
1. Bearer-style: `Bearer <opaque-string>` -> `Bearer <redacted>`
2. Google refresh tokens: `1//<base64ish>` -> `1//<redacted>`
3. Generic JWT-like blobs: three dot-separated base64url segments.
4. Common credential keys when present as `key=value` or `"key": "v"`:
   refresh_token, access_token, id_token, authorization, code,
   client_secret.

The patterns are intentionally over-redacting in the safe direction.
A genuine non-secret string that happens to look like a JWT will be
redacted; a genuine secret that doesn't match any pattern is still
caught by the no-log discipline at the callsite. The filter is a
guardrail, not a substitute for not logging secrets.
"""

from __future__ import annotations

import logging
import re

REDACTED = "<redacted>"

# 1. Bearer <token>. Captures the prefix so we can re-emit it verbatim.
#    Match a non-greedy run of token-shaped chars after the space.
BEARER = re.compile(r"(Bearer\s+)([A-Za-z0-9._\-+/=]+)", re.IGNORECASE)

# 2. Google refresh tokens: `1//<long base64ish>`. Refresh tokens issued
#    by Google's OAuth 2.0 endpoint are documented to start with `1//`
#    and run 60+ characters; we redact aggressively from `1//` to the
#    next non-token character.
GOOGLE_RT = re.compile(r"(1//)([A-Za-z0-9_\-]{20,})")

# 3. JWT-shaped: header.payload.signature where each segment is
#    URL-safe base64. The minimum length per segment (8) is well below
#    a real JWT (typically 100+) but high enough to avoid false
#    positives on things like `a.b.c`. NOTE: this regex may
#    over-redact long base64 strings that happen to contain dots in
#    legitimate non-token contexts (rare but possible in serialized
#    data). The over-redact bias is intentional: the safe direction
#    is to occasionally redact a non-secret rather than to ever leak
#    a real token. Do NOT "tighten" this regex without understanding
#    that the redacting filter is defense-in-depth and the primary
#    control is "do not log tokens at the callsite at all."
JWT_LIKE = re.compile(r"\b([A-Za-z0-9_\-]{8,})\.([A-Za-z0-9_\-]{8,})\.([A-Za-z0-9_\-]{8,})\b")

# 4. key=value and "key": "value" forms. We match six known-sensitive
#    keys and rewrite the value to <redacted>. The patterns handle:
#       refresh_token=abc, refresh_token=abc&...
#       "refresh_token": "abc"
#       refresh_token: abc
#    and the same for the other keys. Case-insensitive to catch
#    Authorization vs authorization.
SENSITIVE_KEYS = (
    "refresh_token",
    "access_token",
    "id_token",
    "authorization",
    "client_secret",
    "code",
    # : the OAuth `state` parameter on
    # /oauth2callback carries an HMAC-signed nonce. Logging it via
    # access logs (uvicorn writes the full path?query) leaked the
    # nonce, which an attacker can replay against a still-pending
    # /oauth/start window. Adding `state` to the sensitive-keys list
    # so the body-level redacting filter scrubs `state=...` shapes
    # complements the access-log query-string scrubber below.
    "state",
    # the post-callback confirmation
    # flow uses a single-use `pending_token` query string parameter
    # (and a hidden form field on POST /oauth/confirm). The token is
    # short-lived but has 10 minutes of replay value if an
    # eavesdropper acquires it. The AccessLogQueryStringScrubber
    # below already strips /oauth/* query strings; this entry covers
    # any pending_token that slips through into a body-level log
    # call (e.g. an exception path that captures request data).
    "pending_token",
)

# Matches `key=value` (form-encoded). value runs to & or whitespace.
KV_FORM = re.compile(
    r"(?P<key>" + "|".join(SENSITIVE_KEYS) + r")=(?P<val>[^&\s\"',]+)",
    re.IGNORECASE,
)

# Matches `"key": "value"` and `'key': 'value'` (JSON-ish).
KV_JSON = re.compile(
    r"(?P<quote>[\"'])(?P<key>"
    + "|".join(SENSITIVE_KEYS)
    + r")(?P=quote)\s*:\s*(?P=quote)(?P<val>[^\"']+)(?P=quote)",
    re.IGNORECASE,
)


def _redact(text: str) -> str:
    """Apply all redaction patterns to a string. Pure function, idempotent."""
    if not text:
        return text
    text = BEARER.sub(lambda m: m.group(1) + REDACTED, text)
    text = GOOGLE_RT.sub(lambda m: m.group(1) + REDACTED, text)
    text = JWT_LIKE.sub(REDACTED, text)
    text = KV_FORM.sub(lambda m: f"{m.group('key')}={REDACTED}", text)
    text = KV_JSON.sub(
        lambda m: (
            f"{m.group('quote')}{m.group('key')}{m.group('quote')}: "
            f"{m.group('quote')}{REDACTED}{m.group('quote')}"
        ),
        text,
    )
    return text


class RedactingFilter(logging.Filter):
    """Logging filter that redacts secret-shaped substrings from every record.

    The filter mutates `record.msg` and `record.args` in place. This is
    the standard pattern for logging filters that want to influence the
    final output regardless of which handler ends up emitting the record.

    A formatted version of the message is computed via
    `record.getMessage()` IF args are present, and `record.msg` is
    replaced with the redacted formatted string with `record.args` set
    to `()`. This collapses arg interpolation into a single redacted
    string so no downstream handler can re-expand the original args
    after the filter has run.

    Attribute redaction is conservative: only `record.msg` and
    `record.args` are touched. Other custom attributes (e.g. anything
    a future structlog wrapper attaches) are left alone, on the
    principle that the filter should not be silently rewriting fields
    the caller did not pass through the message channel. Custom
    attributes that contain secrets are the callsite's responsibility
    and violate the no-log discipline.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            # If args is present, interpolate first, then redact the
            # whole resulting string. Otherwise just redact msg.
            if record.args:
                rendered = record.getMessage()
                record.msg = _redact(rendered)
                record.args = ()
            elif isinstance(record.msg, str):
                record.msg = _redact(record.msg)
        except Exception:
            # A filter must never crash the logging pipeline. If
            # redaction fails for any reason, drop back to a known-safe
            # placeholder rather than letting the original record
            # through (which might still contain a secret).
            record.msg = "<redaction-error>"
            record.args = ()
        return True


class AccessLogQueryStringScrubber(logging.Filter):
    """: drop query strings from /oauth/* uvicorn access logs.

    Uvicorn's access logger emits records with a positional args tuple
    of (client_addr, method, path_with_query, http_version, status_code).
    The third entry (index 2) carries the full path including any
    query string. /oauth2callback?code=...&state=... therefore lands in
    a normal INFO record with the OAuth authorization code and
    HMAC-signed state nonce visible in the message after percent-format
    expansion. Both are short-lived but exploitable in a replay window
    if the log destination is shared (Sentry, journald, log-forwarder).

    The fix scrubs only the path entry, only when it begins with
    /oauth, and only the query string portion (everything after the
    first ?). The path itself stays so operators can tell which OAuth
    endpoint was hit. Status code, latency, and other fields remain.

    Implementation note: we mutate record.args (a tuple) by rebuilding
    it. Mutating a tuple is not in-place; we assign back to record.args
    so the formatted line picks up the change.
    """

    OAUTH_PREFIX = "/oauth"

    def filter(self, record: logging.LogRecord) -> bool:
        if not record.args or len(record.args) < 3:
            return True
        path_with_query = record.args[2]
        if not isinstance(path_with_query, str):
            return True
        if not path_with_query.startswith(self.OAUTH_PREFIX):
            return True
        path_only = path_with_query.split("?", 1)[0]
        record.args = (record.args[0], record.args[1], path_only, *record.args[3:])
        return True


def install_redacting_filter() -> None:
    """Attach RedactingFilter to root + uvicorn loggers, AccessLogQueryStringScrubber to access.

    Idempotent: filters already attached are skipped. Called once from
    server.py lifespan startup, after `logging.basicConfig` so the
    root logger's handlers exist.

    Handler-level + uvicorn logger-level
    ------------------------------------
    Python's logging flow runs `Logger.filter(record)` before
    `Logger.callHandlers(record)`. `callHandlers` walks up the parent
    chain consulting each ancestor logger's HANDLERS, not its filters.
    A root-logger filter therefore fires only for records logged
    directly at the root, never for propagated records from named
    children. Handler-level filters fire for every record that reaches
    that handler, regardless of origin.

    uvicorn's `uvicorn.access` and `uvicorn.error`
    loggers have their own handler chain. Attaching to those loggers
    AND their handlers covers both the access-log scrubber (filters
    must run BEFORE format expansion) and the body-level redacting
    filter (in case uvicorn ever logs token-shaped strings in error
    paths).
    """
    root = logging.getLogger()
    if not any(isinstance(f, RedactingFilter) for f in root.filters):
        root.addFilter(RedactingFilter())
    for handler in root.handlers:
        if not any(isinstance(f, RedactingFilter) for f in handler.filters):
            handler.addFilter(RedactingFilter())

    # uvicorn.access carries the path?query positional.
    access = logging.getLogger("uvicorn.access")
    if not any(isinstance(f, AccessLogQueryStringScrubber) for f in access.filters):
        access.addFilter(AccessLogQueryStringScrubber())
    if not any(isinstance(f, RedactingFilter) for f in access.filters):
        access.addFilter(RedactingFilter())
    for handler in access.handlers:
        if not any(isinstance(f, AccessLogQueryStringScrubber) for f in handler.filters):
            handler.addFilter(AccessLogQueryStringScrubber())
        if not any(isinstance(f, RedactingFilter) for f in handler.filters):
            handler.addFilter(RedactingFilter())

    # uvicorn.error covers startup tracebacks + exception paths.
    error = logging.getLogger("uvicorn.error")
    if not any(isinstance(f, RedactingFilter) for f in error.filters):
        error.addFilter(RedactingFilter())
    for handler in error.handlers:
        if not any(isinstance(f, RedactingFilter) for f in handler.filters):
            handler.addFilter(RedactingFilter())
