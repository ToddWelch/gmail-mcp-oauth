"""Tool-side error helpers.

Translates internal exceptions (TokenUnavailableError, GoogleOAuthError,
GmailApiError, ScopeInsufficient, validation errors) into a consistent
JSON-RPC-shaped error result with a stable code namespace AND an
MCP-style structured `_meta` block carrying machine-readable hints.

Error codes
-----------
We piggy-back on JSON-RPC's error code field and reserve a small range
for tool-side conditions:

    -32000  unknown / wrapped Gmail error
    -32001  bad_request           (caller-side input invariant violated)
    -32002  not_found             (Gmail returned 404; row never linked)
    -32003  needs_reauth          (token row missing/revoked/invalid_grant)
    -32004  scope_insufficient    (granted scope < required scope)
    -32005  rate_limited          (Gmail returned 429 / userRateLimitExceeded)
    -32006  upstream_error        (Gmail 5xx)

The numeric values are stable. Claude.ai sees the message + data; the
host carries the codes mostly for machine-side branching by future
clients.

Hybrid scope handling
---------------------------------------------------
When `scope_insufficient` fires we DO NOT silently broaden the OAuth
scope default at link time. Instead the error response includes a
structured `error_data.required_scopes` array listing every scope
missing for the requested tool, plus `granted_scope` (what the user
actually granted) and a `reconnect_hint` pointing at /oauth/start.
The caller surfaces this so the human can re-link with the right
scopes; the connector default stays narrow (Decision 3, Option C).

The shape MUST be:

    {
        "code": -32004,
        "message": "...",
        "data": {
            "error_data": {
                "required_scopes": [...],
                "granted_scope": "...",
                "reconnect_hint": "Re-link the account at /oauth/start ..."
            }
        }
    }

The nested `data.error_data` indirection is intentional: JSON-RPC's
`error.data` is the standard slot, and within it we use `error_data`
as a stable namespace so we can add fields later without breaking
clients that read top-level data directly.
"""

from __future__ import annotations

from typing import Any


# ---------------------------------------------------------------------------
# Stable error codes
# ---------------------------------------------------------------------------


class ToolErrorCode:
    """Namespace for tool-side JSON-RPC error codes.

    Plain class with int constants instead of an Enum so the values
    interpolate cleanly into JSON-RPC error objects without `.value`
    lookups at every call site.
    """

    UNKNOWN = -32000
    BAD_REQUEST = -32001
    NOT_FOUND = -32002
    NEEDS_REAUTH = -32003
    SCOPE_INSUFFICIENT = -32004
    RATE_LIMITED = -32005
    UPSTREAM_ERROR = -32006


# Default reconnect hint string used by scope_insufficient errors. Kept
# as a module-level constant so tests can assert byte-exact match
# without duplicating the string literal.
RECONNECT_HINT_DEFAULT = "Re-link the account at /oauth/start to grant additional scopes"


# ---------------------------------------------------------------------------
# Error helper
# ---------------------------------------------------------------------------


def tool_error(
    code: int,
    message: str,
    *,
    error_data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return a JSON-RPC-shaped error dict with optional structured `error_data`.

    Output shape:
        {"code": int, "message": str}                   (no error_data)
        {"code": int, "message": str,
         "data": {"error_data": {...}}}                 (with error_data)

    The caller is expected to attach this dict to a JSON-RPC error
    response. The dispatcher layer wraps the return value into the
    full {"jsonrpc": "2.0", "id": ..., "error": ...} envelope.

    `error_data` is opaque to this helper. The caller chooses the
    fields. For scope_insufficient errors, callers should use the
    `scope_insufficient_error` convenience builder below to enforce
    the scope-insufficient contract instead of hand-rolling the dict.
    """
    out: dict[str, Any] = {"code": code, "message": message}
    if error_data is not None:
        out["data"] = {"error_data": error_data}
    return out


def scope_insufficient_error(
    *,
    required_scopes: list[str],
    granted_scope: str,
    reconnect_hint: str = RECONNECT_HINT_DEFAULT,
    sufficient_alternatives: list[str] | None = None,
) -> dict[str, Any]:
    """Build the scope_insufficient response shape.

    Preferred over hand-rolling tool_error(SCOPE_INSUFFICIENT, ...) at
    call sites because it enforces:

    1. All three core keys are present (required_scopes, granted_scope,
       reconnect_hint). Missing any one is a contract violation; this
       builder cannot return a half-shaped response.
    2. `required_scopes` is a list (not a string, not None). Empty
       list is allowed in degenerate cases but the caller almost
       certainly wants to populate it.
    3. The reconnect hint default points at /oauth/start.
    4. Optional `sufficient_alternatives`: when the
       matcher knows that granting any of several scopes would
       satisfy the missing requirement, that list flows through to
       error_data so the operator UI can surface it. The key is
       OMITTED from error_data when the kwarg is None so the response
       shape stays minimal for callers that have not adopted it.

    The PR brief calls this out as a structural test target. Tests
    assert `assert "required_scopes" in resp["data"]["error_data"]`
    et al, which only passes if this builder (or an equivalent) is
    used.
    """
    error_data: dict[str, Any] = {
        "required_scopes": list(required_scopes),
        "granted_scope": granted_scope,
        "reconnect_hint": reconnect_hint,
    }
    if sufficient_alternatives is not None:
        error_data["sufficient_alternatives"] = list(sufficient_alternatives)
    return tool_error(
        ToolErrorCode.SCOPE_INSUFFICIENT,
        f"insufficient OAuth scope: required {required_scopes!r}",
        error_data=error_data,
    )


def needs_reauth_error(message: str) -> dict[str, Any]:
    """Return a needs_reauth error. Caller surface for token-row gone/revoked."""
    return tool_error(ToolErrorCode.NEEDS_REAUTH, message)


def not_found_error(message: str) -> dict[str, Any]:
    """Return a not_found error. Used when Gmail returns 404."""
    return tool_error(ToolErrorCode.NOT_FOUND, message)


def bad_request_error(message: str) -> dict[str, Any]:
    """Return a bad_request error. Used for caller-side input failures."""
    return tool_error(ToolErrorCode.BAD_REQUEST, message)


def upstream_error(message: str, *, status: int | None = None) -> dict[str, Any]:
    """Return an upstream_error. Used when Gmail responds 5xx."""
    data: dict[str, Any] | None = None
    if status is not None:
        data = {"status": status}
    return tool_error(ToolErrorCode.UPSTREAM_ERROR, message, error_data=data)


def rate_limited_error(message: str, *, retry_after_seconds: int | None = None) -> dict[str, Any]:
    """Return a rate_limited error.

    `retry_after_seconds` flows through to error_data so Claude can
    pace retries. Gmail's 429 response sometimes includes a
    Retry-After header; the GmailClient surfaces it for us.
    """
    data: dict[str, Any] | None = None
    if retry_after_seconds is not None:
        data = {"retry_after_seconds": retry_after_seconds}
    return tool_error(ToolErrorCode.RATE_LIMITED, message, error_data=data)


def unknown_error(message: str) -> dict[str, Any]:
    """Return a generic UNKNOWN error. Avoid using directly; prefer the typed helpers."""
    return tool_error(ToolErrorCode.UNKNOWN, message)
