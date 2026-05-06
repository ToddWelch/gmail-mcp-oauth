"""Tests for gmail_tools.errors (scope_insufficient response shape).

The scope_insufficient response shape MUST include
`error_data.required_scopes`, `error_data.granted_scope`, and
`error_data.reconnect_hint` so callers can advise users to re-link
with broader scopes.
"""

from __future__ import annotations

from mcp_gmail.gmail_tools.errors import (
    RECONNECT_HINT_DEFAULT,
    ToolErrorCode,
    bad_request_error,
    needs_reauth_error,
    not_found_error,
    rate_limited_error,
    scope_insufficient_error,
    tool_error,
    unknown_error,
    upstream_error,
)


def test_tool_error_basic_shape():
    err = tool_error(ToolErrorCode.BAD_REQUEST, "missing field")
    assert err == {"code": -32001, "message": "missing field"}
    assert "data" not in err


def test_tool_error_with_error_data_wraps_under_data_namespace():
    err = tool_error(
        ToolErrorCode.UPSTREAM_ERROR,
        "boom",
        error_data={"status": 503},
    )
    assert err["code"] == -32006
    assert err["data"] == {"error_data": {"status": 503}}


def test_scope_insufficient_includes_all_three_required_fields():
    """scope_insufficient: required_scopes, granted_scope, reconnect_hint all present."""
    err = scope_insufficient_error(
        required_scopes=["https://www.googleapis.com/auth/gmail.modify"],
        granted_scope="openid email https://www.googleapis.com/auth/gmail.readonly",
    )
    assert err["code"] == ToolErrorCode.SCOPE_INSUFFICIENT
    error_data = err["data"]["error_data"]
    assert "required_scopes" in error_data
    assert "granted_scope" in error_data
    assert "reconnect_hint" in error_data


def test_scope_insufficient_default_reconnect_hint():
    err = scope_insufficient_error(
        required_scopes=["scope.x"],
        granted_scope="",
    )
    assert err["data"]["error_data"]["reconnect_hint"] == RECONNECT_HINT_DEFAULT


def test_scope_insufficient_required_scopes_is_list_not_tuple():
    """list() conversion in builder protects against tuple input from the caller."""
    err = scope_insufficient_error(
        required_scopes=("scope.x", "scope.y"),  # type: ignore[arg-type]
        granted_scope="",
    )
    assert isinstance(err["data"]["error_data"]["required_scopes"], list)
    assert err["data"]["error_data"]["required_scopes"] == ["scope.x", "scope.y"]


def test_scope_insufficient_passes_granted_scope_through_verbatim():
    granted = "openid email https://www.googleapis.com/auth/gmail.readonly"
    err = scope_insufficient_error(
        required_scopes=["https://www.googleapis.com/auth/gmail.send"],
        granted_scope=granted,
    )
    assert err["data"]["error_data"]["granted_scope"] == granted


def test_scope_insufficient_custom_reconnect_hint():
    err = scope_insufficient_error(
        required_scopes=["x"],
        granted_scope="",
        reconnect_hint="custom hint",
    )
    assert err["data"]["error_data"]["reconnect_hint"] == "custom hint"


def test_scope_insufficient_omits_sufficient_alternatives_when_none():
    """sufficient_alternatives is optional. When the
    caller does NOT pass it, the key MUST be absent from error_data
    so the response shape stays minimal for callers that have not
    adopted the new field.
    """
    err = scope_insufficient_error(
        required_scopes=["scope.x"],
        granted_scope="",
    )
    error_data = err["data"]["error_data"]
    assert "sufficient_alternatives" not in error_data


def test_scope_insufficient_includes_sufficient_alternatives_when_provided():
    """When provided, sufficient_alternatives flows through verbatim
    (converted to a list to defend against tuple input).
    """
    err = scope_insufficient_error(
        required_scopes=["scope.x"],
        granted_scope="",
        sufficient_alternatives=["scope.x", "scope.y"],
    )
    assert err["data"]["error_data"]["sufficient_alternatives"] == [
        "scope.x",
        "scope.y",
    ]


def test_needs_reauth_error_uses_correct_code():
    err = needs_reauth_error("token revoked")
    assert err["code"] == ToolErrorCode.NEEDS_REAUTH
    assert err["message"] == "token revoked"


def test_not_found_error():
    err = not_found_error("message not found")
    assert err["code"] == ToolErrorCode.NOT_FOUND


def test_bad_request_error():
    err = bad_request_error("missing arg")
    assert err["code"] == ToolErrorCode.BAD_REQUEST


def test_rate_limited_error_includes_retry_after():
    err = rate_limited_error("slow down", retry_after_seconds=42)
    assert err["code"] == ToolErrorCode.RATE_LIMITED
    assert err["data"]["error_data"]["retry_after_seconds"] == 42


def test_rate_limited_error_without_retry_after():
    err = rate_limited_error("slow down")
    assert err["code"] == ToolErrorCode.RATE_LIMITED
    assert "data" not in err


def test_upstream_error_with_status():
    err = upstream_error("upstream 502", status=502)
    assert err["code"] == ToolErrorCode.UPSTREAM_ERROR
    assert err["data"]["error_data"]["status"] == 502


def test_upstream_error_without_status():
    err = upstream_error("upstream broken")
    assert err["code"] == ToolErrorCode.UPSTREAM_ERROR
    assert "data" not in err


def test_unknown_error():
    err = unknown_error("???")
    assert err["code"] == ToolErrorCode.UNKNOWN
    assert err["message"] == "???"


def test_tool_error_codes_are_stable_ints():
    """Codes are stable for clients to branch on."""
    assert ToolErrorCode.UNKNOWN == -32000
    assert ToolErrorCode.BAD_REQUEST == -32001
    assert ToolErrorCode.NOT_FOUND == -32002
    assert ToolErrorCode.NEEDS_REAUTH == -32003
    assert ToolErrorCode.SCOPE_INSUFFICIENT == -32004
    assert ToolErrorCode.RATE_LIMITED == -32005
    assert ToolErrorCode.UPSTREAM_ERROR == -32006
