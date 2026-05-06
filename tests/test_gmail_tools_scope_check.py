"""Tests for gmail_tools.scope_check.

Asserts the 30-tool requirement table (11 read + 14 write + 4 cleanup
+ 1 bootstrap) and the ScopeInsufficient exception shape used by the
scope_insufficient response. Also exercises SCOPE_HIERARCHY (scope-hierarchy refinement):
gmail.modify subsumes readonly, mail.google.com/ subsumes the four
core scopes, settings.basic remains exact-match.
"""

from __future__ import annotations

import pytest

from mcp_gmail.gmail_tools.scope_check import (
    EXPECTED_TOOL_COUNT,
    SCOPE_COMPOSE,
    SCOPE_FULL,
    SCOPE_MODIFY,
    SCOPE_READONLY,
    SCOPE_SEND,
    SCOPE_SETTINGS_BASIC,
    TOOL_SCOPE_REQUIREMENTS,
    ScopeInsufficient,
    UnknownTool,
    check_scopes,
)


def test_table_has_exactly_32_tools():
    """32 tools (11 read + 14 write + 4 cleanup + 1 bootstrap + 2 fanout)."""
    assert len(TOOL_SCOPE_REQUIREMENTS) == EXPECTED_TOOL_COUNT == 32


def test_connect_gmail_account_in_table_with_empty_scope_tuple():
    """bootstrap tool is registered with an empty scope tuple.

    The empty tuple is a presence marker only. The dispatcher
    short-circuits the bootstrap tool name BEFORE check_scopes is
    called (see gmail_tools/dispatch.py is_bootstrap_tool branch),
    so the empty tuple is never compared against a granted scope
    string in production. Documented at the table site so a future
    PR does not interpret the empty tuple as 'any granted scope is
    sufficient'.
    """
    assert "connect_gmail_account" in TOOL_SCOPE_REQUIREMENTS
    assert TOOL_SCOPE_REQUIREMENTS["connect_gmail_account"] == ()


def test_pr3a_read_tools_all_require_readonly_or_modify():
    """11 the read tools must require either gmail.readonly or gmail.modify (modify_thread)."""
    pr3a_tools = {
        "read_email",
        "search_emails",
        "download_attachment",
        "download_email",
        "get_thread",
        "list_inbox_threads",
        "get_inbox_with_threads",
        "modify_thread",
        "list_email_labels",
        "list_filters",
        "get_filter",
    }
    assert pr3a_tools.issubset(TOOL_SCOPE_REQUIREMENTS.keys())
    for name in pr3a_tools:
        scopes = TOOL_SCOPE_REQUIREMENTS[name]
        if name == "modify_thread":
            assert SCOPE_MODIFY in scopes
        else:
            assert SCOPE_READONLY in scopes


def test_pr3b_write_tools_all_present_in_table():
    """Write-tool names exist in the table for forward-looking lookups."""
    pr3b_tools = {
        "send_email",
        "create_draft",
        "update_draft",
        "list_drafts",
        "send_draft",
        "delete_draft",
        "create_label",
        "update_label",
        "delete_label",
        "modify_email_labels",
        "create_filter",
        "delete_filter",
        "delete_email",
        "batch_delete_emails",
    }
    assert pr3b_tools.issubset(TOOL_SCOPE_REQUIREMENTS.keys())


def test_pr3c_tools_all_present_in_table():
    """the 4 cleanup tools all have scope entries."""
    pr3c_tools = {
        "reply_all",
        "batch_modify_emails",
        "get_or_create_label",
        "create_filter_from_template",
    }
    assert pr3c_tools.issubset(TOOL_SCOPE_REQUIREMENTS.keys())


def test_pr3m_tools_present_with_readonly_scope():
    """the two fanout helpers ship with gmail.readonly scope."""
    assert TOOL_SCOPE_REQUIREMENTS["multi_search_emails"] == (SCOPE_READONLY,)
    assert TOOL_SCOPE_REQUIREMENTS["batch_read_emails"] == (SCOPE_READONLY,)


def test_pr3m_send_draft_base_scope_unchanged_at_send():
    """send_draft retains its gmail.send-only base scope. The send-draft
    post-send actions need gmail.modify, but that gate lives in the
    handler (drafts.py send_draft) so existing send-only callers do
    NOT see a scope_insufficient on the table-driven check."""
    assert TOOL_SCOPE_REQUIREMENTS["send_draft"] == (SCOPE_SEND,)


def test_reply_all_requires_send_AND_readonly():
    """reply_all reads original headers + sends; both scopes required."""
    scopes = TOOL_SCOPE_REQUIREMENTS["reply_all"]
    assert SCOPE_SEND in scopes
    assert SCOPE_READONLY in scopes


def test_reply_all_with_only_send_scope_fails():
    """Granting gmail.send alone is insufficient; readonly is also required."""
    with pytest.raises(ScopeInsufficient) as exc_info:
        check_scopes(tool_name="reply_all", granted_scope=SCOPE_SEND)
    assert SCOPE_READONLY in exc_info.value.required_scopes


def test_get_or_create_label_requires_modify():
    assert TOOL_SCOPE_REQUIREMENTS["get_or_create_label"] == (SCOPE_MODIFY,)


def test_batch_modify_emails_requires_modify():
    assert TOOL_SCOPE_REQUIREMENTS["batch_modify_emails"] == (SCOPE_MODIFY,)


def test_create_filter_from_template_requires_settings_basic():
    assert TOOL_SCOPE_REQUIREMENTS["create_filter_from_template"] == (SCOPE_SETTINGS_BASIC,)


def test_check_scopes_passes_with_exact_match():
    check_scopes(tool_name="read_email", granted_scope=SCOPE_READONLY)


def test_check_scopes_passes_with_extra_scopes_granted():
    check_scopes(
        tool_name="read_email",
        granted_scope=f"openid email {SCOPE_READONLY} {SCOPE_MODIFY}",
    )


def test_check_scopes_raises_on_empty_granted():
    with pytest.raises(ScopeInsufficient) as exc_info:
        check_scopes(tool_name="read_email", granted_scope="")
    assert SCOPE_READONLY in exc_info.value.required_scopes
    assert exc_info.value.granted_scope == ""


def test_check_scopes_raises_on_missing_scope():
    granted = f"openid email {SCOPE_READONLY}"
    with pytest.raises(ScopeInsufficient) as exc_info:
        check_scopes(tool_name="modify_thread", granted_scope=granted)
    assert SCOPE_MODIFY in exc_info.value.required_scopes
    assert exc_info.value.granted_scope == granted


def test_check_scopes_raises_on_unknown_tool():
    with pytest.raises(UnknownTool):
        check_scopes(tool_name="not_a_real_tool", granted_scope=SCOPE_READONLY)


def test_check_scopes_send_tool_requires_send_scope_only():
    """the send_email needs gmail.send, NOT modify or readonly."""
    with pytest.raises(ScopeInsufficient) as exc_info:
        check_scopes(tool_name="send_email", granted_scope=SCOPE_READONLY)
    assert SCOPE_SEND in exc_info.value.required_scopes


def test_check_scopes_modify_subsumes_readonly():
    """gmail.modify is documented by Google as accepting
    everywhere gmail.readonly is accepted. The matcher now reflects
    that per Google's per-method authorization tables. Granting
    gmail.modify alone satisfies tools that require gmail.readonly.
    """
    check_scopes(tool_name="read_email", granted_scope=SCOPE_MODIFY)


def test_delete_tools_provisional_modify_per_m4():
    """TRASH-semantics design: delete_email and batch_delete_emails are
    provisionally gmail.modify (trash semantics).
    """
    assert TOOL_SCOPE_REQUIREMENTS["delete_email"] == (SCOPE_MODIFY,)
    assert TOOL_SCOPE_REQUIREMENTS["batch_delete_emails"] == (SCOPE_MODIFY,)


def test_full_scope_constant_matches_gmail_documentation():
    """SCOPE_FULL is the mail.google.com/ scope (NOT gmail.permanent)."""
    assert SCOPE_FULL == "https://mail.google.com/"


def test_scope_insufficient_carries_data_for_m2_response():
    try:
        check_scopes(tool_name="send_email", granted_scope=SCOPE_READONLY)
    except ScopeInsufficient as exc:
        assert hasattr(exc, "required_scopes")
        assert hasattr(exc, "granted_scope")
        assert hasattr(exc, "sufficient_alternatives")
        assert isinstance(exc.required_scopes, list)
        assert isinstance(exc.granted_scope, str)
    else:
        pytest.fail("expected ScopeInsufficient")


# ---------------------------------------------------------------------------
# SCOPE_HIERARCHY tests (scope-hierarchy refinement).
# ---------------------------------------------------------------------------


def test_full_subsumes_readonly_at_read_tools():
    """mail.google.com/ accepted at users.messages.get etc."""
    check_scopes(tool_name="read_email", granted_scope=SCOPE_FULL)
    check_scopes(tool_name="get_thread", granted_scope=SCOPE_FULL)
    check_scopes(tool_name="list_email_labels", granted_scope=SCOPE_FULL)


def test_full_subsumes_modify_compose_send():
    """mail.google.com/ accepted everywhere modify, compose, send is."""
    check_scopes(tool_name="modify_thread", granted_scope=SCOPE_FULL)
    check_scopes(tool_name="create_draft", granted_scope=SCOPE_FULL)
    check_scopes(tool_name="send_email", granted_scope=SCOPE_FULL)
    check_scopes(tool_name="send_draft", granted_scope=SCOPE_FULL)


def test_modify_subsumes_compose_at_drafts_create():
    """gmail.modify accepted at users.drafts.create alongside compose."""
    check_scopes(tool_name="create_draft", granted_scope=SCOPE_MODIFY)
    check_scopes(tool_name="update_draft", granted_scope=SCOPE_MODIFY)
    check_scopes(tool_name="delete_draft", granted_scope=SCOPE_MODIFY)


def test_modify_subsumes_send_at_messages_send():
    """gmail.modify accepted at users.messages.send alongside send."""
    check_scopes(tool_name="send_email", granted_scope=SCOPE_MODIFY)
    check_scopes(tool_name="send_draft", granted_scope=SCOPE_MODIFY)


def test_compose_subsumes_send_but_send_does_not_subsume_compose():
    """Asymmetric: compose accepted at messages.send (subsumes send),
    but send rejected at drafts.create/update/delete (does NOT subsume
    compose). users.drafts.create requires compose, modify, or full.
    """
    # compose is sufficient for send_email (users.messages.send).
    check_scopes(tool_name="send_email", granted_scope=SCOPE_COMPOSE)
    # send alone fails at create_draft because compose is NOT subsumed by send.
    with pytest.raises(ScopeInsufficient):
        check_scopes(tool_name="create_draft", granted_scope=SCOPE_SEND)


def test_settings_basic_is_orthogonal_full_does_not_satisfy_filter_tools():
    """users.settings.filters.create / delete accept ONLY gmail.settings.basic.
    mail.google.com/ does NOT subsume settings.basic; granting full alone
    must still fail for filter tools.
    """
    with pytest.raises(ScopeInsufficient):
        check_scopes(tool_name="create_filter", granted_scope=SCOPE_FULL)
    with pytest.raises(ScopeInsufficient):
        check_scopes(tool_name="delete_filter", granted_scope=SCOPE_FULL)
    with pytest.raises(ScopeInsufficient):
        check_scopes(tool_name="create_filter_from_template", granted_scope=SCOPE_MODIFY)
    # Settings.basic itself works.
    check_scopes(tool_name="create_filter", granted_scope=SCOPE_SETTINGS_BASIC)


def test_reply_all_succeeds_with_only_full_scope():
    """reply_all needs send AND readonly; mail.google.com/ subsumes both."""
    check_scopes(tool_name="reply_all", granted_scope=SCOPE_FULL)


def test_reply_all_succeeds_with_only_modify_scope():
    """reply_all needs send AND readonly; gmail.modify subsumes both."""
    check_scopes(tool_name="reply_all", granted_scope=SCOPE_MODIFY)


def test_scope_insufficient_carries_sufficient_alternatives():
    """The exception's sufficient_alternatives lists the scopes that,
    granted alone, would satisfy the FIRST missing required scope.
    For send_email (requires send) with readonly granted, alternatives
    are {send, modify, full} sorted alphabetically.
    """
    with pytest.raises(ScopeInsufficient) as exc_info:
        check_scopes(tool_name="send_email", granted_scope=SCOPE_READONLY)
    alts = exc_info.value.sufficient_alternatives
    assert alts is not None
    assert SCOPE_SEND in alts
    assert SCOPE_MODIFY in alts
    assert SCOPE_FULL in alts
    # Sorted alphabetically per _sufficient_alternatives spec.
    assert alts == sorted(alts)


def test_production_default_scopes_satisfy_all_read_tools():
    """The production default OAuth scope set (openid + email +
    gmail.readonly) must satisfy every read tool except
    modify_thread (which requires gmail.modify by design). Regression
    guard: if someone tightens the read-tool requirements above
    readonly, smoke breaks immediately.
    """
    default_scope = "openid email https://www.googleapis.com/auth/gmail.readonly"
    pr3a_read_tools = {
        "read_email",
        "search_emails",
        "download_attachment",
        "download_email",
        "get_thread",
        "list_inbox_threads",
        "get_inbox_with_threads",
        "list_email_labels",
        "list_filters",
        "get_filter",
    }
    for name in pr3a_read_tools:
        check_scopes(tool_name=name, granted_scope=default_scope)
    # modify_thread is intentionally NOT satisfied by readonly-only.
    with pytest.raises(ScopeInsufficient):
        check_scopes(tool_name="modify_thread", granted_scope=default_scope)
