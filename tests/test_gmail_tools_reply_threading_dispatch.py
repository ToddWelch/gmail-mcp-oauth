"""End to end through dispatch_tool_call: the real scope row, router and audit line.

Item 5 promises an audit line on every refusal and item 7 a loud scope refusal,
so these run the whole path instead of calling a handler directly. They also pin
what the audit line must never carry: subject, recipients or a Message-ID.
"""

from __future__ import annotations

import logging

import httpx
import pytest
import respx

from mcp_gmail.gmail_tools.dispatch import dispatch_tool_call
from mcp_gmail.gmail_tools.errors import ToolErrorCode
from mcp_gmail.gmail_tools.gmail_client import GMAIL_API_BASE
from mcp_gmail.gmail_tools.idempotency import default_cache
from mcp_gmail.logging_filters import silence_http_client_url_logging

from ._threading_fixtures import (
    SCOPES_FULL_ACCESS,
    SCOPES_SEND_ONLY,
    TARGET_RFC_ID,
    TARGET_THREAD,
    error_reason,
    message_metadata,
    mount_draft,
    mount_lookup,
    mount_send,
    posted_body,
)
from .test_gmail_tools_dispatch import (  # noqa: F401
    _seed_token,
    _stub_token_manager_with,
    init_engine_for_dispatch,
)

ACCOUNT = "x@example.com"
SECRET_SUBJECT = "Re: Confidential Supplier Terms"
RECIPIENT = "pat.supplier@example.net"


@pytest.fixture(autouse=True)
def _clear_replay_cache():
    default_cache.clear()
    yield
    default_cache.clear()


async def _dispatch(tool_name: str, scope: str, **arguments):
    settings = _seed_token(auth0_sub="user-a", account_email=ACCOUNT, scope=scope)
    with _stub_token_manager_with("access-tok"):
        return await dispatch_tool_call(
            tool_name=tool_name,
            arguments={"account_email": ACCOUNT, **arguments},
            claims={"sub": "user-a"},
            settings=settings,
        )


def _send_args(**overrides) -> dict:
    args = {
        "sender": ACCOUNT,
        "to": [RECIPIENT],
        "subject": "Re: Items",
        "body_text": "secret body words",
        "reply_to_message_id": TARGET_RFC_ID,
    }
    args.update(overrides)
    return args


def _audit_lines(caplog) -> list[str]:
    return [r.getMessage() for r in caplog.records if r.name == "mcp_gmail.gmail_tools.audit_log"]


@pytest.mark.asyncio
async def test_reply_through_dispatch_posts_the_thread_id_with_todays_arguments():
    """Today's arguments only: this is the cached-schema client the fix must protect."""
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        mount_lookup(router, message_metadata())
        send_route = mount_send(router)
        result = await _dispatch("send_email", SCOPES_FULL_ACCESS, **_send_args())

    assert result["threadId"] == TARGET_THREAD
    assert posted_body(send_route)["threadId"] == TARGET_THREAD


@pytest.mark.asyncio
async def test_new_email_through_dispatch_works_with_send_only_scope():
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        search = mount_lookup(router)
        send_route = mount_send(router, thread_id="brandnewthread01")
        result = await _dispatch(
            "send_email",
            SCOPES_SEND_ONLY,
            **_send_args(subject="A new conversation", reply_to_message_id=None),
        )

    assert search.call_count == 0
    assert set(posted_body(send_route)) == {"raw"}
    assert result["threadId"] == "brandnewthread01"


@pytest.mark.asyncio
async def test_reply_through_dispatch_with_send_only_scope_refuses_with_an_audit_line(caplog):
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        send_route = mount_send(router)
        with caplog.at_level(logging.INFO, logger="mcp_gmail.gmail_tools.audit_log"):
            result = await _dispatch("send_email", SCOPES_SEND_ONLY, **_send_args())

    assert send_route.call_count == 0
    assert result["code"] == ToolErrorCode.SCOPE_INSUFFICIENT
    line = _audit_lines(caplog)[-1]
    assert "outcome=threading_refused" in line
    assert "reason=read_scope_missing" in line
    assert f"error_code={ToolErrorCode.SCOPE_INSUFFICIENT}" in line


@pytest.mark.asyncio
async def test_a_refusal_writes_one_audit_line_and_no_private_content(caplog):
    # The search URL holds the Message-ID, percent-encoded, so match its bare stem.
    silence_http_client_url_logging()
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        mount_lookup(router, message_metadata())
        send_route = mount_send(router)
        with caplog.at_level(logging.INFO):
            result = await _dispatch(
                "send_email", SCOPES_FULL_ACCESS, **_send_args(subject=SECRET_SUBJECT)
            )

    assert send_route.call_count == 0
    assert error_reason(result) == "subject_mismatch"
    lines = _audit_lines(caplog)
    assert len(lines) == 1
    assert "tool=send_email" in lines[0]
    assert "outcome=threading_refused" in lines[0]
    assert "reason=subject_mismatch" in lines[0]
    assert f"error_code={ToolErrorCode.THREADING_REFUSED}" in lines[0]
    assert f"thread_id={TARGET_THREAD}" in lines[0]
    everything = "\n".join(r.getMessage() for r in caplog.records)
    for private in ("Confidential", RECIPIENT, "parent-1", "secret body", "rfc822msgid"):
        assert private not in everything


@pytest.mark.parametrize(
    ("overrides", "listing", "reason"),
    [
        ({"reply_to_message_id": None}, (), "no_reply_target"),
        ({"reply_to_message_id": "two words@example.com"}, (), "invalid_message_id"),
        ({}, (), "reply_target_not_found"),
        (
            {},
            (
                message_metadata(gmail_id="gmailcopyaaaaaaa", thread_id="threadaaaaaaaaaa"),
                message_metadata(gmail_id="gmailcopybbbbbbb", thread_id="threadbbbbbbbbbb"),
            ),
            "reply_target_ambiguous",
        ),
    ],
)
@pytest.mark.asyncio
async def test_each_send_email_refusal_is_audited_with_its_reason(
    caplog, overrides, listing, reason
):
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        mount_lookup(router, *listing)
        send_route = mount_send(router)
        with caplog.at_level(logging.INFO, logger="mcp_gmail.gmail_tools.audit_log"):
            await _dispatch("send_email", SCOPES_FULL_ACCESS, **_send_args(**overrides))

    assert send_route.call_count == 0
    line = _audit_lines(caplog)[-1]
    assert "outcome=threading_refused" in line
    assert f"reason={reason}" in line


@pytest.mark.asyncio
async def test_a_failed_lookup_is_audited_as_a_refusal(caplog):
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        router.get("/users/me/messages").mock(return_value=httpx.Response(503, json={}))
        send_route = mount_send(router)
        with caplog.at_level(logging.INFO, logger="mcp_gmail.gmail_tools.audit_log"):
            await _dispatch("send_email", SCOPES_FULL_ACCESS, **_send_args())

    assert send_route.call_count == 0
    assert "reason=lookup_failed" in _audit_lines(caplog)[-1]


@pytest.mark.asyncio
async def test_a_conflicting_draft_thread_is_audited_with_the_real_thread(caplog):
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        mount_lookup(router, message_metadata())
        created = router.post("/users/me/drafts").mock(return_value=httpx.Response(200, json={}))
        with caplog.at_level(logging.INFO, logger="mcp_gmail.gmail_tools.audit_log"):
            await _dispatch(
                "create_draft",
                SCOPES_FULL_ACCESS,
                **_send_args(thread_id="threadconflict01"),
            )

    assert created.call_count == 0
    line = _audit_lines(caplog)[-1]
    assert "reason=thread_conflict" in line
    assert f"thread_id={TARGET_THREAD}" in line


@pytest.mark.asyncio
async def test_a_wrong_saved_draft_thread_is_audited_with_both_threads(caplog):
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        mount_lookup(router, message_metadata())
        router.post("/users/me/drafts").mock(
            return_value=httpx.Response(
                200,
                json={"id": "draftid000000001", "message": {"threadId": "threadwrongwrong"}},
            )
        )
        with caplog.at_level(logging.INFO, logger="mcp_gmail.gmail_tools.audit_log"):
            await _dispatch("create_draft", SCOPES_FULL_ACCESS, **_send_args())

    line = _audit_lines(caplog)[-1]
    assert "outcome=thread_mismatch" in line
    assert "actual_thread_id=threadwrongwrong" in line
    assert "draft_id=draftid000000001" in line


@pytest.mark.asyncio
async def test_an_unconfirmed_send_is_audited_as_unknown(caplog):
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        mount_lookup(router, message_metadata())
        router.post("/users/me/messages/send").mock(return_value=httpx.Response(500, json={}))
        with caplog.at_level(logging.INFO, logger="mcp_gmail.gmail_tools.audit_log"):
            result = await _dispatch("send_email", SCOPES_FULL_ACCESS, **_send_args())

    assert result["code"] == ToolErrorCode.SEND_OUTCOME_UNKNOWN
    line = _audit_lines(caplog)[-1]
    assert "outcome=send_outcome_unknown" in line
    assert "reason=send_outcome_unknown" in line


@pytest.mark.asyncio
async def test_a_search_url_never_reaches_the_log(caplog):
    """httpx logs each request URL at INFO. Its query holds the Message-ID, or a
    caller's search_emails string, and the audit contract says neither is logged."""
    logging.getLogger("httpx").setLevel(logging.NOTSET)
    silence_http_client_url_logging()
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        mount_lookup(router, message_metadata())
        mount_send(router)
        with caplog.at_level(logging.INFO):
            await _dispatch("send_email", SCOPES_FULL_ACCESS, **_send_args())

    assert "rfc822msgid" not in caplog.text
    assert "parent-1" not in caplog.text


@pytest.mark.asyncio
async def test_a_post_send_mismatch_writes_an_audit_line_with_both_threads(caplog):
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        mount_lookup(router, message_metadata())
        mount_send(router, thread_id="threadwrongwrong", sent_id="sentwrongthread1")
        with caplog.at_level(logging.INFO):
            result = await _dispatch("send_email", SCOPES_FULL_ACCESS, **_send_args())

    assert result["code"] == ToolErrorCode.THREAD_MISMATCH
    line = _audit_lines(caplog)[-1]
    assert "outcome=thread_mismatch" in line
    assert f"thread_id={TARGET_THREAD}" in line
    assert "actual_thread_id=threadwrongwrong" in line
    assert "message_id=sentwrongthread1" in line
    assert any(
        r.levelname == "ERROR" and "threadwrongwrong" in r.getMessage() for r in caplog.records
    )


@pytest.mark.asyncio
async def test_a_refused_send_draft_keeps_the_draft_id_on_its_audit_line(caplog):
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        mount_draft(router, draft_id="draftid000000001", subject="Re: Items")
        send_route = router.post("/users/me/drafts/send").mock(
            return_value=httpx.Response(200, json={"id": "s", "threadId": TARGET_THREAD})
        )
        with caplog.at_level(logging.INFO, logger="mcp_gmail.gmail_tools.audit_log"):
            result = await _dispatch("send_draft", SCOPES_FULL_ACCESS, draft_id="draftid000000001")

    assert send_route.call_count == 0
    assert error_reason(result) == "no_reply_target"
    line = _audit_lines(caplog)[-1]
    assert "draft_id=draftid000000001" in line
    assert "reason=no_reply_target" in line


@pytest.mark.asyncio
async def test_unrelated_errors_keep_their_normal_audit_outcome(caplog):
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        router.post("/users/me/messages/send").mock(return_value=httpx.Response(429, json={}))
        with caplog.at_level(logging.INFO, logger="mcp_gmail.gmail_tools.audit_log"):
            result = await _dispatch(
                "send_email",
                SCOPES_FULL_ACCESS,
                **_send_args(subject="A new conversation", reply_to_message_id=None),
            )

    assert result["code"] == ToolErrorCode.RATE_LIMITED
    line = _audit_lines(caplog)[-1]
    assert "outcome=error" in line
    assert "reason=" not in line
