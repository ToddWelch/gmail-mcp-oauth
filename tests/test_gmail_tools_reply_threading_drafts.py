"""create_draft and update_draft: same guarantee as send_email, before any send.

send_draft is in test_gmail_tools_reply_threading_send_draft.py.
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from mcp_gmail.gmail_tools import drafts
from mcp_gmail.gmail_tools.errors import ToolErrorCode
from mcp_gmail.gmail_tools.gmail_client import GMAIL_API_BASE, GmailClient

from ._threading_fixtures import (
    DRAFT_MESSAGE_ID,
    SCOPES_COMPOSE_ONLY,
    SCOPES_FULL_ACCESS,
    TARGET_RFC_ID,
    TARGET_SUBJECT,
    TARGET_THREAD,
    decode_raw,
    error_reason,
    message_metadata,
    mount_draft,
    mount_fresh_draft,
    mount_lookup,
)


@pytest.fixture
async def client():
    c = GmailClient(access_token="t")
    yield c
    await c.aclose()


def _saved(thread_id: str = TARGET_THREAD, *, message_id: str = "draftmsg") -> httpx.Response:
    return httpx.Response(
        200, json={"id": "d1", "message": {"id": message_id, "threadId": thread_id}}
    )


# Gmail gives a new-conversation draft a threadId equal to its message id (live 2026-11-06).
_SAVED_NEW_CONVERSATION = {"thread_id": "freshdraftthread", "message_id": "freshdraftthread"}


def _create(client, **overrides):
    args = {
        "client": client,
        "sender": "me@example.com",
        "to": ["you@example.com"],
        "subject": f"Re: {TARGET_SUBJECT}",
        "body_text": "thanks",
        "reply_to_message_id": TARGET_RFC_ID,
        "granted_scope": SCOPES_FULL_ACCESS,
    }
    args.update(overrides)
    return drafts.create_draft(**args)


def _update(client, **overrides):
    args = {
        "client": client,
        "draft_id": "d1",
        "sender": "me@example.com",
        "to": ["you@example.com"],
        "subject": f"Re: {TARGET_SUBJECT}",
        "body_text": "thanks",
        "reply_to_message_id": TARGET_RFC_ID,
        "granted_scope": SCOPES_FULL_ACCESS,
    }
    args.update(overrides)
    return drafts.update_draft(**args)


@pytest.mark.asyncio
async def test_create_draft_resolves_the_thread_when_only_the_message_id_is_given(client):
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        mount_lookup(router, message_metadata())
        route = router.post("/users/me/drafts").mock(return_value=_saved())
        result = await _create(client)

    body = json.loads(route.calls[0].request.content)
    assert set(body["message"]) == {"raw", "threadId"}
    assert body["message"]["threadId"] == TARGET_THREAD
    assert decode_raw(body["message"])["In-Reply-To"] == TARGET_RFC_ID
    assert result["id"] == "d1"


@pytest.mark.asyncio
async def test_update_draft_resolves_the_thread_when_only_the_message_id_is_given(client):
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        mount_lookup(router, message_metadata())
        route = router.put("/users/me/drafts/d1").mock(return_value=_saved())
        result = await _update(client)

    body = json.loads(route.calls[0].request.content)
    assert body["message"]["threadId"] == TARGET_THREAD
    assert result["id"] == "d1"


@pytest.mark.asyncio
@pytest.mark.parametrize("form", ["parent-1@mail.example.com", "  <parent-1@mail.example.com>  "])
async def test_every_accepted_id_form_emits_a_clean_header_on_a_draft(client, form):
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        mount_lookup(router, message_metadata())
        created = router.post("/users/me/drafts").mock(return_value=_saved())
        updated = router.put("/users/me/drafts/d1").mock(return_value=_saved())
        await _create(client, reply_to_message_id=form)
        await _update(client, reply_to_message_id=form)

    for route in (created, updated):
        message = json.loads(route.calls[0].request.content)["message"]
        assert decode_raw(message)["In-Reply-To"] == TARGET_RFC_ID


@pytest.mark.asyncio
async def test_create_draft_accepts_a_thread_id_that_agrees(client):
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        mount_lookup(router, message_metadata())
        route = router.post("/users/me/drafts").mock(return_value=_saved())
        result = await _create(client, thread_id=TARGET_THREAD)

    assert route.call_count == 1
    assert result["id"] == "d1"


@pytest.mark.asyncio
async def test_create_draft_refuses_a_conflicting_thread_id(client):
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        mount_lookup(router, message_metadata())
        route = router.post("/users/me/drafts").mock(return_value=_saved())
        result = await _create(client, thread_id="threadconflict01")

    assert route.call_count == 0
    assert result["code"] == ToolErrorCode.THREADING_REFUSED
    assert error_reason(result) == "thread_conflict"
    data = result["data"]["error_data"]
    assert data["thread_id"] == TARGET_THREAD
    assert data["requested_thread_id"] == "threadconflict01"


@pytest.mark.asyncio
async def test_update_draft_refuses_a_conflicting_thread_id(client):
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        mount_lookup(router, message_metadata())
        route = router.put("/users/me/drafts/d1").mock(return_value=_saved())
        result = await _update(client, thread_id="threadconflict01")

    assert route.call_count == 0
    assert error_reason(result) == "thread_conflict"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"subject": "Re: Items", "reply_to_message_id": None}, "no_reply_target"),
        (
            {"subject": "Re: Items", "reply_to_message_id": None, "thread_id": TARGET_THREAD},
            "no_reply_target",
        ),
        ({"subject": "Re: Different"}, "subject_mismatch"),
    ],
)
async def test_create_and_update_apply_the_same_refusals(client, overrides, reason):
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        mount_lookup(router, message_metadata())
        created = router.post("/users/me/drafts").mock(return_value=_saved())
        updated = router.put("/users/me/drafts/d1").mock(return_value=_saved())
        create_result = await _create(client, **overrides)
        update_result = await _update(client, **overrides)

    assert created.call_count == 0
    assert updated.call_count == 0
    assert error_reason(create_result) == reason
    assert error_reason(update_result) == reason


@pytest.mark.asyncio
async def test_a_reply_draft_with_compose_only_scope_refuses_loudly(client):
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        search = mount_lookup(router, message_metadata())
        created = router.post("/users/me/drafts").mock(return_value=_saved())
        result = await _create(client, granted_scope=SCOPES_COMPOSE_ONLY)

    assert created.call_count == 0
    assert search.call_count == 0
    assert result["code"] == ToolErrorCode.SCOPE_INSUFFICIENT


@pytest.mark.asyncio
async def test_a_new_draft_needs_no_read_access_and_no_thread(client):
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        search = mount_lookup(router)
        route = router.post("/users/me/drafts").mock(return_value=_saved(**_SAVED_NEW_CONVERSATION))
        result = await _create(
            client,
            subject="A new conversation",
            reply_to_message_id=None,
            granted_scope=SCOPES_COMPOSE_ONLY,
        )

    assert search.call_count == 0
    assert "threadId" not in json.loads(route.calls[0].request.content)["message"]
    assert result["id"] == "d1"


@pytest.mark.asyncio
async def test_create_draft_reports_a_wrong_saved_thread_as_an_error(client):
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        mount_lookup(router, message_metadata())
        router.post("/users/me/drafts").mock(return_value=_saved("threadwrongwrong"))
        result = await _create(client)

    assert result["code"] == ToolErrorCode.THREAD_MISMATCH
    data = result["data"]["error_data"]
    assert data["expected_thread_id"] == TARGET_THREAD
    assert data["actual_thread_id"] == "threadwrongwrong"
    assert data["draft_id"] == "d1"
    assert "Do not send it" in result["message"]


@pytest.mark.asyncio
async def test_update_draft_reports_a_wrong_saved_thread_as_an_error(client):
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        mount_lookup(router, message_metadata())
        router.put("/users/me/drafts/d1").mock(return_value=_saved("threadwrongwrong"))
        result = await _update(client)

    assert result["code"] == ToolErrorCode.THREAD_MISMATCH


@pytest.mark.asyncio
async def test_thread_id_alone_still_joins_and_is_verified(client):
    """Live 2026-11-06: threadId with a matching subject and no headers joined."""
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        search = mount_lookup(router)
        route = router.post("/users/me/drafts").mock(return_value=_saved())
        result = await _create(
            client,
            subject=TARGET_SUBJECT,
            reply_to_message_id=None,
            thread_id=TARGET_THREAD,
            granted_scope=SCOPES_COMPOSE_ONLY,
        )

    assert search.call_count == 0
    assert json.loads(route.calls[0].request.content)["message"]["threadId"] == TARGET_THREAD
    assert result["id"] == "d1"


@pytest.mark.asyncio
async def test_a_refused_draft_burns_no_upload_slot(client, monkeypatch):
    consumed: list = []
    monkeypatch.setattr(drafts, "consume_slots", lambda **kw: consumed.append(kw))
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        mount_lookup(router)
        await _create(client, consume_token_hashes=["hash"])
        await _update(client, consume_token_hashes=["hash"])

    assert consumed == []


# ---------------------------------------------------------------------------
# update_draft must not silently pull a reply draft out of its conversation.
# Live 2026-11-06: a PUT with no threadId gives the draft a brand-new thread.
# ---------------------------------------------------------------------------


def _plain_update(client, **overrides):
    """Today's arguments, no reply target, no thread, a subject with no Re:."""
    return _update(client, subject=TARGET_SUBJECT, reply_to_message_id=None, **overrides)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "stored",
    [
        # The incident shape: reply headers, but its own brand-new thread, so the id
        # comparison alone would not catch it. Each signal has to work by itself.
        {"thread_id": DRAFT_MESSAGE_ID, "in_reply_to": TARGET_RFC_ID},
        {"thread_id": DRAFT_MESSAGE_ID, "references": TARGET_RFC_ID},
        {"thread_id": TARGET_THREAD},  # joined by thread_id alone: no headers
    ],
)
async def test_updating_a_reply_draft_without_a_target_is_refused(client, stored):
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        mount_draft(router, subject=TARGET_SUBJECT, **stored)
        put_route = router.put("/users/me/drafts/d1").mock(return_value=_saved("brandnewthread01"))
        result = await _plain_update(client)

    assert put_route.call_count == 0
    assert result["code"] == ToolErrorCode.THREADING_REFUSED
    assert error_reason(result) == "no_reply_target"
    assert result["data"]["error_data"]["thread_id"] == stored["thread_id"]


@pytest.mark.asyncio
async def test_updating_a_reply_draft_with_its_target_keeps_the_thread(client):
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        draft_read = mount_draft(router, in_reply_to=TARGET_RFC_ID)
        mount_lookup(router, message_metadata())
        put_route = router.put("/users/me/drafts/d1").mock(return_value=_saved())
        await _update(client)

    assert draft_read.call_count == 0, "the target is restated, so no draft read is needed"
    assert json.loads(put_route.calls[0].request.content)["message"]["threadId"] == TARGET_THREAD


@pytest.mark.asyncio
async def test_updating_a_reply_draft_with_thread_id_alone_keeps_the_thread(client):
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        put_route = router.put("/users/me/drafts/d1").mock(return_value=_saved())
        result = await _plain_update(client, thread_id=TARGET_THREAD)

    assert json.loads(put_route.calls[0].request.content)["message"]["threadId"] == TARGET_THREAD
    assert result["id"] == "d1"


@pytest.mark.asyncio
async def test_updating_a_new_conversation_draft_stays_allowed_on_compose_only(client):
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        mount_fresh_draft(router)
        put_route = router.put("/users/me/drafts/d1").mock(return_value=_saved("brandnewthread01"))
        result = await _plain_update(client, granted_scope=SCOPES_COMPOSE_ONLY)

    assert put_route.call_count == 1
    assert "threadId" not in json.loads(put_route.calls[0].request.content)["message"]
    assert result["id"] == "d1"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("response", "reason"),
    [
        (httpx.Response(503, json={}), "lookup_failed"),
        (httpx.Response(200, json={"id": "d1"}), "lookup_failed"),
    ],
)
async def test_an_unreadable_draft_refuses_the_update(client, response, reason):
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        router.get("/users/me/drafts/d1").mock(return_value=response)
        put_route = router.put("/users/me/drafts/d1").mock(return_value=_saved())
        result = await _plain_update(client)

    assert put_route.call_count == 0
    assert error_reason(result) == reason


@pytest.mark.asyncio
async def test_updating_a_missing_draft_is_not_found(client):
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        router.get("/users/me/drafts/d1").mock(return_value=httpx.Response(404, json={}))
        put_route = router.put("/users/me/drafts/d1").mock(return_value=_saved())
        result = await _plain_update(client)

    assert put_route.call_count == 0
    assert result["code"] == ToolErrorCode.NOT_FOUND
