"""Handler-level tests for the consume-after-build upload flow.

Exercises send_email / create_draft / update_draft with upload-handle
attachments end to end (load -> build -> consume -> POST), asserting the
preserved invariants: idempotency cache HIT consumes nothing, a consume
race after a successful build returns an error with ZERO POST, an
oversize build never burns a slot, and a legitimate send/draft consumes
the slot and makes exactly one POST.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from mcp_gmail import attachment_upload_store as store
from mcp_gmail import config as config_module
from mcp_gmail import db as db_module
from mcp_gmail.crypto import encrypt_bytes
from mcp_gmail.db import Base
from mcp_gmail.gmail_tools import send
from mcp_gmail.gmail_tools.errors import ToolErrorCode
from mcp_gmail.gmail_tools.gmail_client import GMAIL_API_BASE, GmailClient
from mcp_gmail.gmail_tools.idempotency import IdempotencyCache
from mcp_gmail.gmail_tools.tool_router import route_tool

SUB = "u"
EMAIL = "me@example.com"


@pytest.fixture(autouse=True)
def _engine():
    db_module.reset_for_tests()
    engine = db_module.init_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    yield
    db_module.reset_for_tests()


@pytest.fixture
async def client():
    c = GmailClient(access_token="t")
    yield c
    await c.aclose()


def _key() -> str:
    return config_module.load().encryption_key


def _upload_slot(payload: bytes, *, filename: str = "label.pdf") -> str:
    with db_module.session_scope() as session:
        token, _ = store.create_slot(session, auth0_sub=SUB, account_email=EMAIL)
        store.finalize_upload(
            session,
            token_hash=store.hash_token(token),
            encrypted=encrypt_bytes(payload, _key()),
            size_bytes=len(payload),
            filename=filename,
            mime_type="application/pdf",
        )
    return token


def _consumable(token: str) -> bool:
    with db_module.session_scope() as session:
        return (
            store.load_for_consume(
                session, token_hash=store.hash_token(token), auth0_sub=SUB, account_email=EMAIL
            )
            is not None
        )


def _upload_att(token: str) -> dict:
    return {"source": "upload", "upload_token": token}


# ---------------------------------------------------------------------------
# send_email
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_send_email_upload_handle_consumes_and_posts_once(client):
    token = _upload_slot(b"PDFBYTES")
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        route = router.post("/users/me/messages/send").mock(
            return_value=httpx.Response(200, json={"id": "s1", "threadId": "t1"})
        )
        r = await send.send_email(
            client=client,
            auth0_sub=SUB,
            account_email=EMAIL,
            sender=EMAIL,
            to=["you@example.com"],
            subject="hi",
            body_text="b",
            attachments=[_upload_att(token)],
            encryption_key=_key(),
        )
    assert route.call_count == 1
    assert r == {"id": "s1", "threadId": "t1"}
    assert not _consumable(token)  # consumed


@pytest.mark.asyncio
async def test_send_email_cache_hit_consumes_no_slot(client):
    cache = IdempotencyCache()
    token_a = _upload_slot(b"A")
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        route = router.post("/users/me/messages/send").mock(
            return_value=httpx.Response(200, json={"id": "s1", "threadId": "t1"})
        )
        first = await send.send_email(
            client=client,
            auth0_sub=SUB,
            account_email=EMAIL,
            sender=EMAIL,
            to=["you@example.com"],
            subject="hi",
            body_text="b",
            attachments=[_upload_att(token_a)],
            idempotency_key="k1",
            cache=cache,
            encryption_key=_key(),
        )
        # Retry with the SAME key but a fresh slot -> cache HIT, zero consume.
        token_b = _upload_slot(b"B")
        second = await send.send_email(
            client=client,
            auth0_sub=SUB,
            account_email=EMAIL,
            sender=EMAIL,
            to=["you@example.com"],
            subject="hi",
            body_text="b",
            attachments=[_upload_att(token_b)],
            idempotency_key="k1",
            cache=cache,
            encryption_key=_key(),
        )
    assert route.call_count == 1  # cache hit made no extra POST
    assert first == second
    assert not _consumable(token_a)  # first call consumed A
    assert _consumable(token_b)  # cache hit did NOT consume B


@pytest.mark.asyncio
async def test_send_email_consume_race_returns_error_zero_post(client, monkeypatch):
    token = _upload_slot(b"PDFBYTES")
    monkeypatch.setattr(store, "consume", lambda *a, **k: False)
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        route = router.post("/users/me/messages/send").mock(
            return_value=httpx.Response(200, json={"id": "s1"})
        )
        r = await send.send_email(
            client=client,
            auth0_sub=SUB,
            account_email=EMAIL,
            sender=EMAIL,
            to=["you@example.com"],
            subject="hi",
            body_text="b",
            attachments=[_upload_att(token)],
            encryption_key=_key(),
        )
    assert route.call_count == 0  # build ok but consume lost -> NO send
    assert r["code"] == ToolErrorCode.BAD_REQUEST
    monkeypatch.undo()
    assert _consumable(token)  # not spent


# ---------------------------------------------------------------------------
# create_draft / update_draft (via the router: load in router, consume in draft)
# ---------------------------------------------------------------------------


def _draft_args(token: str) -> dict:
    return {
        "account_email": EMAIL,
        "sender": EMAIL,
        "to": ["you@example.com"],
        "subject": "hi",
        "body_text": "b",
        "attachments": [_upload_att(token)],
    }


@pytest.mark.asyncio
async def test_create_draft_upload_handle_consumes_on_create(client):
    token = _upload_slot(b"PDFBYTES")
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        route = router.post("/users/me/drafts").mock(
            return_value=httpx.Response(200, json={"id": "d1"})
        )
        r = await route_tool(
            tool_name="create_draft",
            arguments=_draft_args(token),
            client=client,
            auth0_sub=SUB,
            account_email=EMAIL,
            settings=config_module.load(),
        )
    assert route.call_count == 1
    assert r["id"] == "d1"
    assert not _consumable(token)  # consumed on create


@pytest.mark.asyncio
async def test_update_draft_stale_id_does_not_burn_slot(client):
    # A valid-shaped but nonexistent draft_id is an ordinary caller error;
    # the not-found existence check runs BEFORE consume, so the one-time
    # upload handle survives and no update PUT is attempted.
    token = _upload_slot(b"PDFBYTES")
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        router.get("/users/me/drafts/DRFT_1").mock(
            return_value=httpx.Response(404, json={"error": {"code": 404}})
        )
        put_route = router.put("/users/me/drafts/DRFT_1").mock(
            return_value=httpx.Response(200, json={"id": "DRFT_1"})
        )
        r = await route_tool(
            tool_name="update_draft",
            arguments={**_draft_args(token), "draft_id": "DRFT_1"},
            client=client,
            auth0_sub=SUB,
            account_email=EMAIL,
            settings=config_module.load(),
        )
    assert r["code"] == ToolErrorCode.NOT_FOUND
    assert put_route.call_count == 0  # no update attempted
    assert _consumable(token)  # slot NOT burned


@pytest.mark.asyncio
async def test_create_draft_oversize_build_does_not_burn_slot(client):
    # ~19.6 MiB raw renders over the 25 MiB cap; build rejects before the
    # draft POST and the slot survives for a corrected retry.
    token = _upload_slot(b"\0" * 19_600_000)
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        route = router.post("/users/me/drafts").mock(
            return_value=httpx.Response(200, json={"id": "d1"})
        )
        r = await route_tool(
            tool_name="create_draft",
            arguments=_draft_args(token),
            client=client,
            auth0_sub=SUB,
            account_email=EMAIL,
            settings=config_module.load(),
        )
    assert route.call_count == 0  # oversize -> no draft POST
    assert r["code"] == ToolErrorCode.BAD_REQUEST
    assert _consumable(token)  # slot not burned
