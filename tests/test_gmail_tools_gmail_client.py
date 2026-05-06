"""Tests for gmail_tools.gmail_client.GmailClient.

Uses respx to mock httpx. Asserts:
- Read endpoints round-trip JSON dicts.
- Errors map to GmailApiError with status preserved.
- Retry-After is parsed on 429.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from mcp_gmail.gmail_tools.gmail_client import (
    GMAIL_API_BASE,
    GmailApiError,
    GmailClient,
)


@pytest.fixture
async def client():
    c = GmailClient(access_token="fake-access-token")
    yield c
    await c.aclose()


@pytest.mark.asyncio
async def test_get_message_happy_path(client):
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get("/users/me/messages/abc").mock(
            return_value=httpx.Response(200, json={"id": "abc", "snippet": "hi"})
        )
        result = await client.get_message(message_id="abc")
        assert result == {"id": "abc", "snippet": "hi"}


@pytest.mark.asyncio
async def test_get_message_passes_format_param(client):
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["params"] = dict(request.url.params)
        return httpx.Response(200, json={"id": "abc"})

    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get("/users/me/messages/abc").mock(side_effect=handler)
        await client.get_message(message_id="abc", format="raw")
    assert captured["params"]["format"] == "raw"


@pytest.mark.asyncio
async def test_list_messages_passes_query_and_label_ids(client):
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["params"] = list(request.url.params.multi_items())
        return httpx.Response(200, json={"messages": []})

    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get("/users/me/messages").mock(side_effect=handler)
        await client.list_messages(q="from:foo", label_ids=["INBOX", "STARRED"])
    keys = [k for k, _ in captured["params"]]
    assert "q" in keys
    # httpx repeats the labelIds key for list params.
    assert keys.count("labelIds") == 2


@pytest.mark.asyncio
async def test_get_thread_happy(client):
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get("/users/me/threads/t1").mock(
            return_value=httpx.Response(200, json={"id": "t1", "messages": []})
        )
        r = await client.get_thread(thread_id="t1")
        assert r["id"] == "t1"


@pytest.mark.asyncio
async def test_list_labels_happy(client):
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get("/users/me/labels").mock(
            return_value=httpx.Response(200, json={"labels": [{"id": "INBOX"}]})
        )
        r = await client.list_labels()
        assert r["labels"][0]["id"] == "INBOX"


@pytest.mark.asyncio
async def test_list_filters_happy(client):
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get("/users/me/settings/filters").mock(
            return_value=httpx.Response(200, json={"filter": []})
        )
        r = await client.list_filters()
        assert r == {"filter": []}


@pytest.mark.asyncio
async def test_get_filter_happy(client):
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get("/users/me/settings/filters/F1").mock(
            return_value=httpx.Response(200, json={"id": "F1"})
        )
        r = await client.get_filter(filter_id="F1")
        assert r == {"id": "F1"}


@pytest.mark.asyncio
async def test_get_attachment_happy(client):
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get("/users/me/messages/M1/attachments/A1").mock(
            return_value=httpx.Response(200, json={"size": 99, "data": "abc"})
        )
        r = await client.get_attachment(message_id="M1", attachment_id="A1")
        assert r == {"size": 99, "data": "abc"}


@pytest.mark.asyncio
async def test_404_raises_gmail_api_error(client):
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get("/users/me/messages/missing").mock(
            return_value=httpx.Response(404, json={"error": "not found"})
        )
        with pytest.raises(GmailApiError) as exc_info:
            await client.get_message(message_id="missing")
        assert exc_info.value.status == 404


@pytest.mark.asyncio
async def test_429_carries_retry_after_header(client):
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get("/users/me/messages").mock(
            return_value=httpx.Response(
                429,
                json={"error": "too many requests"},
                headers={"Retry-After": "30"},
            )
        )
        with pytest.raises(GmailApiError) as exc_info:
            await client.list_messages()
        assert exc_info.value.status == 429
        assert exc_info.value.retry_after_seconds == 30


@pytest.mark.asyncio
async def test_500_status_preserved(client):
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get("/users/me/labels").mock(return_value=httpx.Response(500, text="boom"))
        with pytest.raises(GmailApiError) as exc_info:
            await client.list_labels()
        assert exc_info.value.status == 500


@pytest.mark.asyncio
async def test_network_error_raises_status_zero():
    """Connection failure -> GmailApiError(status=0)."""
    transport = httpx.MockTransport(lambda req: (_ for _ in ()).throw(httpx.ConnectError("nope")))
    async with httpx.AsyncClient(transport=transport) as inner:
        client = GmailClient(access_token="t", client=inner)
        with pytest.raises(GmailApiError) as exc_info:
            await client.list_labels()
        assert exc_info.value.status == 0


@pytest.mark.asyncio
async def test_init_rejects_empty_token():
    with pytest.raises(ValueError):
        GmailClient(access_token="")


@pytest.mark.asyncio
async def test_authorization_header_sends_bearer(client):
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["auth"] = request.headers.get("Authorization")
        return httpx.Response(200, json={})

    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get("/users/me/labels").mock(side_effect=handler)
        await client.list_labels()
    assert captured["auth"] == "Bearer fake-access-token"


@pytest.mark.asyncio
async def test_modify_thread_via_write_mixin(client):
    """The write mixin is callable through the GmailClient instance."""
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.post("/users/me/threads/T1/modify").mock(
            return_value=httpx.Response(200, json={"id": "T1"})
        )
        r = await client.modify_thread(
            thread_id="T1",
            add_label_ids=["INBOX"],
        )
        assert r == {"id": "T1"}
