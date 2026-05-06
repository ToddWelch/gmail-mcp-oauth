"""Tests for the read-side message tools (read_email, search_emails,
download_attachment, download_email).
"""

from __future__ import annotations

import httpx
import pytest
import respx

from mcp_gmail.gmail_tools import messages
from mcp_gmail.gmail_tools.errors import ToolErrorCode
from mcp_gmail.gmail_tools.gmail_client import GMAIL_API_BASE, GmailClient


@pytest.fixture
async def client():
    c = GmailClient(access_token="t")
    yield c
    await c.aclose()


@pytest.mark.asyncio
async def test_read_email_happy(client):
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get("/users/me/messages/m1").mock(
            return_value=httpx.Response(200, json={"id": "m1"})
        )
        r = await messages.read_email(client=client, message_id="m1")
        assert r == {"id": "m1"}


@pytest.mark.asyncio
async def test_read_email_404_returns_not_found(client):
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get("/users/me/messages/missing").mock(return_value=httpx.Response(404, json={}))
        r = await messages.read_email(client=client, message_id="missing")
        assert r["code"] == ToolErrorCode.NOT_FOUND


@pytest.mark.asyncio
async def test_read_email_invalid_format_rejected(client):
    r = await messages.read_email(client=client, message_id="m1", format="bogus")
    assert r["code"] == ToolErrorCode.BAD_REQUEST


@pytest.mark.asyncio
async def test_search_emails_passes_query(client):
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["params"] = dict(request.url.params)
        return httpx.Response(200, json={"messages": []})

    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get("/users/me/messages").mock(side_effect=handler)
        await messages.search_emails(client=client, q="from:foo")
    assert captured["params"]["q"] == "from:foo"


@pytest.mark.asyncio
async def test_search_emails_no_args(client):
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get("/users/me/messages").mock(
            return_value=httpx.Response(200, json={"messages": [{"id": "m1"}]})
        )
        r = await messages.search_emails(client=client)
        assert r["messages"][0]["id"] == "m1"


@pytest.mark.asyncio
async def test_download_attachment_happy(client):
    valid_id = "ABC1234567890123"  # 16 chars
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get(f"/users/me/messages/m1/attachments/{valid_id}").mock(
            return_value=httpx.Response(200, json={"size": 5, "data": "aGVsbG8"})
        )
        r = await messages.download_attachment(
            client=client, message_id="m1", attachment_id=valid_id
        )
        assert r["size"] == 5


@pytest.mark.asyncio
async def test_download_attachment_rejects_malformed_id_m5(client):
    """Gmail-ID validation: malformed attachment_id rejected with bad_request, no Gmail call."""
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        # Mock everything; assert nothing is called.
        any_route = router.route()
        any_route.mock(return_value=httpx.Response(200, json={}))
        r = await messages.download_attachment(client=client, message_id="m1", attachment_id="bad")
        assert any_route.called is False
    assert r["code"] == ToolErrorCode.BAD_REQUEST


@pytest.mark.asyncio
async def test_download_attachment_404(client):
    valid_id = "ABC1234567890123"
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get(f"/users/me/messages/m1/attachments/{valid_id}").mock(
            return_value=httpx.Response(404, json={})
        )
        r = await messages.download_attachment(
            client=client, message_id="m1", attachment_id=valid_id
        )
        assert r["code"] == ToolErrorCode.NOT_FOUND


@pytest.mark.asyncio
async def test_download_email_returns_raw_format(client):
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        captured = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["params"] = dict(request.url.params)
            return httpx.Response(200, json={"id": "m1", "raw": "ZW5jb2RlZA"})

        router.get("/users/me/messages/m1").mock(side_effect=handler)
        r = await messages.download_email(client=client, message_id="m1")
    assert captured["params"]["format"] == "raw"
    assert r["raw"] == "ZW5jb2RlZA"


@pytest.mark.asyncio
async def test_download_email_404(client):
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get("/users/me/messages/missing").mock(return_value=httpx.Response(404, json={}))
        r = await messages.download_email(client=client, message_id="missing")
        assert r["code"] == ToolErrorCode.NOT_FOUND
