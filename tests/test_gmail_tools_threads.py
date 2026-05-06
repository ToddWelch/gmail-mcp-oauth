"""Tests for thread tools."""

from __future__ import annotations

import httpx
import pytest
import respx

from mcp_gmail.gmail_tools import threads
from mcp_gmail.gmail_tools.errors import ToolErrorCode
from mcp_gmail.gmail_tools.gmail_client import GMAIL_API_BASE, GmailClient


@pytest.fixture
async def client():
    c = GmailClient(access_token="t")
    yield c
    await c.aclose()


@pytest.mark.asyncio
async def test_get_thread_happy(client):
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get("/users/me/threads/t1").mock(
            return_value=httpx.Response(200, json={"id": "t1", "messages": []})
        )
        r = await threads.get_thread(client=client, thread_id="t1")
        assert r["id"] == "t1"


@pytest.mark.asyncio
async def test_get_thread_404(client):
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get("/users/me/threads/missing").mock(return_value=httpx.Response(404, json={}))
        r = await threads.get_thread(client=client, thread_id="missing")
        assert r["code"] == ToolErrorCode.NOT_FOUND


@pytest.mark.asyncio
async def test_list_inbox_threads_passes_inbox_label(client):
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["params"] = list(request.url.params.multi_items())
        return httpx.Response(200, json={"threads": []})

    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get("/users/me/threads").mock(side_effect=handler)
        await threads.list_inbox_threads(client=client)
    keys = [k for k, _ in captured["params"]]
    values = [v for k, v in captured["params"] if k == "labelIds"]
    assert "labelIds" in keys
    assert values == ["INBOX"]


@pytest.mark.asyncio
async def test_get_inbox_with_threads_expands_each(client):
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get("/users/me/threads").mock(
            return_value=httpx.Response(
                200,
                json={"threads": [{"id": "t1"}, {"id": "t2"}]},
            )
        )
        router.get("/users/me/threads/t1").mock(
            return_value=httpx.Response(
                200,
                json={
                    "id": "t1",
                    "messages": [
                        {
                            "id": "m1",
                            "snippet": "snip-t1",
                            "payload": {
                                "headers": [
                                    {"name": "Subject", "value": "Hello t1"},
                                    {"name": "From", "value": "alice@x.com"},
                                ]
                            },
                        }
                    ],
                },
            )
        )
        router.get("/users/me/threads/t2").mock(
            return_value=httpx.Response(
                200,
                json={
                    "id": "t2",
                    "messages": [
                        {
                            "id": "m2",
                            "snippet": "snip-t2",
                            "payload": {"headers": []},
                        }
                    ],
                },
            )
        )
        r = await threads.get_inbox_with_threads(client=client)
    assert len(r["threads"]) == 2
    t1 = r["threads"][0]
    assert t1["thread_id"] == "t1"
    assert t1["subject"] == "Hello t1"
    assert t1["from_addr"] == "alice@x.com"
    assert t1["snippet"] == "snip-t1"


@pytest.mark.asyncio
async def test_get_inbox_with_threads_handles_per_thread_404(client):
    """A failed individual thread fetch should not abort the whole listing."""
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get("/users/me/threads").mock(
            return_value=httpx.Response(200, json={"threads": [{"id": "t1"}]})
        )
        router.get("/users/me/threads/t1").mock(return_value=httpx.Response(404, json={}))
        r = await threads.get_inbox_with_threads(client=client)
    assert r["threads"][0]["error_status"] == 404


@pytest.mark.asyncio
async def test_modify_thread_passes_label_lists(client):
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = request.read().decode()
        return httpx.Response(200, json={"id": "t1"})

    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.post("/users/me/threads/t1/modify").mock(side_effect=handler)
        await threads.modify_thread(
            client=client,
            thread_id="t1",
            add_label_ids=["INBOX"],
            remove_label_ids=["UNREAD"],
        )
    assert "addLabelIds" in captured["body"]
    assert "removeLabelIds" in captured["body"]


@pytest.mark.asyncio
async def test_modify_thread_404(client):
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.post("/users/me/threads/missing/modify").mock(
            return_value=httpx.Response(404, json={})
        )
        r = await threads.modify_thread(client=client, thread_id="missing")
        assert r["code"] == ToolErrorCode.NOT_FOUND


@pytest.mark.asyncio
async def test_get_inbox_with_threads_passes_max_results(client):
    captured = {}

    def list_handler(request: httpx.Request) -> httpx.Response:
        captured["params"] = dict(request.url.params)
        return httpx.Response(200, json={"threads": []})

    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get("/users/me/threads").mock(side_effect=list_handler)
        await threads.get_inbox_with_threads(client=client, max_results=10)
    assert captured["params"]["maxResults"] == "10"
