"""Tests for the write-side filter tools (create_filter, delete_filter)."""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from mcp_gmail.gmail_tools import filters_write
from mcp_gmail.gmail_tools.errors import ToolErrorCode
from mcp_gmail.gmail_tools.gmail_client import GMAIL_API_BASE, GmailClient


@pytest.fixture
async def client():
    c = GmailClient(access_token="t")
    yield c
    await c.aclose()


# ---------------------------------------------------------------------------
# create_filter
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_filter_sends_criteria_and_action(client):
    captured: dict[str, dict] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.read().decode())
        return httpx.Response(200, json={"id": "F1"})

    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.post("/users/me/settings/filters").mock(side_effect=handler)
        r = await filters_write.create_filter(
            client=client,
            criteria={"from": "boss@x.com"},
            action={"addLabelIds": ["L1"]},
        )
    assert captured["body"] == {
        "criteria": {"from": "boss@x.com"},
        "action": {"addLabelIds": ["L1"]},
    }
    assert r["id"] == "F1"


@pytest.mark.asyncio
async def test_create_filter_rejects_non_dict_criteria(client):
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        any_route = router.route()
        any_route.mock(return_value=httpx.Response(200, json={}))
        # type: ignore on the criteria arg because we are deliberately
        # passing a wrong-typed value to verify the validation.
        r = await filters_write.create_filter(
            client=client,
            criteria="not a dict",  # type: ignore[arg-type]
            action={"addLabelIds": ["L1"]},
        )
        assert any_route.called is False
    assert r["code"] == ToolErrorCode.BAD_REQUEST


@pytest.mark.asyncio
async def test_create_filter_rejects_non_dict_action(client):
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        any_route = router.route()
        any_route.mock(return_value=httpx.Response(200, json={}))
        r = await filters_write.create_filter(
            client=client,
            criteria={"from": "x"},
            action=None,  # type: ignore[arg-type]
        )
        assert any_route.called is False
    assert r["code"] == ToolErrorCode.BAD_REQUEST


# ---------------------------------------------------------------------------
# empty-dict rejection on create_filter
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_filter_rejects_empty_criteria_dict(client):
    """Empty `criteria={}` would match every incoming message; reject."""
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        any_route = router.route()
        any_route.mock(return_value=httpx.Response(200, json={}))
        r = await filters_write.create_filter(
            client=client,
            criteria={},
            action={"addLabelIds": ["L1"]},
        )
        assert any_route.called is False
    assert r["code"] == ToolErrorCode.BAD_REQUEST
    assert "criteria" in r["message"].lower()


@pytest.mark.asyncio
async def test_create_filter_rejects_empty_action_dict(client):
    """Empty `action={}` is a no-op filter; reject."""
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        any_route = router.route()
        any_route.mock(return_value=httpx.Response(200, json={}))
        r = await filters_write.create_filter(
            client=client,
            criteria={"from": "x@example.com"},
            action={},
        )
        assert any_route.called is False
    assert r["code"] == ToolErrorCode.BAD_REQUEST
    assert "action" in r["message"].lower()


@pytest.mark.asyncio
async def test_create_filter_rejects_both_empty_dicts(client):
    """Both empty: rejected (criteria check fires first per current ordering)."""
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        any_route = router.route()
        any_route.mock(return_value=httpx.Response(200, json={}))
        r = await filters_write.create_filter(
            client=client,
            criteria={},
            action={},
        )
        assert any_route.called is False
    assert r["code"] == ToolErrorCode.BAD_REQUEST


# ---------------------------------------------------------------------------
# delete_filter
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_delete_filter_calls_DELETE(client):
    captured: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["method"] = request.method
        return httpx.Response(204)

    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.delete("/users/me/settings/filters/F1").mock(side_effect=handler)
        r = await filters_write.delete_filter(client=client, filter_id="F1")
    assert captured["method"] == "DELETE"
    assert r == {}


@pytest.mark.asyncio
async def test_delete_filter_404(client):
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.delete("/users/me/settings/filters/missing").mock(
            return_value=httpx.Response(404, json={})
        )
        r = await filters_write.delete_filter(client=client, filter_id="missing")
    assert r["code"] == ToolErrorCode.NOT_FOUND
