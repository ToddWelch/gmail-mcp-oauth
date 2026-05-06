"""Tests for the read-side filter tools (list_filters, get_filter)."""

from __future__ import annotations

import httpx
import pytest
import respx

from mcp_gmail.gmail_tools import filters_read
from mcp_gmail.gmail_tools.errors import ToolErrorCode
from mcp_gmail.gmail_tools.gmail_client import GMAIL_API_BASE, GmailClient


@pytest.mark.asyncio
async def test_list_filters_happy():
    async with GmailClient(access_token="t") as client:
        with respx.mock(base_url=GMAIL_API_BASE) as router:
            router.get("/users/me/settings/filters").mock(
                return_value=httpx.Response(200, json={"filter": []})
            )
            r = await filters_read.list_filters(client=client)
            assert r == {"filter": []}


@pytest.mark.asyncio
async def test_get_filter_happy():
    async with GmailClient(access_token="t") as client:
        with respx.mock(base_url=GMAIL_API_BASE) as router:
            router.get("/users/me/settings/filters/F1").mock(
                return_value=httpx.Response(200, json={"id": "F1"})
            )
            r = await filters_read.get_filter(client=client, filter_id="F1")
            assert r["id"] == "F1"


@pytest.mark.asyncio
async def test_get_filter_404_returns_not_found():
    async with GmailClient(access_token="t") as client:
        with respx.mock(base_url=GMAIL_API_BASE) as router:
            router.get("/users/me/settings/filters/missing").mock(
                return_value=httpx.Response(404, json={})
            )
            r = await filters_read.get_filter(client=client, filter_id="missing")
            assert r["code"] == ToolErrorCode.NOT_FOUND
