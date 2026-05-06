"""Tests for the read-side label tool (list_email_labels)."""

from __future__ import annotations

import httpx
import pytest
import respx

from mcp_gmail.gmail_tools import labels_read
from mcp_gmail.gmail_tools.gmail_client import GMAIL_API_BASE, GmailClient


@pytest.mark.asyncio
async def test_list_email_labels_happy():
    async with GmailClient(access_token="t") as client:
        with respx.mock(base_url=GMAIL_API_BASE) as router:
            router.get("/users/me/labels").mock(
                return_value=httpx.Response(
                    200,
                    json={"labels": [{"id": "INBOX", "name": "INBOX"}]},
                )
            )
            r = await labels_read.list_email_labels(client=client)
            assert r["labels"][0]["id"] == "INBOX"


@pytest.mark.asyncio
async def test_list_email_labels_empty():
    async with GmailClient(access_token="t") as client:
        with respx.mock(base_url=GMAIL_API_BASE) as router:
            router.get("/users/me/labels").mock(
                return_value=httpx.Response(200, json={"labels": []})
            )
            r = await labels_read.list_email_labels(client=client)
            assert r == {"labels": []}
