"""Tests for filter_templates.build_filter_body_from_template and the
create_filter_from_template tool.

Covers blocker B2 (query-injection / label-bombing mitigation):
- Empty `query` rejected.
- Whitespace-only `query` rejected.
- Single-character `query` rejected.
- Caller-supplied query of length >= 2 accepted.
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from mcp_gmail.gmail_tools import filters_write
from mcp_gmail.gmail_tools.errors import ToolErrorCode
from mcp_gmail.gmail_tools.filter_templates import (
    TEMPLATE_NAMES,
    build_filter_body_from_template,
)
from mcp_gmail.gmail_tools.gmail_client import GMAIL_API_BASE, GmailClient


# ---------------------------------------------------------------------------
# build_filter_body_from_template (pure function tests)
# ---------------------------------------------------------------------------


def test_template_names_are_three_documented_templates():
    assert set(TEMPLATE_NAMES) == {
        "auto_archive_sender",
        "auto_label_from_keyword",
        "auto_label_sender",
    }


def test_unknown_template_returns_bad_request():
    r = build_filter_body_from_template(template="not_a_template")
    assert r["code"] == ToolErrorCode.BAD_REQUEST


def test_auto_archive_sender_builds_archive_body():
    body = build_filter_body_from_template(
        template="auto_archive_sender",
        sender_email="boss@example.com",
    )
    assert body == {
        "criteria": {"from": "boss@example.com"},
        "action": {"removeLabelIds": ["INBOX"]},
    }


def test_auto_archive_sender_strips_whitespace():
    body = build_filter_body_from_template(
        template="auto_archive_sender",
        sender_email="  boss@example.com  ",
    )
    assert body["criteria"]["from"] == "boss@example.com"


def test_auto_archive_sender_rejects_empty_email():
    r = build_filter_body_from_template(template="auto_archive_sender", sender_email="")
    assert r["code"] == ToolErrorCode.BAD_REQUEST


def test_auto_archive_sender_rejects_whitespace_only_email():
    r = build_filter_body_from_template(template="auto_archive_sender", sender_email="   ")
    assert r["code"] == ToolErrorCode.BAD_REQUEST


def test_auto_label_sender_builds_label_body():
    body = build_filter_body_from_template(
        template="auto_label_sender",
        sender_email="vendor@example.com",
        label_id="Label_42",
    )
    assert body == {
        "criteria": {"from": "vendor@example.com"},
        "action": {"addLabelIds": ["Label_42"]},
    }


def test_auto_label_sender_requires_label_id():
    r = build_filter_body_from_template(
        template="auto_label_sender",
        sender_email="vendor@example.com",
    )
    assert r["code"] == ToolErrorCode.BAD_REQUEST


# ---------------------------------------------------------------------------
# B2: query injection / label bombing rejections
# ---------------------------------------------------------------------------


def test_create_filter_from_template_rejects_empty_query():
    """B2: empty query string rejected before any Gmail call."""
    r = build_filter_body_from_template(
        template="auto_label_from_keyword",
        query="",
        label_id="Label_1",
    )
    assert r["code"] == ToolErrorCode.BAD_REQUEST


def test_create_filter_from_template_rejects_whitespace_only_query():
    """B2: query that is only whitespace rejected (no labelling of every message)."""
    r = build_filter_body_from_template(
        template="auto_label_from_keyword",
        query="   ",
        label_id="Label_1",
    )
    assert r["code"] == ToolErrorCode.BAD_REQUEST


def test_create_filter_from_template_rejects_one_char_query():
    """B2: single-character query is overly broad; rejected."""
    r = build_filter_body_from_template(
        template="auto_label_from_keyword",
        query="x",
        label_id="Label_1",
    )
    assert r["code"] == ToolErrorCode.BAD_REQUEST


def test_create_filter_from_template_rejects_one_char_query_with_padding():
    """A query of `' x '` has 1 non-whitespace char after strip; rejected."""
    r = build_filter_body_from_template(
        template="auto_label_from_keyword",
        query="  x  ",
        label_id="Label_1",
    )
    assert r["code"] == ToolErrorCode.BAD_REQUEST


def test_create_filter_from_template_accepts_two_char_query():
    """Two-char query is allowed (the threshold)."""
    body = build_filter_body_from_template(
        template="auto_label_from_keyword",
        query="ab",
        label_id="Label_1",
    )
    assert body == {
        "criteria": {"query": "ab"},
        "action": {"addLabelIds": ["Label_1"]},
    }


def test_create_filter_from_template_passes_realistic_query():
    body = build_filter_body_from_template(
        template="auto_label_from_keyword",
        query="from:invoices@example.com",
        label_id="Label_invoices",
    )
    assert body["criteria"]["query"] == "from:invoices@example.com"
    assert body["action"]["addLabelIds"] == ["Label_invoices"]


def test_auto_label_from_keyword_requires_label_id():
    r = build_filter_body_from_template(
        template="auto_label_from_keyword",
        query="from:x@y.com",
    )
    assert r["code"] == ToolErrorCode.BAD_REQUEST


# ---------------------------------------------------------------------------
# create_filter_from_template tool (round-trip via Gmail mock)
# ---------------------------------------------------------------------------


@pytest.fixture
async def client():
    c = GmailClient(access_token="t")
    yield c
    await c.aclose()


@pytest.mark.asyncio
async def test_create_filter_from_template_happy_path(client):
    """auto_archive_sender posts the right body and returns Gmail's response."""
    captured: dict[str, dict] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.read().decode())
        return httpx.Response(200, json={"id": "F1"})

    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.post("/users/me/settings/filters").mock(side_effect=handler)
        r = await filters_write.create_filter_from_template(
            client=client,
            template="auto_archive_sender",
            sender_email="boss@example.com",
        )
    assert r == {"id": "F1"}
    assert captured["body"] == {
        "criteria": {"from": "boss@example.com"},
        "action": {"removeLabelIds": ["INBOX"]},
    }


@pytest.mark.asyncio
async def test_create_filter_from_template_rejects_empty_query_no_gmail_call(client):
    """B2 round-trip: empty query never reaches Gmail."""
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        any_route = router.route()
        any_route.mock(return_value=httpx.Response(200, json={}))
        r = await filters_write.create_filter_from_template(
            client=client,
            template="auto_label_from_keyword",
            query="",
            label_id="Label_1",
        )
        assert any_route.called is False
    assert r["code"] == ToolErrorCode.BAD_REQUEST


@pytest.mark.asyncio
async def test_create_filter_from_template_unknown_template_returns_bad_request(client):
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        any_route = router.route()
        any_route.mock(return_value=httpx.Response(200, json={}))
        r = await filters_write.create_filter_from_template(
            client=client,
            template="bogus_template",
        )
        assert any_route.called is False
    assert r["code"] == ToolErrorCode.BAD_REQUEST
