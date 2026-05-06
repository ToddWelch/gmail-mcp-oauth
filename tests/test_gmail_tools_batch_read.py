"""Tests for the batch_read_emails tool.

Coverage matrix:
- happy path: ordered results, format defaults to metadata
- format=metadata applies default metadata_headers
- format=metadata with caller-supplied headers passes them verbatim
- format=minimal: passes format=minimal; no metadataHeaders sent
- partial-success: 404 on one id; others succeed
- partial-success carries Retry-After
- handler-entry oversize / empty rejection (defense-in-depth past schema)
- bad format value at handler entry rejected
- adversarial id at schema layer (probes); enum=metadata|minimal only
"""

from __future__ import annotations

import re

import httpx
import pytest
import respx

from mcp_gmail.gmail_tools import TOOL_DEFINITIONS, messages_extras
from mcp_gmail.gmail_tools.errors import ToolErrorCode
from mcp_gmail.gmail_tools.gmail_client import GMAIL_API_BASE, GmailClient


@pytest.fixture
async def client():
    c = GmailClient(access_token="t")
    yield c
    await c.aclose()


# ---------------------------------------------------------------------------
# Happy paths
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_batch_read_returns_ordered_messages(client):
    """5 ids fan out into 5 GETs, ordered by input."""
    ids = ["m1", "m2", "m3", "m4", "m5"]

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        mid = path.rsplit("/", 1)[-1]
        return httpx.Response(200, json={"id": mid, "threadId": f"t-{mid}"})

    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get(re.compile(r"/users/me/messages/m\d+")).mock(side_effect=handler)
        r = await messages_extras.batch_read_emails(client=client, message_ids=ids)

    assert "messages" in r
    msgs = r["messages"]
    assert len(msgs) == 5
    assert [m["id"] for m in msgs] == ids


@pytest.mark.asyncio
async def test_batch_read_default_format_is_metadata(client):
    """When format is omitted, the underlying GET sends format=metadata."""
    captured: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request.url.params.get("format", ""))
        return httpx.Response(200, json={"id": "m1"})

    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get("/users/me/messages/m1").mock(side_effect=handler)
        await messages_extras.batch_read_emails(client=client, message_ids=["m1"])
    assert captured == ["metadata"]


@pytest.mark.asyncio
async def test_batch_read_default_metadata_headers_applied(client):
    """when metadata_headers omitted and format=metadata,
    the default ['From', 'Subject', 'Date'] is sent to Gmail."""
    captured_multi: list[list[tuple[str, str]]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured_multi.append(list(request.url.params.multi_items()))
        return httpx.Response(200, json={"id": "m1"})

    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get("/users/me/messages/m1").mock(side_effect=handler)
        await messages_extras.batch_read_emails(client=client, message_ids=["m1"])

    assert len(captured_multi) == 1
    headers = [v for k, v in captured_multi[0] if k == "metadataHeaders"]
    assert headers == ["From", "Subject", "Date"]


@pytest.mark.asyncio
async def test_batch_read_caller_supplied_metadata_headers_pass_through(client):
    """Caller-supplied metadata_headers replaces the default verbatim."""
    captured_multi: list[list[tuple[str, str]]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured_multi.append(list(request.url.params.multi_items()))
        return httpx.Response(200, json={"id": "m1"})

    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get("/users/me/messages/m1").mock(side_effect=handler)
        await messages_extras.batch_read_emails(
            client=client,
            message_ids=["m1"],
            metadata_headers=["Message-Id", "References"],
        )

    headers = [v for k, v in captured_multi[0] if k == "metadataHeaders"]
    assert headers == ["Message-Id", "References"]


@pytest.mark.asyncio
async def test_batch_read_format_minimal_does_not_send_metadata_headers(client):
    """When format=minimal, metadataHeaders is irrelevant; no key sent."""
    captured_multi: list[list[tuple[str, str]]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured_multi.append(list(request.url.params.multi_items()))
        return httpx.Response(200, json={"id": "m1"})

    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get("/users/me/messages/m1").mock(side_effect=handler)
        await messages_extras.batch_read_emails(
            client=client,
            message_ids=["m1"],
            format="minimal",
        )

    keys = [k for k, _ in captured_multi[0]]
    assert "metadataHeaders" not in keys
    assert ("format", "minimal") in captured_multi[0]


# ---------------------------------------------------------------------------
# Partial success
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_batch_read_partial_failure_surfaces_per_id_error(client):
    """One id 404s; the four other reads succeed; record carries message_id."""
    ids = ["m1", "m2", "missing", "m4", "m5"]

    def handler(request: httpx.Request) -> httpx.Response:
        mid = request.url.path.rsplit("/", 1)[-1]
        if mid == "missing":
            return httpx.Response(404, json={})
        return httpx.Response(200, json={"id": mid})

    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get(re.compile(r"/users/me/messages/.+")).mock(side_effect=handler)
        r = await messages_extras.batch_read_emails(client=client, message_ids=ids)

    assert len(r["messages"]) == 5
    failed = r["messages"][2]
    assert failed["message_id"] == "missing"
    assert failed["error_status"] == 404
    assert "error_message" in failed
    # Successes intact in order.
    assert r["messages"][0]["id"] == "m1"
    assert r["messages"][4]["id"] == "m5"


@pytest.mark.asyncio
async def test_batch_read_429_carries_retry_after(client):
    """a 429 with Retry-After surfaces retry_after_seconds."""
    ids = ["m1", "rate"]

    def handler(request: httpx.Request) -> httpx.Response:
        mid = request.url.path.rsplit("/", 1)[-1]
        if mid == "rate":
            return httpx.Response(429, json={}, headers={"Retry-After": "11"})
        return httpx.Response(200, json={"id": mid})

    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get(re.compile(r"/users/me/messages/.+")).mock(side_effect=handler)
        r = await messages_extras.batch_read_emails(client=client, message_ids=ids)

    failed = r["messages"][1]
    assert failed["error_status"] == 429
    assert failed.get("retry_after_seconds") == 11


# ---------------------------------------------------------------------------
# Handler-entry rejection (defense in depth past JSON Schema)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_batch_read_oversize_rejected_at_handler(client):
    """101 ids: handler rejects, no Gmail call lands."""
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        any_route = router.route()
        any_route.mock(return_value=httpx.Response(200, json={}))
        r = await messages_extras.batch_read_emails(
            client=client, message_ids=[f"m{i}" for i in range(101)]
        )
        assert any_route.called is False
    assert r["code"] == ToolErrorCode.BAD_REQUEST


@pytest.mark.asyncio
async def test_batch_read_at_cap_passes(client):
    """Exactly 100 ids is allowed."""

    def handler(request: httpx.Request) -> httpx.Response:
        mid = request.url.path.rsplit("/", 1)[-1]
        return httpx.Response(200, json={"id": mid})

    ids = [f"m{i}" for i in range(100)]
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get(re.compile(r"/users/me/messages/.+")).mock(side_effect=handler)
        r = await messages_extras.batch_read_emails(client=client, message_ids=ids)
    assert len(r["messages"]) == 100


@pytest.mark.asyncio
async def test_batch_read_empty_list_rejected(client):
    """Empty message_ids list returns bad_request."""
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        any_route = router.route()
        any_route.mock(return_value=httpx.Response(200, json={}))
        r = await messages_extras.batch_read_emails(client=client, message_ids=[])
        assert any_route.called is False
    assert r["code"] == ToolErrorCode.BAD_REQUEST


@pytest.mark.asyncio
async def test_batch_read_invalid_format_rejected_at_handler(client):
    """format='full' (or anything outside the enum) rejected before any HTTP call."""
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        any_route = router.route()
        any_route.mock(return_value=httpx.Response(200, json={}))
        r = await messages_extras.batch_read_emails(
            client=client, message_ids=["m1"], format="full"
        )
        assert any_route.called is False
    assert r["code"] == ToolErrorCode.BAD_REQUEST


# ---------------------------------------------------------------------------
# Schema-layer probes (no jsonschema dep; re.match against pattern)
# ---------------------------------------------------------------------------


def test_pr3m_batch_read_format_enum_excludes_full_and_raw():
    """Schema enum is exactly metadata + minimal; a future loosening to
    `full` or `raw` would silently change response sizes by an order
    of magnitude. Catch the drift here."""
    tool_def = next(d for d in TOOL_DEFINITIONS if d["name"] == "batch_read_emails")
    fmt = tool_def["inputSchema"]["properties"]["format"]
    assert fmt["enum"] == ["metadata", "minimal"]


def test_pr3m_batch_read_caps_at_100():
    """maxItems=100 / minItems=1 on message_ids."""
    tool_def = next(d for d in TOOL_DEFINITIONS if d["name"] == "batch_read_emails")
    msg_ids = tool_def["inputSchema"]["properties"]["message_ids"]
    assert msg_ids["maxItems"] == 100
    assert msg_ids["minItems"] == 1


def test_pr3m_batch_read_message_ids_pattern_rejects_adversarial_at_schema():
    """The adversarial probe set is rejected by the JSON Schema
    pattern on each message_ids[i]. The regex parity walker
    auto-asserts the pattern matches _VALIDATION_PATTERN; this test
    additionally exercises the rejection."""
    tool_def = next(d for d in TOOL_DEFINITIONS if d["name"] == "batch_read_emails")
    items = tool_def["inputSchema"]["properties"]["message_ids"]["items"]
    pattern = re.compile(items["pattern"])
    bad = [
        "id\x00null",
        "id\r\nX-Injected: 1",
        "idаbc",  # cyrillic
        "id%2Fbad",
        "id\\bad",
        "id#fragment",
        "id;evil",
        "id@evil",
        ".",
        "T" * 257,
    ]
    for v in bad:
        assert pattern.match(v) is None, f"unexpectedly matched {v!r}"


def test_pr3m_batch_read_metadata_headers_pattern_rejects_crlf():
    """each metadata_headers item carries a token-only pattern.
    CRLF / colon / space cannot reach Gmail's metadataHeaders param."""
    tool_def = next(d for d in TOOL_DEFINITIONS if d["name"] == "batch_read_emails")
    items = tool_def["inputSchema"]["properties"]["metadata_headers"]["items"]
    pattern = re.compile(items["pattern"])
    bad = [
        "From\r\nX-Injected: 1",
        "Subject\x00",
        "Date: 2026",
        "From Line",
        "X:Y",
    ]
    for v in bad:
        assert pattern.match(v) is None, f"unexpectedly matched {v!r}"
    # Realistic header names accepted.
    for ok in ["From", "Subject", "Date", "Message-Id", "X-Custom-Header"]:
        assert pattern.match(ok) is not None


# ---------------------------------------------------------------------------
# Handler-entry validation: malformed id surfaces per-id, not batch-fail
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_batch_read_handler_entry_malformed_id_surfaces_per_id(client):
    """Bypass the schema by calling the handler with a bad id directly.
    validate_gmail_id raises ValueError; the per-coroutine catch
    converts it to a per-id error record (NOT a batch failure)."""
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        # The valid ids should still fire; the bad id should not.
        good_route = router.get(re.compile(r"/users/me/messages/m\d+")).mock(
            return_value=httpx.Response(200, json={"id": "m1"})
        )
        ids = ["m1", "bad id with spaces", "m2"]
        r = await messages_extras.batch_read_emails(client=client, message_ids=ids)
        assert good_route.called is True

    assert len(r["messages"]) == 3
    # Bad id slot carries the per-id error record.
    bad_rec = r["messages"][1]
    assert bad_rec.get("message_id") == "bad id with spaces"
    assert "error_status" in bad_rec
    assert "error_message" in bad_rec
