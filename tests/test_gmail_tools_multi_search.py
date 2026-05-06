"""Tests for the multi_search_emails tool.

Coverage matrix:
- happy path: ordered results, per-query echo
- partial-success: 429 on one query, others succeed
- partial-success carries Retry-After
- handler-entry oversize / empty rejection (defense-in-depth past schema)
- duplicate query strings allowed and echoed
- max_results_per_query / label_ids forwarded to underlying calls
- schema-layer probe: 1001-char query rejected at the JSON Schema layer
- network error (httpx.RequestError) caught per-coroutine
"""

from __future__ import annotations

import re
from typing import Any

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
async def test_multi_search_returns_ordered_per_query_results(client):
    """Three distinct queries return three result records in input order."""
    queries = ["from:alice", "from:bob", "from:carol"]

    def handler(request: httpx.Request) -> httpx.Response:
        q = request.url.params.get("q", "")
        # Embed the query verbatim in the response so we can verify
        # the per-coroutine echo lines up.
        return httpx.Response(200, json={"messages": [{"id": f"m-{q}"}]})

    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get("/users/me/messages").mock(side_effect=handler)
        r = await messages_extras.multi_search_emails(client=client, queries=queries)

    assert "results" in r
    results = r["results"]
    assert len(results) == 3
    assert [rec["query"] for rec in results] == queries
    for q, rec in zip(queries, results, strict=True):
        assert rec["messages"][0]["id"] == f"m-{q}"


@pytest.mark.asyncio
async def test_multi_search_forwards_max_results_per_query_and_label_ids(client):
    """Optional params propagate to every underlying list_messages call."""
    captured_params: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured_params.append(dict(request.url.params))
        return httpx.Response(200, json={"messages": []})

    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get("/users/me/messages").mock(side_effect=handler)
        await messages_extras.multi_search_emails(
            client=client,
            queries=["a", "b"],
            max_results_per_query=42,
            label_ids=["INBOX", "STARRED"],
        )

    assert len(captured_params) == 2
    for params in captured_params:
        assert params["maxResults"] == "42"
        # httpx serializes list values into a multi_dict via params=;
        # respx's request.url.params returns a QueryParams object that
        # only exposes the FIRST value via .get/__getitem__. Use
        # multi_items() (httpx.URL.params -> .multi_items returns all
        # repeated key/value pairs).
    # Re-pull with multi_items via respx capture (we did not capture
    # multi_items above). Repeat one call with a multi-aware capture.
    captured_multi: list[list[tuple[str, str]]] = []

    def multi_handler(request: httpx.Request) -> httpx.Response:
        captured_multi.append(list(request.url.params.multi_items()))
        return httpx.Response(200, json={"messages": []})

    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get("/users/me/messages").mock(side_effect=multi_handler)
        await messages_extras.multi_search_emails(
            client=client,
            queries=["a"],
            label_ids=["INBOX", "STARRED"],
        )
    assert len(captured_multi) == 1
    label_values = [v for k, v in captured_multi[0] if k == "labelIds"]
    assert label_values == ["INBOX", "STARRED"]


@pytest.mark.asyncio
async def test_multi_search_duplicate_queries_both_echoed(client):
    """Duplicate query strings are not deduped; both surface in the result."""
    queries = ["from:client_a", "from:client_a"]

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"messages": []})

    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get("/users/me/messages").mock(side_effect=handler)
        r = await messages_extras.multi_search_emails(client=client, queries=queries)

    assert len(r["results"]) == 2
    assert r["results"][0]["query"] == "from:client_a"
    assert r["results"][1]["query"] == "from:client_a"


@pytest.mark.asyncio
async def test_multi_search_empty_query_string_passes_through(client):
    """An empty `q` is permitted (consistent with search_emails)."""
    queries = ["", "from:alice"]

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"messages": [{"id": "x"}]})

    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get("/users/me/messages").mock(side_effect=handler)
        r = await messages_extras.multi_search_emails(client=client, queries=queries)

    assert len(r["results"]) == 2
    assert r["results"][0]["query"] == ""


@pytest.mark.asyncio
async def test_multi_search_passes_through_next_page_token_and_estimate(client):
    """Gmail's nextPageToken and resultSizeEstimate flow through per-query."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "messages": [{"id": "m1"}],
                "nextPageToken": "next-abc",
                "resultSizeEstimate": 17,
            },
        )

    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get("/users/me/messages").mock(side_effect=handler)
        r = await messages_extras.multi_search_emails(client=client, queries=["x"])

    rec = r["results"][0]
    assert rec["next_page_token"] == "next-abc"
    assert rec["result_size_estimate"] == 17


# ---------------------------------------------------------------------------
# Partial success
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_multi_search_partial_failure_surfaces_per_query_error_record(client):
    """One query returns 429; others succeed; ordering preserved."""

    def handler(request: httpx.Request) -> httpx.Response:
        q = request.url.params.get("q", "")
        if q == "fail":
            return httpx.Response(429, json={}, headers={"Retry-After": "7"})
        return httpx.Response(200, json={"messages": [{"id": "ok"}]})

    queries = ["good1", "fail", "good2"]
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get("/users/me/messages").mock(side_effect=handler)
        r = await messages_extras.multi_search_emails(client=client, queries=queries)

    assert len(r["results"]) == 3
    assert r["results"][0]["query"] == "good1"
    assert r["results"][0]["messages"][0]["id"] == "ok"
    failed = r["results"][1]
    assert failed["query"] == "fail"
    assert failed["error_status"] == 429
    # Retry-After flows through.
    assert failed.get("retry_after_seconds") == 7
    assert "error_message" in failed
    assert r["results"][2]["query"] == "good2"
    assert r["results"][2]["messages"][0]["id"] == "ok"


# ---------------------------------------------------------------------------
# Handler-entry rejection (defense in depth past JSON Schema)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_multi_search_oversize_queries_rejected_at_handler(client):
    """26 queries: handler returns bad_request, no Gmail call lands."""
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        any_route = router.route()
        any_route.mock(return_value=httpx.Response(200, json={"messages": []}))
        r = await messages_extras.multi_search_emails(
            client=client,
            queries=[f"q{i}" for i in range(26)],
        )
        assert any_route.called is False
    assert r["code"] == ToolErrorCode.BAD_REQUEST


@pytest.mark.asyncio
async def test_multi_search_empty_queries_list_rejected(client):
    """Empty queries list: handler returns bad_request."""
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        any_route = router.route()
        any_route.mock(return_value=httpx.Response(200, json={}))
        r = await messages_extras.multi_search_emails(client=client, queries=[])
        assert any_route.called is False
    assert r["code"] == ToolErrorCode.BAD_REQUEST


@pytest.mark.asyncio
async def test_multi_search_at_cap_succeeds(client):
    """Exactly 25 queries: succeeds (cap is inclusive)."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"messages": []})

    queries = [f"q{i}" for i in range(25)]
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get("/users/me/messages").mock(side_effect=handler)
        r = await messages_extras.multi_search_emails(client=client, queries=queries)
    assert len(r["results"]) == 25


# ---------------------------------------------------------------------------
# Schema-layer probe (no jsonschema dep; re.match against pattern)
# ---------------------------------------------------------------------------


def test_pr3m_multi_search_schema_pattern_rejects_oversize_query():
    """The 1000-char maxLength on each items entry is enforced at the schema layer.

    JSON Schema's maxLength rejects strings of length > 1000. We
    extract the items spec and verify the cap directly.
    """
    tool_def = next(d for d in TOOL_DEFINITIONS if d["name"] == "multi_search_emails")
    items = tool_def["inputSchema"]["properties"]["queries"]["items"]
    assert items["maxLength"] == 1000


def test_pr3m_multi_search_schema_caps_at_25():
    """The maxItems=25 cap on `queries` lives at the schema layer."""
    tool_def = next(d for d in TOOL_DEFINITIONS if d["name"] == "multi_search_emails")
    queries = tool_def["inputSchema"]["properties"]["queries"]
    assert queries["maxItems"] == 25
    assert queries["minItems"] == 1


def test_pr3m_multi_search_label_ids_pattern_matches_validation_regex():
    """label_ids[i] pattern should be the canonical Gmail-ID regex,
    so adversarial label IDs (CRLF, null byte, etc.) are rejected at
    the JSON Schema layer."""
    tool_def = next(d for d in TOOL_DEFINITIONS if d["name"] == "multi_search_emails")
    label_ids = tool_def["inputSchema"]["properties"]["label_ids"]
    pattern = re.compile(label_ids["items"]["pattern"])

    bad = [
        "id\x00null",
        "id\r\nX-Injected: 1",
        "id with spaces",
        "id%2Fbad",
        "id#fragment",
        "id;evil",
        "id@evil",
    ]
    for v in bad:
        assert pattern.match(v) is None
    # Realistic IDs accepted
    assert pattern.match("INBOX") is not None
    assert pattern.match("Label_123") is not None


# ---------------------------------------------------------------------------
# Network error (httpx.RequestError catch)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_multi_search_network_error_surfaces_as_per_query_record(client):
    """A transport-layer failure on one query produces an error record,
    rather than aborting the gather. The codebase's gmail_client wraps
    httpx.HTTPError into GmailApiError(status=0); this test exercises
    that path while documenting the seam this test closes."""

    def handler(request: httpx.Request) -> httpx.Response:
        q = request.url.params.get("q", "")
        if q == "boom":
            raise httpx.ConnectError("simulated connect failure")
        return httpx.Response(200, json={"messages": [{"id": "ok"}]})

    queries = ["fine", "boom", "fine2"]
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get("/users/me/messages").mock(side_effect=handler)
        r = await messages_extras.multi_search_emails(client=client, queries=queries)

    assert len(r["results"]) == 3
    assert r["results"][0]["messages"][0]["id"] == "ok"
    failed = r["results"][1]
    assert failed["query"] == "boom"
    # gmail_client wraps connect failures as GmailApiError(status=0).
    assert failed["error_status"] == 0
    assert "error_message" in failed
    assert r["results"][2]["messages"][0]["id"] == "ok"
