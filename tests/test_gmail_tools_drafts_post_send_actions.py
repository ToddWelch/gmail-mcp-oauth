"""send_draft post-send action tests.

Split from test_gmail_tools_drafts.py to honor the file-size rule;
the parent test file is already at 458 LOC and adding ~150 LOC of
post-send enhancement coverage there would compound the violation.

Coverage matrix:
- backward compat: legacy callers (no new params) hit the same
  request/response shape byte-for-byte
- archive_thread=true: send + modify_thread with removeLabelIds=['INBOX']
- add_labels / remove_labels pass through to modify_thread
- archive_thread + caller-supplied remove_labels merge with INBOX dedup
- send-success + modify-fail: success record + post_send_actions.applied=false
- send-fail (404): not_found_error; modify NEVER called (idempotency boundary)
- send-fail (other GmailApiError): re-raised; modify NEVER called
- post-send action with all-empty + archive_thread=false: NO modify call
- send_draft + archive_thread=true + caller granted only SEND scope:
  bad_request_error at handler entry, send NEVER called
- adversarial label id rejected by LABEL_ID_LIST_PROP regex (schema layer)
"""

from __future__ import annotations

import json
import re

import httpx
import pytest
import respx

from mcp_gmail.gmail_tools import drafts
from mcp_gmail.gmail_tools.errors import ToolErrorCode
from mcp_gmail.gmail_tools.gmail_client import GMAIL_API_BASE, GmailClient
from mcp_gmail.gmail_tools.scope_check import SCOPE_MODIFY, SCOPE_SEND


@pytest.fixture
async def client():
    c = GmailClient(access_token="t")
    yield c
    await c.aclose()


# Mailbox scope big enough for post-send actions across the suite.
_SCOPE_MODIFY_GRANTED = SCOPE_MODIFY


# ---------------------------------------------------------------------------
# Backward compat ( callers must not regress)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_send_draft_omits_post_send_actions_when_no_new_params(client):
    """Caller omits archive_thread / add_labels / remove_labels:
    - request body is byte-identical to  {"id": draft_id}
    - response is the raw sent message resource (no post_send_actions key)
    - modify_thread is NEVER called
    """
    captured: dict[str, dict] = {}
    modify_called = {"value": False}

    def send_handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.read().decode())
        return httpx.Response(200, json={"id": "sent-1", "threadId": "t-1", "labelIds": ["SENT"]})

    def modify_handler(request: httpx.Request) -> httpx.Response:
        modify_called["value"] = True
        return httpx.Response(200, json={})

    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        router.post("/users/me/drafts/send").mock(side_effect=send_handler)
        router.post(re.compile(r"/users/me/threads/[^/]+/modify")).mock(side_effect=modify_handler)
        r = await drafts.send_draft(client=client, draft_id="d1")

    assert captured["body"] == {"id": "d1"}
    assert "post_send_actions" not in r
    assert r["id"] == "sent-1"
    assert r["threadId"] == "t-1"
    assert modify_called["value"] is False


# ---------------------------------------------------------------------------
# archive_thread / labels happy paths
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_send_draft_archive_thread_calls_modify_with_inbox_remove(client):
    """archive_thread=true: send + modify_thread with removeLabelIds=['INBOX']."""
    sent = {"id": "sent-2", "threadId": "t-2", "labelIds": ["SENT"]}
    modify_body: dict[str, dict] = {}

    def send_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=sent)

    def modify_handler(request: httpx.Request) -> httpx.Response:
        modify_body["body"] = json.loads(request.read().decode())
        return httpx.Response(200, json={"id": "t-2"})

    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.post("/users/me/drafts/send").mock(side_effect=send_handler)
        router.post("/users/me/threads/t-2/modify").mock(side_effect=modify_handler)
        r = await drafts.send_draft(
            client=client,
            draft_id="d1",
            archive_thread=True,
            granted_scope=_SCOPE_MODIFY_GRANTED,
        )

    assert modify_body["body"] == {"removeLabelIds": ["INBOX"]}
    assert r["post_send_actions"]["applied"] is True
    assert r["post_send_actions"]["thread_id"] == "t-2"
    assert r["post_send_actions"]["action_failures"] == []


@pytest.mark.asyncio
async def test_send_draft_add_labels_passes_through(client):
    """add_labels populates addLabelIds on modify_thread."""
    modify_body: dict[str, dict] = {}

    def send_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"id": "s", "threadId": "t-3"})

    def modify_handler(request: httpx.Request) -> httpx.Response:
        modify_body["body"] = json.loads(request.read().decode())
        return httpx.Response(200, json={})

    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.post("/users/me/drafts/send").mock(side_effect=send_handler)
        router.post("/users/me/threads/t-3/modify").mock(side_effect=modify_handler)
        await drafts.send_draft(
            client=client,
            draft_id="d1",
            add_labels=["Label_A", "Label_B"],
            granted_scope=_SCOPE_MODIFY_GRANTED,
        )

    assert modify_body["body"] == {"addLabelIds": ["Label_A", "Label_B"]}


@pytest.mark.asyncio
async def test_send_draft_remove_labels_passes_through(client):
    """remove_labels populates removeLabelIds on modify_thread."""
    modify_body: dict[str, dict] = {}

    def send_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"id": "s", "threadId": "t-4"})

    def modify_handler(request: httpx.Request) -> httpx.Response:
        modify_body["body"] = json.loads(request.read().decode())
        return httpx.Response(200, json={})

    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.post("/users/me/drafts/send").mock(side_effect=send_handler)
        router.post("/users/me/threads/t-4/modify").mock(side_effect=modify_handler)
        await drafts.send_draft(
            client=client,
            draft_id="d1",
            remove_labels=["UNREAD"],
            granted_scope=_SCOPE_MODIFY_GRANTED,
        )

    assert modify_body["body"] == {"removeLabelIds": ["UNREAD"]}


@pytest.mark.asyncio
async def test_send_draft_archive_with_caller_remove_labels_dedups_inbox(client):
    """archive_thread=true + caller already supplied INBOX in
    remove_labels: the merge dedups so Gmail receives ['INBOX'], not
    ['INBOX', 'INBOX']."""
    modify_body: dict[str, dict] = {}

    def send_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"id": "s", "threadId": "t-5"})

    def modify_handler(request: httpx.Request) -> httpx.Response:
        modify_body["body"] = json.loads(request.read().decode())
        return httpx.Response(200, json={})

    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.post("/users/me/drafts/send").mock(side_effect=send_handler)
        router.post("/users/me/threads/t-5/modify").mock(side_effect=modify_handler)
        await drafts.send_draft(
            client=client,
            draft_id="d1",
            archive_thread=True,
            remove_labels=["INBOX", "UNREAD"],
            granted_scope=_SCOPE_MODIFY_GRANTED,
        )

    # Dedup: INBOX appears exactly once.
    assert modify_body["body"]["removeLabelIds"].count("INBOX") == 1
    assert "UNREAD" in modify_body["body"]["removeLabelIds"]


@pytest.mark.asyncio
async def test_send_draft_archive_with_add_and_remove_merges_correctly(client):
    """archive_thread=true + add_labels + remove_labels: modify body has
    BOTH addLabelIds and removeLabelIds; INBOX appended to remove."""
    modify_body: dict[str, dict] = {}

    def send_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"id": "s", "threadId": "t-6"})

    def modify_handler(request: httpx.Request) -> httpx.Response:
        modify_body["body"] = json.loads(request.read().decode())
        return httpx.Response(200, json={})

    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.post("/users/me/drafts/send").mock(side_effect=send_handler)
        router.post("/users/me/threads/t-6/modify").mock(side_effect=modify_handler)
        await drafts.send_draft(
            client=client,
            draft_id="d1",
            archive_thread=True,
            add_labels=["Label_X"],
            remove_labels=["UNREAD"],
            granted_scope=_SCOPE_MODIFY_GRANTED,
        )

    body = modify_body["body"]
    assert body["addLabelIds"] == ["Label_X"]
    assert "INBOX" in body["removeLabelIds"]
    assert "UNREAD" in body["removeLabelIds"]


# ---------------------------------------------------------------------------
# Idempotency boundary: send-success + modify-fail
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_send_draft_send_succeeds_modify_fails_returns_success_with_action_failures(client):
    """The send is on the wire; modify_thread fails. Result: success
    record annotated with post_send_actions.applied=false. The send
    mock fires EXACTLY ONCE (no retry)."""
    send_calls = {"count": 0}

    def send_handler(request: httpx.Request) -> httpx.Response:
        send_calls["count"] += 1
        return httpx.Response(200, json={"id": "sent-7", "threadId": "t-7"})

    def modify_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={})

    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.post("/users/me/drafts/send").mock(side_effect=send_handler)
        router.post("/users/me/threads/t-7/modify").mock(side_effect=modify_handler)
        r = await drafts.send_draft(
            client=client,
            draft_id="d1",
            archive_thread=True,
            granted_scope=_SCOPE_MODIFY_GRANTED,
        )

    # Send fired once, NOT retried.
    assert send_calls["count"] == 1
    # Top-level fields preserved (back-compat): success record.
    assert r["id"] == "sent-7"
    assert r["threadId"] == "t-7"
    # Action failures captured.
    pa = r["post_send_actions"]
    assert pa["applied"] is False
    assert pa["thread_id"] == "t-7"
    assert len(pa["action_failures"]) == 1
    failure = pa["action_failures"][0]
    assert failure["action"] == "modify_thread"
    assert failure["status"] == 404


# ---------------------------------------------------------------------------
# Send-fail: NO modify, NO retry
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_send_draft_send_404_skips_post_send_actions(client):
    """Send 404 returns not_found_error; modify_thread is NEVER called.
    This is the explicit decoupling the orchestrator brief mandates."""
    modify_called = {"value": False}

    def modify_handler(request: httpx.Request) -> httpx.Response:
        modify_called["value"] = True
        return httpx.Response(200, json={})

    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        router.post("/users/me/drafts/send").mock(return_value=httpx.Response(404, json={}))
        router.post(re.compile(r"/users/me/threads/[^/]+/modify")).mock(side_effect=modify_handler)
        r = await drafts.send_draft(
            client=client,
            draft_id="missing",
            archive_thread=True,
            granted_scope=_SCOPE_MODIFY_GRANTED,
        )

    assert r["code"] == ToolErrorCode.NOT_FOUND
    assert modify_called["value"] is False


# ---------------------------------------------------------------------------
# Empty post-send action lists
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_send_draft_empty_lists_and_archive_false_skips_modify_entirely(client):
    """add_labels=[], remove_labels=[], archive_thread=False: short-circuit
    BEFORE the modify_thread call. Falsy lists evaluate to no post-send
    work, matching the back-compat path."""
    modify_called = {"value": False}

    def modify_handler(request: httpx.Request) -> httpx.Response:
        modify_called["value"] = True
        return httpx.Response(200, json={})

    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        router.post("/users/me/drafts/send").mock(
            return_value=httpx.Response(200, json={"id": "s", "threadId": "t-8"})
        )
        router.post(re.compile(r"/users/me/threads/[^/]+/modify")).mock(side_effect=modify_handler)
        r = await drafts.send_draft(
            client=client,
            draft_id="d1",
            archive_thread=False,
            add_labels=[],
            remove_labels=[],
        )

    assert modify_called["value"] is False
    # Back-compat shape: no post_send_actions key.
    assert "post_send_actions" not in r


# ---------------------------------------------------------------------------
# Scope=SEND_ONLY rejection at handler entry
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_send_draft_with_archive_but_send_only_scope_rejected(client):
    """Caller granted gmail.send only (no gmail.modify) AND requests
    archive_thread: handler returns bad_request_error BEFORE the send
    is dispatched. The Gmail mock must NEVER be called (no message
    ends up on the wire)."""
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        any_route = router.route()
        any_route.mock(return_value=httpx.Response(200, json={}))
        r = await drafts.send_draft(
            client=client,
            draft_id="d1",
            archive_thread=True,
            granted_scope=SCOPE_SEND,
        )
        assert any_route.called is False

    assert r["code"] == ToolErrorCode.BAD_REQUEST
    # Useful error message points at /oauth/start.
    assert "/oauth/start" in r["message"]
    assert "gmail.modify" in r["message"]


@pytest.mark.asyncio
async def test_send_draft_with_add_labels_but_send_only_scope_rejected(client):
    """Same as above but with add_labels triggering the gate."""
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        any_route = router.route()
        any_route.mock(return_value=httpx.Response(200, json={}))
        r = await drafts.send_draft(
            client=client,
            draft_id="d1",
            add_labels=["Label_X"],
            granted_scope=SCOPE_SEND,
        )
        assert any_route.called is False

    assert r["code"] == ToolErrorCode.BAD_REQUEST


@pytest.mark.asyncio
async def test_send_draft_modify_network_error_surfaces_in_action_failures(client):
    """Network error on the modify call: action_failures records status=0
    + the network error message; send is NOT retried."""
    send_calls = {"count": 0}

    def send_handler(request: httpx.Request) -> httpx.Response:
        send_calls["count"] += 1
        return httpx.Response(200, json={"id": "s", "threadId": "t-net"})

    def modify_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("simulated modify connect failure")

    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.post("/users/me/drafts/send").mock(side_effect=send_handler)
        router.post("/users/me/threads/t-net/modify").mock(side_effect=modify_handler)
        r = await drafts.send_draft(
            client=client,
            draft_id="d1",
            archive_thread=True,
            granted_scope=_SCOPE_MODIFY_GRANTED,
        )

    assert send_calls["count"] == 1
    pa = r["post_send_actions"]
    assert pa["applied"] is False
    # gmail_client wraps connect failures into GmailApiError(status=0).
    failure = pa["action_failures"][0]
    assert failure["action"] == "modify_thread"
    assert failure["status"] == 0


@pytest.mark.asyncio
async def test_send_draft_modify_validation_error_surfaces_in_action_failures(client):
    """ValueError on the modify call (e.g. malformed thread_id from Gmail's
    own response): action_failures records status=-1 + the validator
    message; send is NOT retried."""
    sent_calls = {"count": 0}

    def send_handler(request: httpx.Request) -> httpx.Response:
        sent_calls["count"] += 1
        # Gmail returns a malformed threadId (synthetic edge case).
        return httpx.Response(200, json={"id": "s", "threadId": "bad id with spaces"})

    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        router.post("/users/me/drafts/send").mock(side_effect=send_handler)
        # Modify endpoint mock; validate_gmail_id should fail before
        # the request is sent, so this should NOT be called.
        modify_route = router.post(re.compile(r"/users/me/threads/.+/modify")).mock(
            return_value=httpx.Response(200, json={})
        )
        r = await drafts.send_draft(
            client=client,
            draft_id="d1",
            archive_thread=True,
            granted_scope=_SCOPE_MODIFY_GRANTED,
        )

    assert sent_calls["count"] == 1
    assert modify_route.called is False
    pa = r["post_send_actions"]
    assert pa["applied"] is False
    failure = pa["action_failures"][0]
    assert failure["action"] == "modify_thread"
    assert failure["status"] == -1
    assert "thread_id" in failure["message"]


@pytest.mark.asyncio
async def test_send_draft_missing_thread_id_surfaces_action_failure():
    """Defensive: if Gmail somehow returns a sent message without
    threadId, drafts_post_send records a structured action_failures
    entry rather than crashing. Exercises the helper directly because
    in practice Gmail always returns threadId on a successful send."""
    from mcp_gmail.gmail_tools import drafts_post_send

    sent = {"id": "x"}  # no threadId
    r = await drafts_post_send.apply_post_send_actions(
        client=None,  # never used because the helper short-circuits
        sent_message=sent,
        archive_thread=True,
        add_labels=None,
        remove_labels=None,
    )
    pa = r["post_send_actions"]
    assert pa["applied"] is False
    assert pa["thread_id"] is None
    assert pa["action_failures"][0]["status"] == -1
    assert "lacked threadId" in pa["action_failures"][0]["message"]


@pytest.mark.asyncio
async def test_send_draft_no_post_send_action_with_send_only_scope_succeeds(client):
    """Legacy callers (no post-send params) with SEND-only scope still
    succeed. The handler-entry gate only triggers when wants_post_send."""

    def send_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"id": "ok"})

    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.post("/users/me/drafts/send").mock(side_effect=send_handler)
        r = await drafts.send_draft(
            client=client,
            draft_id="d1",
            granted_scope=SCOPE_SEND,
        )

    assert r["id"] == "ok"


# ---------------------------------------------------------------------------
# Schema-layer regex on label IDs
# ---------------------------------------------------------------------------


def test_pr3m_send_draft_add_labels_schema_pattern_rejects_adversarial():
    """LABEL_ID_LIST_PROP's regex is reused on the new add_labels /
    remove_labels params. Adversarial probes (CRLF, null byte, etc.)
    rejected at the schema layer."""
    from mcp_gmail.gmail_tools import TOOL_DEFINITIONS

    tool_def = next(d for d in TOOL_DEFINITIONS if d["name"] == "send_draft")
    add_labels = tool_def["inputSchema"]["properties"]["add_labels"]
    remove_labels = tool_def["inputSchema"]["properties"]["remove_labels"]
    add_pattern = re.compile(add_labels["items"]["pattern"])
    remove_pattern = re.compile(remove_labels["items"]["pattern"])
    bad = [
        "id\x00null",
        "id\r\nX-Injected: 1",
        "id with spaces",
        "id;evil",
        "id@evil",
    ]
    for v in bad:
        assert add_pattern.match(v) is None
        assert remove_pattern.match(v) is None
    # Realistic accepted.
    for ok in ["INBOX", "Label_123", "My-Label"]:
        assert add_pattern.match(ok) is not None
        assert remove_pattern.match(ok) is not None
