"""Tests for the write-side label tools (create_label, update_label, delete_label)."""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from mcp_gmail.gmail_tools import labels_write
from mcp_gmail.gmail_tools.errors import ToolErrorCode
from mcp_gmail.gmail_tools.gmail_client import GMAIL_API_BASE, GmailClient


@pytest.fixture
async def client():
    c = GmailClient(access_token="t")
    yield c
    await c.aclose()


# ---------------------------------------------------------------------------
# create_label
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_label_sends_name(client):
    captured: dict[str, dict] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.read().decode())
        return httpx.Response(200, json={"id": "Label_1", "name": "Project X"})

    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.post("/users/me/labels").mock(side_effect=handler)
        r = await labels_write.create_label(client=client, name="Project X")
    assert captured["body"] == {"name": "Project X"}
    assert r["id"] == "Label_1"


@pytest.mark.asyncio
async def test_create_label_omits_none_optionals(client):
    captured: dict[str, dict] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.read().decode())
        return httpx.Response(200, json={"id": "Label_1"})

    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.post("/users/me/labels").mock(side_effect=handler)
        await labels_write.create_label(client=client, name="X")
    assert "labelListVisibility" not in captured["body"]
    assert "messageListVisibility" not in captured["body"]
    assert "color" not in captured["body"]


@pytest.mark.asyncio
async def test_create_label_includes_visibility_and_color(client):
    captured: dict[str, dict] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.read().decode())
        return httpx.Response(200, json={"id": "Label_1"})

    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.post("/users/me/labels").mock(side_effect=handler)
        await labels_write.create_label(
            client=client,
            name="X",
            label_list_visibility="labelShow",
            message_list_visibility="show",
            color={"backgroundColor": "#ff0000", "textColor": "#ffffff"},
        )
    body = captured["body"]
    assert body["labelListVisibility"] == "labelShow"
    assert body["messageListVisibility"] == "show"
    assert body["color"] == {"backgroundColor": "#ff0000", "textColor": "#ffffff"}


# ---------------------------------------------------------------------------
# 225-char Gmail label-name cap, char count not byte
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_label_accepts_225_char_name(client):
    """Exactly at the Gmail cap: accepted."""
    name_at_cap = "x" * 225
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.post("/users/me/labels").mock(
            return_value=httpx.Response(200, json={"id": "L1", "name": name_at_cap})
        )
        r = await labels_write.create_label(client=client, name=name_at_cap)
    assert r["id"] == "L1"


@pytest.mark.asyncio
async def test_create_label_rejects_226_char_name(client):
    """One char over the cap: bad_request, no Gmail call."""
    name_over = "x" * 226
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        any_route = router.route()
        any_route.mock(return_value=httpx.Response(200, json={"id": "leak"}))
        r = await labels_write.create_label(client=client, name=name_over)
        assert any_route.called is False
    assert r["code"] == ToolErrorCode.BAD_REQUEST
    assert "225" in r["message"]


@pytest.mark.asyncio
async def test_create_label_unicode_char_count_not_byte_count(client):
    """The cap is on CHARS not BYTES. 'é' is 1 char (2 UTF-8 bytes).

    Gmail's documented limit is display-length, so a 225-char string of
    multi-byte glyphs is accepted (450 UTF-8 bytes). 226 multi-byte
    glyphs is rejected by char count alone, no byte arithmetic.
    """
    # 225 multi-byte glyphs: 450 bytes UTF-8, but 225 chars -> accepted.
    name_unicode_at_cap = "é" * 225
    assert len(name_unicode_at_cap) == 225
    assert len(name_unicode_at_cap.encode("utf-8")) == 450
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.post("/users/me/labels").mock(
            return_value=httpx.Response(200, json={"id": "L1", "name": name_unicode_at_cap})
        )
        r = await labels_write.create_label(client=client, name=name_unicode_at_cap)
    assert r["id"] == "L1"

    # 226 multi-byte glyphs -> rejected (char count, not byte count).
    name_unicode_over = "é" * 226
    assert len(name_unicode_over) == 226
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        any_route = router.route()
        any_route.mock(return_value=httpx.Response(200, json={"id": "leak"}))
        r = await labels_write.create_label(client=client, name=name_unicode_over)
        assert any_route.called is False
    assert r["code"] == ToolErrorCode.BAD_REQUEST


# ---------------------------------------------------------------------------
# update_label
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_update_label_sends_partial_body(client):
    captured: dict[str, str | dict] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["method"] = request.method
        captured["body"] = json.loads(request.read().decode())
        return httpx.Response(200, json={"id": "L1", "name": "renamed"})

    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.put("/users/me/labels/L1").mock(side_effect=handler)
        r = await labels_write.update_label(client=client, label_id="L1", name="renamed")
    assert captured["method"] == "PUT"
    assert captured["body"] == {"name": "renamed"}
    assert r["name"] == "renamed"


@pytest.mark.asyncio
async def test_update_label_404(client):
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.put("/users/me/labels/missing").mock(return_value=httpx.Response(404, json={}))
        r = await labels_write.update_label(client=client, label_id="missing", name="x")
    assert r["code"] == ToolErrorCode.NOT_FOUND


# ---------------------------------------------------------------------------
# update_label cap symmetry with create_label
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_update_label_accepts_225_char_name(client):
    """Exactly at the Gmail cap: accepted, request reaches Gmail."""
    name_at_cap = "x" * 225
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.put("/users/me/labels/L1").mock(
            return_value=httpx.Response(200, json={"id": "L1", "name": name_at_cap})
        )
        r = await labels_write.update_label(client=client, label_id="L1", name=name_at_cap)
    assert r["id"] == "L1"
    assert r["name"] == name_at_cap


@pytest.mark.asyncio
async def test_update_label_rejects_226_char_name(client):
    """One char over the cap: bad_request, no Gmail call."""
    name_over = "x" * 226
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        any_route = router.route()
        any_route.mock(return_value=httpx.Response(200, json={"id": "leak"}))
        r = await labels_write.update_label(client=client, label_id="L1", name=name_over)
        assert any_route.called is False
    assert r["code"] == ToolErrorCode.BAD_REQUEST
    assert "225" in r["message"]


@pytest.mark.asyncio
async def test_update_label_with_no_name_change_succeeds(client):
    """Regression: name=None (color-only update) bypasses the cap check.

    update_label allows partial bodies; callers updating only the color
    or visibility flags pass name=None. The cap check must not block
    that path.
    """
    captured: dict[str, dict] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.read().decode())
        return httpx.Response(200, json={"id": "L1"})

    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.put("/users/me/labels/L1").mock(side_effect=handler)
        r = await labels_write.update_label(
            client=client,
            label_id="L1",
            color={"backgroundColor": "#000000", "textColor": "#ffffff"},
        )
    assert "name" not in captured["body"]
    assert captured["body"]["color"] == {
        "backgroundColor": "#000000",
        "textColor": "#ffffff",
    }
    assert r["id"] == "L1"


# ---------------------------------------------------------------------------
# delete_label
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_delete_label_calls_DELETE(client):
    captured: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["method"] = request.method
        return httpx.Response(204)

    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.delete("/users/me/labels/L1").mock(side_effect=handler)
        r = await labels_write.delete_label(client=client, label_id="L1")
    assert captured["method"] == "DELETE"
    assert r == {}


@pytest.mark.asyncio
async def test_delete_label_404(client):
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.delete("/users/me/labels/missing").mock(return_value=httpx.Response(404, json={}))
        r = await labels_write.delete_label(client=client, label_id="missing")
    assert r["code"] == ToolErrorCode.NOT_FOUND


# ---------------------------------------------------------------------------
# get_or_create_label
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_or_create_label_returns_existing_when_name_matches(client):
    """Existing label with exact-name match returned without create call."""
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        list_route = router.get("/users/me/labels").mock(
            return_value=httpx.Response(
                200,
                json={
                    "labels": [
                        {"id": "Label_INBOX", "name": "INBOX", "type": "system"},
                        {"id": "Label_42", "name": "Project X", "type": "user"},
                    ]
                },
            )
        )
        create_route = router.post("/users/me/labels").mock(
            return_value=httpx.Response(200, json={"id": "should_not_create"})
        )
        r = await labels_write.get_or_create_label(client=client, name="Project X")
        assert list_route.called is True
        assert create_route.called is False
    assert r["id"] == "Label_42"
    assert r["name"] == "Project X"


@pytest.mark.asyncio
async def test_get_or_create_label_creates_when_missing(client):
    """No exact-name match -> create call lands."""
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get("/users/me/labels").mock(return_value=httpx.Response(200, json={"labels": []}))
        router.post("/users/me/labels").mock(
            return_value=httpx.Response(200, json={"id": "Label_new", "name": "NEW"})
        )
        r = await labels_write.get_or_create_label(client=client, name="NEW")
    assert r["id"] == "Label_new"
    assert r["name"] == "NEW"


@pytest.mark.asyncio
async def test_get_or_create_label_is_case_sensitive(client):
    """N3: 'important' and 'Important' are distinct labels per Gmail."""
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get("/users/me/labels").mock(
            return_value=httpx.Response(
                200,
                json={"labels": [{"id": "L1", "name": "Important", "type": "user"}]},
            )
        )
        router.post("/users/me/labels").mock(
            return_value=httpx.Response(200, json={"id": "L2", "name": "important"})
        )
        r = await labels_write.get_or_create_label(client=client, name="important")
    assert r["id"] == "L2", "lowercase name should not match capitalized existing"


@pytest.mark.asyncio
async def test_get_or_create_label_passes_visibility_to_create(client):
    """Optional visibility / color flow through to create body."""
    captured: dict[str, dict] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.read().decode())
        return httpx.Response(200, json={"id": "Lnew"})

    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get("/users/me/labels").mock(return_value=httpx.Response(200, json={"labels": []}))
        router.post("/users/me/labels").mock(side_effect=handler)
        await labels_write.get_or_create_label(
            client=client,
            name="X",
            label_list_visibility="labelHide",
            color={"backgroundColor": "#000000", "textColor": "#ffffff"},
        )
    assert captured["body"]["labelListVisibility"] == "labelHide"
    assert captured["body"]["color"] == {
        "backgroundColor": "#000000",
        "textColor": "#ffffff",
    }
