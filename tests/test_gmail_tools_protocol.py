"""Tests for the mcp_protocol layer wiring of gmail_tools.

The protocol's tools/list MUST return the 25 tools (11 read + 14
write). tools/call routes by name to dispatch_tool_call and returns
either a JSON-RPC success result (with content blocks) or an error
envelope.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from mcp_gmail import mcp_protocol


@pytest.mark.asyncio
async def test_tools_list_returns_thirty_tools():
    """All four manifests combine to advertise 32 tools
    (11 read + 18 write + 1 bootstrap + 2 fanout extras)."""
    msg = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    response = await mcp_protocol.handle_jsonrpc(msg)
    assert response is not None
    assert "result" in response
    tools = response["result"]["tools"]
    assert len(tools) == 32
    names = [t["name"] for t in tools]
    # Read tools
    assert "read_email" in names
    assert "list_email_labels" in names
    # Write tools (14-tool surface)
    assert "send_email" in names
    assert "create_draft" in names
    assert "update_draft" in names
    assert "list_drafts" in names
    assert "send_draft" in names
    assert "delete_draft" in names
    assert "create_label" in names
    assert "update_label" in names
    assert "delete_label" in names
    assert "modify_email_labels" in names
    assert "create_filter" in names
    assert "delete_filter" in names
    assert "delete_email" in names
    assert "batch_delete_emails" in names
    # Cleanup tools (4)
    assert "reply_all" in names
    assert "batch_modify_emails" in names
    assert "get_or_create_label" in names
    assert "create_filter_from_template" in names
    # Bootstrap tool (1 tool)
    assert "connect_gmail_account" in names


@pytest.mark.asyncio
async def test_tools_call_unknown_name_returns_method_not_found():
    msg = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {"name": "not_a_real_tool", "arguments": {}},
    }
    response = await mcp_protocol.handle_jsonrpc(msg)
    assert response is not None
    assert response["error"]["code"] == -32601


@pytest.mark.asyncio
async def test_tools_call_missing_name_returns_invalid_params():
    msg = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {},
    }
    response = await mcp_protocol.handle_jsonrpc(msg)
    assert response["error"]["code"] == -32602


@pytest.mark.asyncio
async def test_tools_call_dispatches_to_gmail_tools():
    """The protocol layer calls dispatch_tool_call with the right args."""
    captured = {}

    async def fake(*, tool_name, arguments, claims, settings):
        captured["tool_name"] = tool_name
        captured["arguments"] = arguments
        captured["claims_sub"] = (claims or {}).get("sub")
        return {"id": "fake-result"}

    with patch.object(mcp_protocol, "dispatch_tool_call", side_effect=fake):
        msg = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "list_email_labels",
                "arguments": {"account_email": "x@example.com"},
            },
        }
        claims = {"sub": "user-a"}
        response = await mcp_protocol.handle_jsonrpc(msg, claims=claims)

    assert captured["tool_name"] == "list_email_labels"
    assert captured["arguments"] == {"account_email": "x@example.com"}
    assert captured["claims_sub"] == "user-a"
    assert response is not None
    # Success response wraps result as a content block.
    assert "result" in response
    assert "content" in response["result"]
    assert response["result"]["isError"] is False


@pytest.mark.asyncio
async def test_tools_call_error_dict_becomes_jsonrpc_error():
    """When dispatch returns an error-shaped dict, it surfaces as JSON-RPC error."""

    async def fake(**_kwargs):
        return {"code": -32004, "message": "scope"}

    with patch.object(mcp_protocol, "dispatch_tool_call", side_effect=fake):
        msg = {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "read_email",
                "arguments": {"account_email": "x@example.com", "message_id": "M1"},
            },
        }
        response = await mcp_protocol.handle_jsonrpc(msg, claims={"sub": "user-a"})

    assert response is not None
    assert "error" in response
    assert response["error"]["code"] == -32004


@pytest.mark.asyncio
async def test_tools_call_dispatch_exception_becomes_internal_error():
    """An unexpected exception in dispatch surfaces as -32603 (internal error)."""

    async def fake(**_kwargs):
        raise RuntimeError("oops")

    with patch.object(mcp_protocol, "dispatch_tool_call", side_effect=fake):
        msg = {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "read_email",
                "arguments": {"account_email": "x@example.com", "message_id": "M1"},
            },
        }
        response = await mcp_protocol.handle_jsonrpc(msg, claims={"sub": "user-a"})

    assert response["error"]["code"] == -32603


@pytest.mark.asyncio
async def test_tools_list_each_tool_has_required_schema_fields():
    """Every TOOL_DEFINITIONS entry must have name, description, inputSchema."""
    for tool in mcp_protocol.TOOL_DEFINITIONS:
        assert "name" in tool
        assert "description" in tool
        assert "inputSchema" in tool
        schema = tool["inputSchema"]
        assert schema.get("type") == "object"
        assert "properties" in schema
        # Every read tool requires account_email.
        assert "account_email" in schema["properties"]
        assert "account_email" in schema.get("required", [])
        # Strict additionalProperties.
        assert schema.get("additionalProperties") is False
