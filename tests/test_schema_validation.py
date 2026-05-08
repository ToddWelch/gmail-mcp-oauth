"""Server-side JSON Schema validation tests for the dispatch boundary.

Covers `mcp_gmail.gmail_tools._schema_validator.validate_arguments`
(the per-tool compiled-validator cache) and its wiring in
`mcp_protocol.handle_jsonrpc` between the registered-tool check and
`dispatch_tool_call`.

Properties verified:
    1. Manifest sanity (Draft202012Validator.check_schema per tool).
    2. Happy path (one fixture per registered tool from
       `tests._schema_fixtures.HAPPY_FIXTURES`).
    3. Schema rejection probes (wrong type, missing required, oversize
       array, regex pattern mismatch, additionalProperties violation,
       enum violation, maxLength violation).
    4. Adversarial probes (CRLF, null byte, oversize, header/array
       items).
    5. No value echo (wire response carries correlation_id only).
    6. Notification short-circuit (None on schema-invalid notification).
    7. Defense in depth (schema-valid + handler-invalid still rejected).
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from jsonschema import Draft202012Validator

from mcp_gmail import mcp_protocol
from mcp_gmail.gmail_tools import TOOL_DEFINITIONS
from mcp_gmail.gmail_tools._schema_validator import validate_arguments

from ._schema_fixtures import EMAIL, GMAIL_ID, HAPPY_FIXTURES, THREAD_ID


# 1. Manifest sanity.


@pytest.mark.parametrize("tool", TOOL_DEFINITIONS, ids=lambda t: t["name"])
def test_every_tool_input_schema_is_valid_draft_2020_12(tool):
    Draft202012Validator.check_schema(tool["inputSchema"])


def test_happy_fixtures_cover_every_registered_tool():
    """Drift surface: a new tool added to TOOL_DEFINITIONS without a
    matching fixture entry must fail this test."""
    declared = {t["name"] for t in TOOL_DEFINITIONS}
    fixtured = set(HAPPY_FIXTURES.keys())
    assert declared == fixtured, (
        f"fixture drift: missing={declared - fixtured}, extra={fixtured - declared}"
    )


# 2. Happy path per tool.


@pytest.mark.parametrize(
    "tool_name,arguments",
    list(HAPPY_FIXTURES.items()),
    ids=list(HAPPY_FIXTURES.keys()),
)
def test_happy_path_validates(tool_name, arguments):
    assert validate_arguments(tool_name, arguments) is None


# 3. Schema rejection probes.


def test_reject_wrong_type_message_id_not_string():
    field = validate_arguments("read_email", {"account_email": EMAIL, "message_id": 42})
    assert field is not None and "message_id" in field


def test_reject_missing_required_account_email():
    """Missing-required surfaces at the parent path '/' since the
    absent property has no own path segment."""
    field = validate_arguments("read_email", {"message_id": GMAIL_ID})
    assert field == "/"


def test_reject_oversized_array_against_max_items():
    """batch_read_emails.message_ids has maxItems=100."""
    bad = {"account_email": EMAIL, "message_ids": [f"M{i}" for i in range(101)]}
    field = validate_arguments("batch_read_emails", bad)
    assert field is not None and "message_ids" in field


def test_reject_pattern_mismatch_path_traversal():
    bad = {"account_email": EMAIL, "message_id": "../etc/passwd"}
    field = validate_arguments("read_email", bad)
    assert field is not None and "message_id" in field


def test_reject_additional_properties_violation():
    bad = {"account_email": EMAIL, "message_id": GMAIL_ID, "evil": True}
    assert validate_arguments("read_email", bad) is not None


def test_reject_enum_violation():
    bad = {"account_email": EMAIL, "message_id": GMAIL_ID, "format": "bogus"}
    field = validate_arguments("read_email", bad)
    assert field is not None and "format" in field


def test_reject_max_length_violation():
    """search_emails.q has maxLength=1000."""
    field = validate_arguments("search_emails", {"account_email": EMAIL, "q": "x" * 1001})
    assert field is not None and "q" in field


# 4. Adversarial probes at the schema layer.


@pytest.mark.parametrize(
    "bad_id",
    [
        pytest.param("id\r\nX-Injected: 1", id="crlf"),
        pytest.param("id\nbody-injection", id="lf-only"),
        pytest.param("id\x00null", id="null-byte"),
        pytest.param("id with spaces", id="space"),
        pytest.param("id;param=evil", id="semicolon"),
        pytest.param("id@evil.example", id="at-sign"),
        pytest.param("id#fragment", id="hash"),
        pytest.param("id%2Fbad", id="url-encoded-slash"),
        pytest.param("id\\bad", id="backslash"),
        pytest.param("idаbc", id="unicode-cyrillic-homoglyph"),
        pytest.param("a" * 257, id="oversize-257-chars"),
    ],
)
def test_adversarial_message_id_rejected_at_schema_layer(bad_id):
    """Each adversarial shape rejected at schema BEFORE handlers run."""
    field = validate_arguments("read_email", {"account_email": EMAIL, "message_id": bad_id})
    assert field is not None and "message_id" in field


def test_adversarial_metadata_header_blocks_crlf():
    bad = {
        "account_email": EMAIL,
        "message_ids": [GMAIL_ID],
        "metadata_headers": ["From", "X-Inject\r\nEvil: 1"],
    }
    field = validate_arguments("batch_read_emails", bad)
    assert field is not None and "metadata_headers" in field


def test_adversarial_label_id_in_array_rejected():
    bad = {
        "account_email": EMAIL,
        "thread_id": THREAD_ID,
        "add_label_ids": ["INBOX", "evil\r\nshape"],
    }
    field = validate_arguments("modify_thread", bad)
    assert field is not None and "add_label_ids" in field


# 5. No value echo on the JSON-RPC wire.


@pytest.mark.asyncio
async def test_wire_response_does_not_echo_invalid_value():
    """A schema-invalid payload carrying a recognizable token must not
    surface that token in the JSON-RPC error envelope. Reflected-payload
    DoS mitigation."""
    # Token contains characters (`!@#`) that the Gmail-ID pattern
    # rejects, so the schema layer fails the call. The token's
    # alphanumeric prefix (`SECRET_LEAK_PROBE_ABC123`) is the
    # recognizable substring we assert never echoes.
    recognizable = "SECRET_LEAK_PROBE_ABC123"
    bad_value = f"{recognizable}!@#"
    msg = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "read_email",
            "arguments": {"account_email": EMAIL, "message_id": bad_value},
        },
    }
    response = await mcp_protocol.handle_jsonrpc(msg, correlation_id="cid-leak")
    assert response is not None and response["error"]["code"] == -32602
    assert recognizable not in repr(response)


@pytest.mark.asyncio
async def test_wire_response_carries_correlation_id_only():
    msg = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "read_email",
            "arguments": {"account_email": EMAIL, "message_id": "../etc/passwd"},
        },
    }
    response = await mcp_protocol.handle_jsonrpc(msg, correlation_id="cid-x")
    assert response["error"]["code"] == -32602
    assert "cid-x" in response["error"]["message"]
    assert "../etc/passwd" not in response["error"]["message"]
    assert "pattern" not in response["error"]["message"]


# 6. Notification short-circuit.


@pytest.mark.asyncio
async def test_schema_invalid_notification_returns_none():
    msg = {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "read_email",
            "arguments": {"account_email": EMAIL, "message_id": "../etc/passwd"},
        },
    }
    assert await mcp_protocol.handle_jsonrpc(msg) is None


# 7. Defense in depth.


@pytest.mark.asyncio
async def test_schema_valid_payload_still_subject_to_handler_validation():
    """Schema-valid arguments still flow to dispatch; handler-layer
    rejections (e.g. tool_router_helpers ToolValidation -> -32001)
    surface unchanged. Confirms the schema layer is additive."""
    captured = {}

    async def fake(*, tool_name, arguments, claims, settings):
        captured["called"] = True
        return {"code": -32001, "message": "handler-layer rejection"}

    msg = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "read_email",
            "arguments": {"account_email": EMAIL, "message_id": GMAIL_ID},
        },
    }
    with patch.object(mcp_protocol, "dispatch_tool_call", side_effect=fake):
        response = await mcp_protocol.handle_jsonrpc(msg, claims={"sub": "u"})

    assert captured.get("called") is True
    assert response["error"]["code"] == -32001
