"""Shared respx helpers for the reply-threading tests.

Every ID and address here is made up. Tests mount the two Gmail reads the
resolver performs (search by rfc822msgid, then one metadata GET per hit) and
the send endpoints, then assert on what was actually POSTed.
"""

from __future__ import annotations

import asyncio
import base64
import email
import json

import httpx
import respx

from mcp_gmail.gmail_tools.scope_check import (
    SCOPE_COMPOSE,
    SCOPE_MODIFY,
    SCOPE_READONLY,
    SCOPE_SEND,
)

# Scope strings a linked account can hold.
SCOPES_FULL_ACCESS = SCOPE_MODIFY
SCOPES_SEND_ONLY = SCOPE_SEND
SCOPES_COMPOSE_ONLY = SCOPE_COMPOSE
SCOPES_SEND_AND_READ = f"{SCOPE_SEND} {SCOPE_READONLY}"

TARGET_RFC_ID = "<parent-1@mail.example.com>"
TARGET_GMAIL_ID = "gmailparent00001"
TARGET_THREAD = "thread0000000001"
TARGET_SUBJECT = "Items"
DRAFT_MESSAGE_ID = "draftmessage0001"


def message_metadata(
    *,
    gmail_id: str = TARGET_GMAIL_ID,
    thread_id: str = TARGET_THREAD,
    rfc_id: str = TARGET_RFC_ID,
    subject: str = TARGET_SUBJECT,
) -> dict:
    """A Gmail format=metadata message. Gmail returns the header as 'Message-Id'."""
    return {
        "id": gmail_id,
        "threadId": thread_id,
        "payload": {
            "headers": [
                {"name": "Message-Id", "value": rfc_id},
                {"name": "Subject", "value": subject},
            ]
        },
    }


def mount_lookup(router: respx.Router, *messages: dict, next_page_token: str | None = None):
    """Mount the search and the per-hit metadata GETs. Returns the search route."""
    listing: dict = {"resultSizeEstimate": len(messages)}
    if messages:
        listing["messages"] = [{"id": m["id"], "threadId": m["threadId"]} for m in messages]
    if next_page_token is not None:
        listing["nextPageToken"] = next_page_token
    search = router.get("/users/me/messages").mock(return_value=httpx.Response(200, json=listing))
    for m in messages:
        router.get(f"/users/me/messages/{m['id']}").mock(return_value=httpx.Response(200, json=m))
    return search


def mount_send(
    router: respx.Router, *, thread_id: str = TARGET_THREAD, sent_id: str = "sent000000000001"
):
    """Mount users.messages.send, answering with `thread_id`."""
    return router.post("/users/me/messages/send").mock(
        return_value=httpx.Response(200, json={"id": sent_id, "threadId": thread_id})
    )


def mount_draft(
    router: respx.Router,
    *,
    draft_id: str = "d1",
    thread_id: str = TARGET_THREAD,
    subject: str = "A new conversation",
    in_reply_to: str | None = None,
    references: str | None = None,
):
    """Mount the metadata read send_draft performs on a stored draft."""
    headers = [{"name": "Subject", "value": subject}]
    if in_reply_to is not None:
        headers.append({"name": "In-Reply-To", "value": in_reply_to})
    if references is not None:
        headers.append({"name": "References", "value": references})
    return router.get(f"/users/me/drafts/{draft_id}").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": draft_id,
                "message": {
                    "id": DRAFT_MESSAGE_ID,
                    "threadId": thread_id,
                    "labelIds": ["DRAFT"],
                    "payload": {"headers": headers},
                },
            },
        )
    )


def mount_fresh_draft(router: respx.Router, *, draft_id: str = "d1"):
    """A draft that is a new conversation: Gmail gives it threadId == its message id."""
    return router.get(f"/users/me/drafts/{draft_id}").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": draft_id,
                "message": {
                    "id": "freshdraftthread",
                    "threadId": "freshdraftthread",
                    "labelIds": ["DRAFT"],
                    "payload": {"headers": [{"name": "Subject", "value": "A new conversation"}]},
                },
            },
        )
    )


async def slow_send(request: httpx.Request) -> httpx.Response:
    """A send POST that really yields, as a network call does. Without this no two
    calls ever interleave, and a concurrency test passes with the lock removed."""
    await asyncio.sleep(0.01)
    return httpx.Response(200, json={"id": "sent000000000001", "threadId": TARGET_THREAD})


def posted_body(route) -> dict:
    """The JSON body of the single POST a route received."""
    assert route.call_count == 1, f"expected exactly one POST, got {route.call_count}"
    return json.loads(route.calls[0].request.content)


def decode_raw(body: dict) -> email.message.Message:
    """Parse the RFC 5322 message out of a Gmail `raw` field."""
    raw = body["raw"]
    padded = raw + "=" * (-len(raw) % 4)
    return email.message_from_bytes(base64.urlsafe_b64decode(padded))


def error_reason(result: dict) -> str | None:
    """The machine-readable refusal reason on a typed error."""
    return result["data"]["error_data"].get("reason")
