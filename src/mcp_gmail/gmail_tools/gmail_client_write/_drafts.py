"""Drafts-resource write methods for GmailClient.

Covers list, create, update, send, and delete on `/users/me/drafts`.
`list_drafts` is a GET but lives on the write-side surface because it
is consumed only by the draft tools, which require gmail.compose
scope rather than gmail.readonly.
"""

from __future__ import annotations

from typing import Any

from ..gmail_id import validate_gmail_id


class _DraftsWriteMixin:
    """Drafts-resource write methods."""

    async def list_drafts(
        self,
        *,
        q: str | None = None,
        page_token: str | None = None,
        max_results: int | None = None,
    ) -> dict[str, Any]:
        # GET technically, but listed under "write-side" because it is
        # only used by the draft tools (which require
        # gmail.compose scope, not gmail.readonly).
        params: dict[str, Any] = {}
        if q is not None:
            params["q"] = q
        if page_token is not None:
            params["pageToken"] = page_token
        if max_results is not None:
            params["maxResults"] = max_results
        return await self._get("/users/me/drafts", params=params)

    async def create_draft(
        self,
        *,
        raw_message: str,
        thread_id: str | None = None,
    ) -> dict[str, Any]:
        # optional threadId on the Message resource. Gmail's
        # threading docs require ALL of: matching threadId, RFC 2822
        # In-Reply-To/References headers, and matching Subject. Headers
        # and Subject are set during message construction; threadId is
        # the authoritative join Gmail uses when stitching the draft
        # into the existing thread. validate_gmail_id raises ValueError
        # on shape miss; the dispatcher's tool_router translates
        # ValueError into a typed bad_request_error. When thread_id is
        # None the request body must NOT include the key at all so
        # back-compat is preserved (tested in
        # test_create_draft_omits_threadid_when_not_provided).
        message_body: dict[str, Any] = {"raw": raw_message}
        if thread_id is not None:
            message_body["threadId"] = validate_gmail_id(thread_id, field="thread_id")
        return await self._post(
            "/users/me/drafts",
            body={"message": message_body},
        )

    async def update_draft(
        self,
        *,
        draft_id: str,
        raw_message: str,
        thread_id: str | None = None,
    ) -> dict[str, Any]:
        # validate ID before path interpolation.
        draft_id = validate_gmail_id(draft_id, field="draft_id")
        # same thread_id contract as create_draft. Omitted when
        # the caller does not pass one, preserving the prior request
        # shape for every existing call site.
        message_body: dict[str, Any] = {"raw": raw_message}
        if thread_id is not None:
            message_body["threadId"] = validate_gmail_id(thread_id, field="thread_id")
        return await self._put(
            f"/users/me/drafts/{draft_id}",
            body={"message": message_body},
        )

    async def send_draft(self, *, draft_id: str) -> dict[str, Any]:
        # Validate ID even though it goes into a JSON body rather than
        # a path. Defense in depth: we have the validator, the cost is
        # one regex match, and Google's /drafts/send endpoint deserves
        # the same protection as the path-based draft endpoints.
        draft_id = validate_gmail_id(draft_id, field="draft_id")
        return await self._post("/users/me/drafts/send", body={"id": draft_id})

    async def delete_draft(self, *, draft_id: str) -> dict[str, Any]:
        # Validate ID before path interpolation.
        draft_id = validate_gmail_id(draft_id, field="draft_id")
        return await self._delete(f"/users/me/drafts/{draft_id}")
