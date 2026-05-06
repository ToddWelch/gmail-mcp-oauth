"""Messages-resource write methods for GmailClient.

Covers send, trash, delete (permanent), batch_delete, batch_modify,
and modify on `/users/me/messages`. Also colocates `get_user_profile`
because it is a GET that is consumed only by the write-side
`reply_all` tool; keeping the read-side client surface
(gmail_client.py) limited to the read tools' actual upstream calls
makes the read-only audit story tighter.
"""

from __future__ import annotations

from typing import Any

from ..gmail_id import validate_gmail_id


class _MessagesWriteMixin:
    """Messages-resource write methods (and the profile GET used by reply)."""

    # ---- read: profile ------------------------------------------------------

    async def get_user_profile(self) -> dict[str, Any]:
        # GET /users/me/profile. Returns the linked mailbox's
        # `emailAddress`, `messagesTotal`, `threadsTotal`, `historyId`.
        # Used by reply_all to identify which address counts as
        # "self" so it can be filtered out of the expanded To+Cc set.
        # Listed under the write mixin (despite being a GET) because it
        # is only consumed by write-side tools; keeping the read-side
        # client surface (gmail_client.py) limited to the read tools'
        # actual upstream calls makes the read-only audit story tighter.
        return await self._get("/users/me/profile")

    # ---- write: messages ----------------------------------------------------

    async def send_message(self, *, raw_message: str) -> dict[str, Any]:
        return await self._post(
            "/users/me/messages/send",
            body={"raw": raw_message},
        )

    async def trash_message(self, *, message_id: str) -> dict[str, Any]:
        # gmail.modify scope: recoverable. Used by the `delete_email`
        # tool when the trash-semantics path is chosen.
        # Validate ID before path interpolation.
        message_id = validate_gmail_id(message_id, field="message_id")
        return await self._post(
            f"/users/me/messages/{message_id}/trash",
            body={},
        )

    async def delete_message(self, *, message_id: str) -> dict[str, Any]:
        # Not exposed by default; see TRASH-vs-permanent-delete decision
        # in docs/GMAIL_MCP_TOOLS.md.
        # mail.google.com/ scope: PERMANENT. Not used unless the operator
        # explicitly opts into hard-delete semantics. See the
        # TRASH-vs-permanent discussion in scope_check.py.
        # Validate ID before path interpolation.
        message_id = validate_gmail_id(message_id, field="message_id")
        return await self._delete(f"/users/me/messages/{message_id}")

    async def batch_delete_messages(self, *, message_ids: list[str]) -> dict[str, Any]:
        # Not exposed by default; see TRASH-vs-permanent-delete decision
        # in docs/GMAIL_MCP_TOOLS.md.
        # mail.google.com/ scope: PERMANENT batch. Same TRASH-vs-permanent caveat.
        #
        # This method is the raw Gmail batchDelete endpoint (permanent).
        # The user-facing `batch_delete_emails` tool intentionally does
        # NOT call this; it uses batch_modify_messages with
        # addLabelIds=['TRASH'] for trash semantics (recoverable,
        # gmail.modify scope). This method is left dormant on the mixin
        # so a future change can flip the tool to hard-delete by
        # changing only the tool wiring, not the client surface.
        # Validate every ID in the JSON body before the request is sent.
        validated_ids = [
            validate_gmail_id(mid, field=f"message_ids[{i}]") for i, mid in enumerate(message_ids)
        ]
        return await self._post(
            "/users/me/messages/batchDelete",
            body={"ids": validated_ids},
        )

    async def batch_modify_messages(
        self,
        *,
        message_ids: list[str],
        add_label_ids: list[str] | None = None,
        remove_label_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        # gmail.modify scope: bulk add/remove labels across up to 1000
        # messages in one Gmail call. The user-facing tool layer uses
        # this for the `batch_delete_emails` tool (with
        # addLabelIds=['TRASH']) to implement recoverable bulk-trash
        # semantics. Gmail returns 204 on success; the client surface
        # returns {} for empty bodies.
        # Validate every message ID and every label ID. Critical: the
        # validation pattern is the LOOSER 1..256 char range so system
        # labels like 'INBOX', 'TRASH', 'UNREAD' (4-7 chars) pass. The
        # 16..128 char audit heuristic is intentionally NOT used here;
        # that band would reject the batch_delete_emails flow which
        # posts addLabelIds=['TRASH']. Regression-guarded by
        # test_batch_modify_accepts_trash_in_add_label_ids.
        validated_ids = [
            validate_gmail_id(mid, field=f"message_ids[{i}]") for i, mid in enumerate(message_ids)
        ]
        body: dict[str, Any] = {"ids": validated_ids}
        if add_label_ids:
            body["addLabelIds"] = [
                validate_gmail_id(lid, field=f"add_label_ids[{i}]")
                for i, lid in enumerate(add_label_ids)
            ]
        if remove_label_ids:
            body["removeLabelIds"] = [
                validate_gmail_id(lid, field=f"remove_label_ids[{i}]")
                for i, lid in enumerate(remove_label_ids)
            ]
        return await self._post(
            "/users/me/messages/batchModify",
            body=body,
        )

    async def modify_message(
        self,
        *,
        message_id: str,
        add_label_ids: list[str] | None = None,
        remove_label_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        # validate ID before path interpolation, plus all
        # label IDs in the JSON body.
        message_id = validate_gmail_id(message_id, field="message_id")
        body: dict[str, Any] = {}
        if add_label_ids:
            body["addLabelIds"] = [
                validate_gmail_id(lid, field=f"add_label_ids[{i}]")
                for i, lid in enumerate(add_label_ids)
            ]
        if remove_label_ids:
            body["removeLabelIds"] = [
                validate_gmail_id(lid, field=f"remove_label_ids[{i}]")
                for i, lid in enumerate(remove_label_ids)
            ]
        return await self._post(
            f"/users/me/messages/{message_id}/modify",
            body=body,
        )
