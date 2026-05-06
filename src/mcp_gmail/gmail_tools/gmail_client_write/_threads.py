"""Threads-resource write methods for GmailClient.

Currently a single method (`modify_thread`); kept in its own module
because thread-level operations are a distinct Gmail resource and
sized for thread-level methods if they land later.
"""

from __future__ import annotations

from typing import Any

from ..gmail_id import validate_gmail_id


class _ThreadsWriteMixin:
    """Threads-resource write methods."""

    async def modify_thread(
        self,
        *,
        thread_id: str,
        add_label_ids: list[str] | None = None,
        remove_label_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        # This method is used via the modify_thread read-side tool.
        # It is grouped with read tools because its result mirrors a
        # thread read, but the underlying Gmail call requires
        # gmail.modify scope.
        # validate ID before path interpolation, plus all
        # label IDs in the JSON body.
        thread_id = validate_gmail_id(thread_id, field="thread_id")
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
            f"/users/me/threads/{thread_id}/modify",
            body=body,
        )
