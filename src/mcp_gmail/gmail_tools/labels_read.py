"""Read-side label tools: list_email_labels.

Label create/update/delete are concerns and live in the write
side of GmailClient. This module exposes only the listing read.
"""

from __future__ import annotations

from typing import Any

from .gmail_client import GmailClient


async def list_email_labels(*, client: GmailClient) -> dict[str, Any]:
    """List every label on the linked mailbox.

    Returns Gmail's `users.labels.list` response verbatim. Each label
    has `id`, `name`, `type` (system|user), and `messageListVisibility`
    / `labelListVisibility` flags.
    """
    return await client.list_labels()
