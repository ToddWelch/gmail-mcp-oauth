"""Read-side filter tools: list_filters, get_filter.

Filter create/delete are concerns and live in the write side
of GmailClient. This module exposes the read-side list/get.
"""

from __future__ import annotations

from typing import Any

from .errors import not_found_error
from .gmail_client import GmailApiError, GmailClient


async def list_filters(*, client: GmailClient) -> dict[str, Any]:
    """List every Gmail filter on the linked mailbox.

    Returns Gmail's `users.settings.filters.list` response verbatim.
    Each filter has `id`, `criteria` (matching rules), `action` (label
    add/remove, archive, mark important, etc).
    """
    return await client.list_filters()


async def get_filter(
    *,
    client: GmailClient,
    filter_id: str,
) -> dict[str, Any]:
    """Return one filter by ID, or a 404-flavored not_found error."""
    try:
        return await client.get_filter(filter_id=filter_id)
    except GmailApiError as exc:
        if exc.status == 404:
            return not_found_error(f"filter not found: {filter_id}")
        raise
