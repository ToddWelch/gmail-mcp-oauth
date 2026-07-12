"""Read-side message tools: read_email, search_emails, download_attachment, download_email.

Each function takes a GmailClient instance and tool arguments, returns
a JSON-serializable dict. No HTTP transport details bleed into the tool
layer; that is the GmailClient's job. No DB session is opened here; the
dispatcher owns the session boundary.

Output shape
------------
Every tool returns a plain dict that JSON-serializes cleanly. Results
mirror the relevant Gmail API response shape with two adjustments:

1. We do NOT echo the user-supplied query, subject, or body in the
   response if the caller didn't already have it. Gmail's response
   already contains everything we want to return; passing through is
   safe.
2. Attachment data (download_attachment, download_email) is returned
   as base64url since that is what Gmail returns to us. The caller
   decodes if they need binary bytes. download_attachment wraps the
   raw Gmail attachment payload in an enriched object
   ({filename, mime_type, size, data}) and lives in
   attachment_download.py (split out under the 300-LOC /
   distinct-responsibility rule); see
   attachment_download.download_attachment for the formal output
   contract and the three selection modes.

Audit log
---------
Each function does NOT call audit() directly. The dispatcher does so
on outcome. Doing it here would either duplicate the call or force the
dispatcher to skip its own (and lose the cross-cutting outcome shape).
This module's responsibility is "make the call, return the dict";
audit happens at the dispatch boundary.
"""

from __future__ import annotations

from typing import Any

from .attachment_download import download_attachment
from .errors import bad_request_error, not_found_error
from .gmail_client import GmailApiError, GmailClient
from .message_text import extract_lean_message

# download_attachment lives in attachment_download.py (split out under
# the 300-LOC / distinct-responsibility rule). Re-exported here so the
# router's `messages.download_attachment` reference and existing test
# imports keep resolving unchanged.
__all__ = [
    "read_email",
    "search_emails",
    "download_attachment",
    "download_email",
]


# ---------------------------------------------------------------------------
# Tool: read_email
# ---------------------------------------------------------------------------


async def read_email(
    *,
    client: GmailClient,
    message_id: str,
    format: str = "full",
) -> dict[str, Any]:
    """Return one message by ID. Format defaults to 'full' (Gmail's standard).

    Caller-side: dispatcher validates message_id is a non-empty string.
    Cross-user isolation is by construction: the GmailClient is built
    from a token belonging to a specific (auth0_sub, account_email),
    so the row lookup that produced the access token rejects mismatched
    actors before this function runs.

    format='text' is a token-efficient read for bloated HTML emails:
    Gmail has no 'text' format, so we fetch with 'full' and reduce the
    message to a LEAN object (curated headers + decoded plain-text body
    + attachment metadata) via message_text.extract_lean_message,
    dropping the full payload, HTML part, and inline base64. See
    message_text.py for the body-selection and charset rules.
    """
    if format not in ("full", "metadata", "minimal", "raw", "text"):
        return bad_request_error(
            f"format must be one of full|metadata|minimal|raw|text, got {format!r}"
        )
    # 'text' is server-side sugar: Gmail is always called with 'full',
    # then reduced. Every other format passes straight through.
    gmail_format = "full" if format == "text" else format
    try:
        message = await client.get_message(message_id=message_id, format=gmail_format)
    except GmailApiError as exc:
        if exc.status == 404:
            return not_found_error(f"message not found: {message_id}")
        raise
    if format == "text":
        return extract_lean_message(message)
    return message


# ---------------------------------------------------------------------------
# Tool: search_emails
# ---------------------------------------------------------------------------


async def search_emails(
    *,
    client: GmailClient,
    q: str | None = None,
    label_ids: list[str] | None = None,
    page_token: str | None = None,
    max_results: int | None = None,
) -> dict[str, Any]:
    """Search messages with Gmail's search syntax. Returns the message ID list page.

    Note: Gmail's list endpoint does NOT return message bodies. Each
    item in the result is a stub with `id` and `threadId`. The caller
    is expected to follow up with read_email per ID for full content.
    """
    return await client.list_messages(
        q=q,
        label_ids=label_ids,
        page_token=page_token,
        max_results=max_results,
    )


# ---------------------------------------------------------------------------
# Tool: download_email
# ---------------------------------------------------------------------------


async def download_email(
    *,
    client: GmailClient,
    message_id: str,
) -> dict[str, Any]:
    """Return the full RFC 5322 raw bytes of a message, base64url-encoded.

    Calls get_message with format='raw'. Gmail returns a payload
    containing a `raw` field that is base64url-encoded RFC 822 bytes.
    The caller decodes if they want the .eml file content.

    Returned shape (Gmail's standard):
        {
            "id": "...",
            "threadId": "...",
            "labelIds": [...],
            "snippet": "...",
            "raw": "<base64url-encoded RFC 822 bytes>"
        }
    """
    try:
        return await client.get_message(message_id=message_id, format="raw")
    except GmailApiError as exc:
        if exc.status == 404:
            return not_found_error(f"message not found: {message_id}")
        raise
