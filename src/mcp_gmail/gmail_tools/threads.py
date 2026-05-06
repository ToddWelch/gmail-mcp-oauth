"""Thread tools: get_thread, list_inbox_threads, get_inbox_with_threads, modify_thread.

Three pure-read tools and one borderline (modify_thread, which
requires gmail.modify scope but is grouped with read tools per the
read/write split because its result shape mirrors the read side).

get_inbox_with_threads is a convenience tool: list inbox threads,
then expand each into a one-call summary (subject, last sender,
snippet). Implemented by listing threads with INBOX label, then
fetching each thread by ID with format='metadata'. The N+1 round-trip
is acceptable for inbox-sized counts (typically 25-50 threads); a
caller who wants raw thread IDs without the expansion uses
list_inbox_threads instead.
"""

from __future__ import annotations

from typing import Any

from .errors import not_found_error
from .gmail_client import GmailApiError, GmailClient


# Default page size for inbox listings. Mirrors Gmail's default of 100
# but trimmed because the convenience expansion in
# get_inbox_with_threads is N+1 round trips.
_INBOX_DEFAULT_PAGE_SIZE = 25


# ---------------------------------------------------------------------------
# Tool: get_thread
# ---------------------------------------------------------------------------


async def get_thread(
    *,
    client: GmailClient,
    thread_id: str,
    format: str = "full",
) -> dict[str, Any]:
    """Return one thread by ID with all its messages."""
    try:
        return await client.get_thread(thread_id=thread_id, format=format)
    except GmailApiError as exc:
        if exc.status == 404:
            return not_found_error(f"thread not found: {thread_id}")
        raise


# ---------------------------------------------------------------------------
# Tool: list_inbox_threads
# ---------------------------------------------------------------------------


async def list_inbox_threads(
    *,
    client: GmailClient,
    page_token: str | None = None,
    max_results: int | None = None,
) -> dict[str, Any]:
    """List INBOX-labelled threads (no expansion, just IDs).

    Returns Gmail's `users.threads.list` result verbatim, scoped to the
    INBOX system label. Caller follows up per thread ID via get_thread
    for full content.
    """
    return await client.list_threads(
        label_ids=["INBOX"],
        page_token=page_token,
        max_results=max_results,
    )


# ---------------------------------------------------------------------------
# Tool: get_inbox_with_threads
# ---------------------------------------------------------------------------


async def get_inbox_with_threads(
    *,
    client: GmailClient,
    max_results: int | None = None,
) -> dict[str, Any]:
    """List INBOX threads and expand each into a metadata summary.

    For each thread, fetch with format='metadata' (returns headers and
    snippet, no body). Result is a list of dicts with `thread_id`,
    `subject`, `from_addr`, `snippet`, `message_count`, `last_message_id`.

    Caller-facing convenience for "give me the inbox at a glance"
    workflow without making the model call read_email N times.
    """
    page_size = max_results or _INBOX_DEFAULT_PAGE_SIZE
    listing = await client.list_threads(label_ids=["INBOX"], max_results=page_size)
    thread_stubs = listing.get("threads", []) or []

    summaries: list[dict[str, Any]] = []
    for stub in thread_stubs:
        tid = stub.get("id")
        if not tid:
            continue
        try:
            thread = await client.get_thread(thread_id=tid, format="metadata")
        except GmailApiError as exc:
            # Skip individual fetch failures rather than aborting the
            # whole inbox listing. Surface the failed thread id so the
            # caller can investigate.
            summaries.append({"thread_id": tid, "error_status": exc.status})
            continue
        summaries.append(_summarize_thread(thread))

    return {
        "threads": summaries,
        "next_page_token": listing.get("nextPageToken"),
        "result_size_estimate": listing.get("resultSizeEstimate"),
    }


def _summarize_thread(thread: dict[str, Any]) -> dict[str, Any]:
    """Pull thread_id, subject, from, snippet from a metadata-format thread."""
    messages = thread.get("messages", []) or []
    out: dict[str, Any] = {
        "thread_id": thread.get("id"),
        "message_count": len(messages),
        "subject": None,
        "from_addr": None,
        "snippet": None,
        "last_message_id": None,
    }
    if not messages:
        return out
    last = messages[-1]
    out["last_message_id"] = last.get("id")
    out["snippet"] = last.get("snippet")
    headers = (last.get("payload") or {}).get("headers") or []
    for h in headers:
        name = (h.get("name") or "").lower()
        if name == "subject" and out["subject"] is None:
            out["subject"] = h.get("value")
        elif name == "from" and out["from_addr"] is None:
            out["from_addr"] = h.get("value")
    return out


# ---------------------------------------------------------------------------
# Tool: modify_thread
# ---------------------------------------------------------------------------


async def modify_thread(
    *,
    client: GmailClient,
    thread_id: str,
    add_label_ids: list[str] | None = None,
    remove_label_ids: list[str] | None = None,
) -> dict[str, Any]:
    """Add and/or remove labels on a thread.

    Requires gmail.modify scope (TOOL_SCOPE_REQUIREMENTS enforces
    this). Returns the updated thread metadata from Gmail.

    No-op detection: if both lists are empty/None, we still call
    Gmail's modify endpoint with an empty body. Gmail accepts this and
    returns the unchanged thread. We could short-circuit, but doing so
    would mask caller bugs (e.g. forgetting to populate the lists)
    while saving one HTTP round trip. The audit log line is still
    valuable here.
    """
    try:
        return await client.modify_thread(
            thread_id=thread_id,
            add_label_ids=add_label_ids,
            remove_label_ids=remove_label_ids,
        )
    except GmailApiError as exc:
        if exc.status == 404:
            return not_found_error(f"thread not found: {thread_id}")
        raise
