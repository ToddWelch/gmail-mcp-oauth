"""fanout tools: multi_search_emails, batch_read_emails.

Both tools are convenience wrappers that asyncio.gather N single-shot
Gmail calls under one OAuth token, returning per-query / per-id
records ordered to match the input. Partial-success behaviour matches
the existing get_inbox_with_threads idiom (threads.py line 104 to 108):
each coroutine catches the relevant Gmail / network exceptions and
emits a {error_status, error_message} record so one failed entry does
not abort the whole gather.

Why ordered list, not dict
--------------------------
multi_search_emails: query strings can repeat or contain dict-unsafe
chars (curly braces, colons, whitespace). An ordered list with the
echoed query keeps the record shape self-describing and tolerates
duplicates.

batch_read_emails: every entry already carries its own Gmail `id`,
so the caller can re-key on `id` if needed. Failed entries echo the
requested `message_id` so callers can still identify which id failed.

Schema-layer handles the shape rules; this module enforces handler-
level defense in depth (the layered-validation pattern: schema rejects
shapes that cannot possibly be Gmail values; handler rejects what the
schema might miss). For multi_search_emails the schema sets
maxItems=25 / queries[*]=string-up-to-1000-chars; the handler still
checks list-truthiness and per-query types because schema bypass via
programmatic clients is the documented threat model.

Exception catch
---------------------------
The per-coroutine catch covers GmailApiError (the typed wrapper) AND
httpx.RequestError (the underlying transport seam). gmail_client._request
already translates httpx.HTTPError into GmailApiError(status=0), but
the belt-and-braces httpx.RequestError catch costs nothing and closes
the seam if a future refactor stops doing the translation. Mirrors
threads.py's catch (it catches GmailApiError on the partial-success
path; this module widens to network errors).

Retry-After
-----------------------
On 429 the GmailClient surfaces `retry_after_seconds` on the
GmailApiError. The per-coroutine error record includes it when present
so callers can pace their next batch.
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx

from .errors import bad_request_error
from .gmail_client import GmailApiError, GmailClient


# Caps mirror the schema layer; handler rejection is defense-in-depth.
_MAX_QUERIES_PER_CALL = 25
_MAX_MESSAGE_IDS_PER_CALL = 100

# Default Gmail metadata headers when format=metadata and the caller
# omits metadata_headers . Passing None to Gmail yields a
# headers-less metadata response, which is rarely what the caller
# wants for the morning-sweep workflow.
_DEFAULT_METADATA_HEADERS: tuple[str, ...] = ("From", "Subject", "Date")


def _make_error_record(
    *,
    label_key: str,
    label_value: str,
    exc: BaseException,
) -> dict[str, Any]:
    """Build a per-entry error record from a caught exception.

    Mirrors threads.get_inbox_with_threads's per-thread error_status
    pattern. Retry-After flows through when the underlying
    GmailApiError exposes it (429s).
    """
    record: dict[str, Any] = {label_key: label_value}
    if isinstance(exc, GmailApiError):
        record["error_status"] = exc.status
        record["error_message"] = str(exc)
        if exc.retry_after_seconds is not None:
            record["retry_after_seconds"] = exc.retry_after_seconds
    elif isinstance(exc, httpx.RequestError):
        # Network-layer error not yet translated to GmailApiError.
        # In practice gmail_client._request wraps httpx.HTTPError into
        # GmailApiError(status=0); this branch closes the seam if a
        # future refactor leaks the raw transport exception.
        record["error_status"] = 0
        record["error_message"] = f"network error: {exc}"
    elif isinstance(exc, ValueError):
        # validate_gmail_id raises ValueError for shape mismatches.
        # Per-id rejection rather than aborting the whole batch keeps
        # behaviour consistent with the partial-success contract.
        record["error_status"] = -1
        record["error_message"] = str(exc)
    else:
        record["error_status"] = -1
        record["error_message"] = repr(exc)
    return record


# ---------------------------------------------------------------------------
# Tool: multi_search_emails
# ---------------------------------------------------------------------------


async def multi_search_emails(
    *,
    client: GmailClient,
    queries: list[str],
    max_results_per_query: int | None = None,
    label_ids: list[str] | None = None,
) -> dict[str, Any]:
    """Run N Gmail searches concurrently. Returns per-query results.

    Defense-in-depth checks (the schema layer is the primary gate but
    programmatic clients can bypass it):

    - queries must be a non-empty list (schema: minItems=1).
    - queries length capped at 25 (schema: maxItems=25).

    Returns shape:
        {"results": [
            {"query": "<echoed>", "messages": [...],
             "next_page_token": ..., "result_size_estimate": N},
            {"query": "<echoed>", "error_status": 429, "error_message": "..."},
            ...
        ]}
    """
    if not queries:
        return bad_request_error("queries must be a non-empty list")
    if len(queries) > _MAX_QUERIES_PER_CALL:
        return bad_request_error(f"queries exceeds per-call cap of {_MAX_QUERIES_PER_CALL} entries")

    async def _one(q: str) -> dict[str, Any]:
        try:
            resp = await client.list_messages(
                q=q,
                label_ids=label_ids,
                max_results=max_results_per_query,
            )
        except (GmailApiError, httpx.RequestError, ValueError) as exc:
            return _make_error_record(label_key="query", label_value=q, exc=exc)
        return {
            "query": q,
            "messages": resp.get("messages", []) or [],
            "next_page_token": resp.get("nextPageToken"),
            "result_size_estimate": resp.get("resultSizeEstimate"),
        }

    # asyncio.gather preserves input order in the result list. We do
    # NOT pass return_exceptions=True because each coroutine already
    # catches every exception of interest and returns an error record.
    # An unexpected exception (BaseException-derived) would still
    # propagate, which is the right behaviour for things like
    # KeyboardInterrupt or asyncio.CancelledError.
    results = await asyncio.gather(*(_one(q) for q in queries))
    return {"results": list(results)}


# ---------------------------------------------------------------------------
# Tool: batch_read_emails
# ---------------------------------------------------------------------------


async def batch_read_emails(
    *,
    client: GmailClient,
    message_ids: list[str],
    format: str = "metadata",
    metadata_headers: list[str] | None = None,
) -> dict[str, Any]:
    """Fetch N messages concurrently. Returns per-id metadata or minimal records.

    format must be 'metadata' or 'minimal'. 'full' and 'raw' are
    intentionally excluded (the schema enum enforces this; handler
    re-checks for defense-in-depth).

    metadata_headers default `['From', 'Subject', 'Date']` is applied
    when the caller omits the field . Passing None to the
    underlying Gmail get_message would yield headers-less metadata,
    which is rarely the desired morning-sweep behaviour.

    Returns shape:
        {"messages": [
            {"id": "...", "threadId": "...", "labelIds": [...], "snippet": "...", ...},
            {"message_id": "<requested>", "error_status": 404, "error_message": "..."},
            ...
        ]}
    """
    if not message_ids:
        return bad_request_error("message_ids must be a non-empty list")
    if len(message_ids) > _MAX_MESSAGE_IDS_PER_CALL:
        return bad_request_error(
            f"message_ids exceeds per-call cap of {_MAX_MESSAGE_IDS_PER_CALL} entries"
        )
    if format not in ("metadata", "minimal"):
        return bad_request_error(f"format must be one of metadata|minimal, got {format!r}")

    # apply default when caller omitted the field.
    effective_headers: list[str] | None
    if metadata_headers is None:
        effective_headers = list(_DEFAULT_METADATA_HEADERS) if format == "metadata" else None
    else:
        effective_headers = metadata_headers

    async def _one(mid: str) -> dict[str, Any]:
        try:
            return await client.get_message(
                message_id=mid,
                format=format,
                metadata_headers=effective_headers if format == "metadata" else None,
            )
        except (GmailApiError, httpx.RequestError, ValueError) as exc:
            return _make_error_record(label_key="message_id", label_value=mid, exc=exc)

    results = await asyncio.gather(*(_one(m) for m in message_ids))
    return {"messages": list(results)}
