"""Write-side filter tools: create_filter, delete_filter.

Both require gmail.settings.basic scope (per scope_check.py). They
map to Gmail's users.settings.filters API:

    POST   /users/me/settings/filters         -> create
    DELETE /users/me/settings/filters/{id}    -> delete

Note Gmail's filter API does not expose a PUT/PATCH endpoint; updates
are done by deleting and recreating. the service ships create + delete only;
a higher-level "update_filter" convenience tool would be a follow-up
since it cannot be a single Gmail call.

Body shape
----------
Gmail's filter body is two nested dicts: `criteria` and `action`.

    {
      "criteria": {
        "from": "...",                # optional
        "to": "...",                  # optional
        "subject": "...",             # optional
        "query": "...",               # Gmail search syntax, optional
        "negatedQuery": "...",        # optional
        "hasAttachment": bool,        # optional
        "excludeChats": bool,         # optional
        "size": int,                  # optional, in bytes
        "sizeComparison": "larger"|"smaller"
      },
      "action": {
        "addLabelIds": [...],         # optional
        "removeLabelIds": [...],      # optional
        "forward": "...@example.com"  # optional, must be a verified
                                      # forwarding address Gmail knows
                                      # about for the mailbox
      }
    }

We pass `criteria` and `action` through verbatim as opaque dicts. The
JSON Schema in tool_definitions.py loosely constrains them (object
type, no extra prop checks); Gmail validates shape on the server and
returns clear errors. Replicating Gmail's full validation here would
be both a maintenance burden and a divergence risk.
"""

from __future__ import annotations

from typing import Any

from .errors import bad_request_error, not_found_error
from .filter_templates import build_filter_body_from_template
from .gmail_client import GmailApiError, GmailClient


# ---------------------------------------------------------------------------
# Tool: create_filter
# ---------------------------------------------------------------------------


async def create_filter(
    *,
    client: GmailClient,
    criteria: dict[str, Any],
    action: dict[str, Any],
) -> dict[str, Any]:
    """Create a Gmail settings filter.

    `criteria` is the matching rule set, `action` is what to do with
    matching messages. Both must be objects (validated server-side
    by Gmail; we additionally reject obviously-wrong types here so a
    misuse like `criteria=None` fails fast with bad_request rather
    than a Gmail 400 round trip).

    empty `criteria={}` AND empty `action={}` are
    rejected before the Gmail call. An empty-criteria filter would
    match every incoming message, and an empty-action filter is a
    no-op; both shapes are foot-guns Gmail historically accepts and
    silently no-ops or, worse, persists into the user's filter list.
    Reject at the tool boundary so a caller bug never reaches Gmail.

    The filter applies to NEW incoming mail going forward; existing
    messages are not touched. Returns the full filter record including
    the assigned `id`.
    """
    if not isinstance(criteria, dict):
        return bad_request_error("criteria must be an object")
    if not isinstance(action, dict):
        return bad_request_error("action must be an object")
    if not criteria:
        return bad_request_error("criteria must contain at least one field")
    if not action:
        return bad_request_error("action must contain at least one field")
    body = {"criteria": criteria, "action": action}
    return await client.create_filter(body=body)


# ---------------------------------------------------------------------------
# Tool: create_filter_from_template
# ---------------------------------------------------------------------------


async def create_filter_from_template(
    *,
    client: GmailClient,
    template: str,
    sender_email: str | None = None,
    query: str | None = None,
    label_id: str | None = None,
) -> dict[str, Any]:
    """Create a Gmail filter using a named template.

    Templates are defined in `filter_templates.py`. This tool is a
    thin convenience over `create_filter`: it calls
    `build_filter_body_from_template` to assemble the criteria + action
    pair, then forwards to Gmail.

    Foot-gun mitigations live in
    `build_filter_body_from_template`. This wrapper short-circuits on
    any bad_request_error returned from the builder so no Gmail call
    is made for malformed inputs.
    """
    body_or_error = build_filter_body_from_template(
        template=template,
        sender_email=sender_email,
        query=query,
        label_id=label_id,
    )
    # The builder returns an error dict on bad input; pass through.
    if "code" in body_or_error and isinstance(body_or_error.get("code"), int):
        return body_or_error
    return await client.create_filter(body=body_or_error)


# ---------------------------------------------------------------------------
# Tool: delete_filter
# ---------------------------------------------------------------------------


async def delete_filter(
    *,
    client: GmailClient,
    filter_id: str,
) -> dict[str, Any]:
    """Delete a Gmail filter by ID.

    Filters do not get re-applied retroactively, so deleting a filter
    only stops it matching new mail; it does not undo prior labels or
    moves. Gmail returns 204 on success.
    """
    try:
        return await client.delete_filter(filter_id=filter_id)
    except GmailApiError as exc:
        if exc.status == 404:
            return not_found_error(f"filter not found: {filter_id}")
        raise
