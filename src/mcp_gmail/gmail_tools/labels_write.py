"""Write-side label tools: create_label, update_label, delete_label.

All three require gmail.modify scope (per scope_check.py). They map
1:1 to Gmail's users.labels API:

    POST   /users/me/labels             -> create
    PUT    /users/me/labels/{id}        -> update
    DELETE /users/me/labels/{id}        -> delete

Body shape decisions
--------------------
Gmail's create/update bodies are flat dicts with optional fields:

    name                                 (required on create)
    labelListVisibility                  ("labelShow" | "labelHide" | "labelShowIfUnread")
    messageListVisibility                ("show" | "hide")
    color                                ({"backgroundColor": "#...", "textColor": "#..."})

The tool layer accepts these as named arguments and assembles the body
dict, omitting fields the caller didn't pass. The JSON Schema in
tool_definitions.py constrains the inputs. We do NOT try to validate
hex color strings here; Gmail returns 400 with a clear message if the
value is malformed, and replicating Gmail's validation rules is
brittle.

Update vs partial update
------------------------
Gmail offers both PUT (full update) and PATCH (partial update) on
labels. We use PUT because the tool surface accepts only the fields
the caller wants to change and our update body sends just those
fields, which Gmail's PUT accepts. PATCH would be slightly more
correct semantically but would require negotiating which fields the
caller wanted to touch versus which were absent intentionally; PUT
plus the omit-on-None convention is simpler and matches the read-side
pattern (Gmail's read returns the same flat shape).
"""

from __future__ import annotations

from typing import Any

from .errors import bad_request_error, not_found_error
from .gmail_client import GmailApiError, GmailClient


# Gmail's documented label-name display-length cap. Counted in CHARACTERS
# (Python `len()` on str), not bytes. A 226-char name with all-ASCII is
# rejected; a 225-char name with multi-byte glyphs (e.g. "é") is also
# 225 chars and accepted, even though it weighs more in UTF-8 bytes.
_LABEL_NAME_MAX_CHARS = 225


def _build_label_body(
    *,
    name: str | None,
    label_list_visibility: str | None,
    message_list_visibility: str | None,
    color: dict[str, Any] | None,
) -> dict[str, Any]:
    """Assemble the Gmail label body dict, omitting None values.

    Centralized so create_label and update_label produce identical
    field shapes for the same caller input. Gmail tolerates extra
    fields but rejects malformed enum values, so we only set keys the
    caller actually populated.
    """
    body: dict[str, Any] = {}
    if name is not None:
        body["name"] = name
    if label_list_visibility is not None:
        body["labelListVisibility"] = label_list_visibility
    if message_list_visibility is not None:
        body["messageListVisibility"] = message_list_visibility
    if color is not None:
        body["color"] = color
    return body


# ---------------------------------------------------------------------------
# Tool: create_label
# ---------------------------------------------------------------------------


async def create_label(
    *,
    client: GmailClient,
    name: str,
    label_list_visibility: str | None = None,
    message_list_visibility: str | None = None,
    color: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Create a new user label.

    `name` is required by Gmail. The other three fields are optional
    and Gmail picks sensible defaults (labelShow / show / no color)
    when omitted. Returns Gmail's response body, which is the full
    label record including the assigned `id`.

    `name` is rejected before the Gmail call when
    it exceeds Gmail's documented 225-character display-length cap.
    The check is in CHARS (Python `len()`), not bytes; Gmail's limit
    is on display length, so multi-byte glyphs (e.g. "é") count as
    one character even though they weigh two bytes in UTF-8.
    """
    if len(name) > _LABEL_NAME_MAX_CHARS:
        return bad_request_error(
            f"label name exceeds Gmail's {_LABEL_NAME_MAX_CHARS}-character limit: {len(name)} chars"
        )
    body = _build_label_body(
        name=name,
        label_list_visibility=label_list_visibility,
        message_list_visibility=message_list_visibility,
        color=color,
    )
    return await client.create_label(body=body)


# ---------------------------------------------------------------------------
# Tool: update_label
# ---------------------------------------------------------------------------


async def update_label(
    *,
    client: GmailClient,
    label_id: str,
    name: str | None = None,
    label_list_visibility: str | None = None,
    message_list_visibility: str | None = None,
    color: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Update an existing label by ID.

    All body fields are optional individually; the caller supplies the
    ones they want to change. System labels (INBOX, SENT, etc.) cannot
    be renamed; Gmail returns 400 in that case.

    On 404, returns not_found_error so the dispatcher can record the
    canonical error shape.

    Symmetry with create_label: when `name` is provided, the same
    225-character display-length cap is enforced before the Gmail call.
    `name=None` (color-only or visibility-only updates) skips the
    check, which preserves the existing behavior where update_label
    accepts a partial body.
    """
    if name is not None and len(name) > _LABEL_NAME_MAX_CHARS:
        return bad_request_error(
            f"label name exceeds Gmail's {_LABEL_NAME_MAX_CHARS}-character limit: {len(name)} chars"
        )
    body = _build_label_body(
        name=name,
        label_list_visibility=label_list_visibility,
        message_list_visibility=message_list_visibility,
        color=color,
    )
    try:
        return await client.update_label(label_id=label_id, body=body)
    except GmailApiError as exc:
        if exc.status == 404:
            return not_found_error(f"label not found: {label_id}")
        raise


# ---------------------------------------------------------------------------
# Tool: get_or_create_label
# ---------------------------------------------------------------------------


async def get_or_create_label(
    *,
    client: GmailClient,
    name: str,
    label_list_visibility: str | None = None,
    message_list_visibility: str | None = None,
    color: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return the existing label with `name`, or create one if missing.

    Two-step: list labels, find by exact-name match, return that
    record if present; otherwise create a new label and return Gmail's
    response.

    TOCTOU and case-sensitivity caveats (per):
    - A race exists between the list call and the create call. If
      another caller (or a concurrent Apps Script automation) creates
      the label after our list returned no match but before our
      create lands, Gmail returns a 409-style duplicate-name error
      from the create. We surface that error rather than retrying
      the list (the retry would race again).
    - Name matching is case-sensitive per Gmail's behavior.
      "Important" and "important" are distinct labels in Gmail's
      catalog and this tool treats them as such.
    """
    listing = await client.list_labels()
    existing = listing.get("labels") if isinstance(listing, dict) else None
    if isinstance(existing, list):
        for entry in existing:
            if not isinstance(entry, dict):
                continue
            if entry.get("name") == name:
                # Case-sensitive exact match per Gmail. Return the
                # listing entry verbatim; callers may need the system
                # / user `type` field and the visibility flags.
                return dict(entry)

    # No match -> create. If a concurrent caller raced us in here,
    # Gmail will reject with a duplicate-name 409 from the create
    # call; that error propagates.
    return await create_label(
        client=client,
        name=name,
        label_list_visibility=label_list_visibility,
        message_list_visibility=message_list_visibility,
        color=color,
    )


# ---------------------------------------------------------------------------
# Tool: delete_label
# ---------------------------------------------------------------------------


async def delete_label(
    *,
    client: GmailClient,
    label_id: str,
) -> dict[str, Any]:
    """Delete a user label by ID.

    System labels cannot be deleted; Gmail returns 400. Deleting a
    user label removes it from every message and thread that carried
    it; messages themselves remain in place. Gmail returns 204 on
    success; the GmailClient renders that as `{}`.
    """
    try:
        return await client.delete_label(label_id=label_id)
    except GmailApiError as exc:
        if exc.status == 404:
            return not_found_error(f"label not found: {label_id}")
        raise
