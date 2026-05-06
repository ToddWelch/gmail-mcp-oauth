"""Filter-template builder for create_filter_from_template.

Gmail filter bodies are two nested dicts (`criteria` and `action`).
Most callers use a small handful of stable shapes (auto-archive a
sender, label mail matching a query, label mail from a sender).
the create_filter_from_template tool exposes those common shapes
as named templates so callers do not have to hand-roll the body.

What each template does and what it does NOT do
-----------------------------------------------
- `auto_archive_sender`: matches a literal `from:<email>` filter and
  removes the INBOX label on match. For domain-wide matching (e.g.
  anything from `@spam.com`), use `auto_label_from_keyword` with
  `from:*@spam.com` query syntax.

- `auto_label_from_keyword`: matches arbitrary Gmail query syntax
  supplied by the caller. Caller is responsible for query
  correctness; over-broad queries label every future message. Per
  the cleanup-tools design (foot-gun B2), the builder rejects empty / whitespace-only
  / single-character queries before they are sent to Gmail. The
  caller must explicitly opt in to a non-trivial query.

- `auto_label_sender`: matches a literal `from:<email>` filter and
  adds a label. Functionally equivalent to `auto_label_from_keyword`
  with a `from:` query, exposed separately because the
  email-address-only case is by far the most common and giving it a
  named template makes intent more discoverable in tool listings.

Foot-gun mitigations (blocker B2)
---------------------------------------
- Empty or whitespace-only `query` -> bad_request_error (caller bug).
- Single-character `query` -> bad_request_error (overly broad).
- Empty / malformed sender_email on the sender templates ->
  bad_request_error.
- Caller-supplied `label_id` or `sender_email` is passed verbatim to
  Gmail; we do not over-validate (Gmail rejects malformed addresses
  with a clear 400) but we do reject obvious empties.

Note: This module produces the criteria + action body. The actual
Gmail HTTP call lives in filters_write.create_filter_from_template,
which calls into the GmailClient.
"""

from __future__ import annotations

from typing import Any

from .errors import bad_request_error


# Minimum length for a free-form Gmail query string. Below this we
# treat the query as a likely caller bug or an over-broad pattern that
# would label every future message. The threshold of 2 was chosen
# because no useful Gmail query operator + value is shorter than that
# (e.g. `is:starred` is 10, `from:x@y.z` is 11).
_MIN_QUERY_LENGTH = 2


# Public template names. Listed as a tuple (not a dict) so the order
# is stable for tool-listing introspection.
TEMPLATE_NAMES: tuple[str, ...] = (
    "auto_archive_sender",
    "auto_label_from_keyword",
    "auto_label_sender",
)


def build_filter_body_from_template(
    *,
    template: str,
    sender_email: str | None = None,
    query: str | None = None,
    label_id: str | None = None,
) -> dict[str, Any]:
    """Build the Gmail filter body (criteria + action) for `template`.

    Returns either:
      - A 2-key dict {"criteria": {...}, "action": {...}} ready to POST
        to /users/me/settings/filters.
      - A bad_request_error dict on caller-side validation failure.

    Validation rules (B2, foot-gun mitigation):
      - Unknown template name -> bad_request_error.
      - auto_archive_sender / auto_label_sender: sender_email must be
        a non-empty string.
      - auto_label_sender / auto_label_from_keyword: label_id must be
        a non-empty string.
      - auto_label_from_keyword: query must be a non-empty string of
        at least _MIN_QUERY_LENGTH non-whitespace characters. Empty
        and whitespace-only queries are rejected explicitly because
        Gmail accepts them and silently labels every future message.
    """
    if template not in TEMPLATE_NAMES:
        return bad_request_error(
            f"unknown template: {template!r}; expected one of {list(TEMPLATE_NAMES)}"
        )

    if template == "auto_archive_sender":
        if not isinstance(sender_email, str) or not sender_email.strip():
            return bad_request_error("sender_email is required for auto_archive_sender")
        return {
            "criteria": {"from": sender_email.strip()},
            # INBOX is a label; removing it is how Gmail spells "archive".
            "action": {"removeLabelIds": ["INBOX"]},
        }

    if template == "auto_label_sender":
        if not isinstance(sender_email, str) or not sender_email.strip():
            return bad_request_error("sender_email is required for auto_label_sender")
        if not isinstance(label_id, str) or not label_id.strip():
            return bad_request_error("label_id is required for auto_label_sender")
        return {
            "criteria": {"from": sender_email.strip()},
            "action": {"addLabelIds": [label_id.strip()]},
        }

    # auto_label_from_keyword
    if not isinstance(query, str):
        return bad_request_error("query is required for auto_label_from_keyword")
    stripped = query.strip()
    if not stripped:
        return bad_request_error("query cannot be empty")
    if len(stripped) < _MIN_QUERY_LENGTH:
        return bad_request_error(f"query must contain at least {_MIN_QUERY_LENGTH} characters")
    if not isinstance(label_id, str) or not label_id.strip():
        return bad_request_error("label_id is required for auto_label_from_keyword")
    return {
        "criteria": {"query": stripped},
        "action": {"addLabelIds": [label_id.strip()]},
    }
