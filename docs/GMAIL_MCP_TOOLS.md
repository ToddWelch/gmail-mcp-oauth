# Gmail MCP tool reference

The mcp-gmail service exposes 32 tools to Claude.ai connectors: 13 read
tools (the 11 + the 2 fanout helpers), 14 write tools,
4 cleanup tools, and 1 bootstrap tool. This doc is the
per-tool reference, scope table, audit log shape, and operational
target. It tracks the state of `mcp-gmail/src/mcp_gmail/gmail_tools/`
and is updated alongside every PR that changes a tool surface.

## Tool surface (read, 13 tools)

| Tool | Required scope | Read/Write | Notes |
|------|---------------|------------|-------|
| `read_email` | `gmail.readonly` | read | Format defaults to `full`. |
| `search_emails` | `gmail.readonly` | read | Gmail web-search syntax. Returns ID stubs only; follow up with read_email per ID. |
| `download_attachment` | `gmail.readonly` | read | `attachment_id` validated against Gmail ID pattern before HTTP. |
| `download_email` | `gmail.readonly` | read | Returns RFC 5322 raw bytes base64url-encoded. |
| `get_thread` | `gmail.readonly` | read | Returns all messages in the thread. |
| `list_inbox_threads` | `gmail.readonly` | read | Stubs only; expand via get_thread. |
| `get_inbox_with_threads` | `gmail.readonly` | read | Convenience: lists + expands metadata in one call. N+1 round trips. |
| `modify_thread` | `gmail.modify` | write-on-read-shape | Add/remove labels on a thread. Borderline: result shape is read-side, but mutates server state. |
| `list_email_labels` | `gmail.readonly` | read | System + user labels. |
| `list_filters` | `gmail.readonly` | read | All Gmail settings filters. |
| `get_filter` | `gmail.readonly` | read | One filter by ID. |
| `multi_search_emails` | `gmail.readonly` | read | Run up to 25 Gmail searches concurrently in one call. Returns ordered per-query results; failed queries surface as `{query, error_status, error_message}` records (partial-success). asyncio.gather under one OAuth token. |
| `batch_read_emails` | `gmail.readonly` | read | Fetch up to 100 messages by ID concurrently. `format` enum is `["metadata", "minimal"]` (no full/raw). `metadata_headers` defaults to `['From', 'Subject', 'Date']`. Per-id failures surface as `{message_id, error_status, error_message}` records (partial-success). |

## Tool surface (write, 14 tools)

| Tool | Required scope | Notes |
|------|---------------|-------|
| `send_email` | `gmail.send` | Optional `idempotency_key`; 60s in-process dedupe keyed by `(auth0_sub, account_email, idempotency_key)`. 25 MiB encoded-size cap on the assembled message. |
| `create_draft` | `gmail.compose` | Same EmailMessage path as send_email; 25 MiB cap enforced. Optional `thread_id` sets `message.threadId` on the request, the authoritative thread join per Gmail's threading docs; header-only threading via `reply_to_message_id` / `reply_to_references` is best-effort fallback. |
| `update_draft` | `gmail.compose` | Full PUT replace; the body wholly replaces the prior draft. Same `thread_id` parameter and semantics as `create_draft`. |
| `list_drafts` | `gmail.compose` | Returns id stubs; follow up with read_email per id for full content. |
| `send_draft` | `gmail.send` (+ `gmail.modify` for post-send actions) | Consumes the draft (Gmail moves it from DRAFT to SENT). optional `archive_thread`, `add_labels`, `remove_labels` apply a follow-up modify_thread to the original thread AFTER the send succeeds. Post-send actions are best-effort: send-success + action-fail returns the success record annotated with `post_send_actions.applied=false` and `action_failures`; the send is NEVER retried. Send-fail returns the existing error shape with no actions attempted. Caller must have granted gmail.modify (subsumed by gmail.modify or full); a SEND-only token plus any post-send param returns `bad_request_error` at handler entry. |
| `delete_draft` | `gmail.compose` | Permanent on the draft only; no impact on sent messages. |
| `create_label` | `gmail.modify` | System labels (INBOX, SENT, etc.) are not user-creatable. |
| `update_label` | `gmail.modify` | System labels cannot be renamed. |
| `delete_label` | `gmail.modify` | Removes the label from every message and thread that carried it; messages remain in place. |
| `modify_email_labels` | `gmail.modify` | Single-message label add/remove (vs modify_thread which is at thread level). |
| `create_filter` | `gmail.settings.basic` | Applies to NEW incoming mail; existing messages are not touched. |
| `delete_filter` | `gmail.settings.basic` | Stops the filter matching new mail; does NOT undo prior labels or moves. |
| `delete_email` | `gmail.modify` | TRASH semantics (recoverable for 30 days). Implemented via `users.messages.trash`, NOT `users.messages.delete`. |
| `batch_delete_emails` | `gmail.modify` | TRASH semantics, up to 1000 messages per call. Implemented via `users.messages.batchModify` with `addLabelIds=['TRASH']`, NOT `users.messages.batchDelete`. |

## Tool surface (cleanup, 4 tools)

| Tool | Required scope | Notes |
|------|---------------|-------|
| `reply_all` | `gmail.send` + `gmail.readonly` | Pass the source message via the `message_id` input field. Replies to ALL recipients on the original message (To + Cc minus self), NOT just the sender. Self resolved via `users.getProfile`; getProfile failure surfaces as `upstream_error` rather than silent fallback. Expanded recipient set capped at 100. Idempotency cache shared with `send_email` (do not reuse the same `idempotency_key` for both tools). |
| `batch_modify_emails` | `gmail.modify` | Bulk add/remove labels across up to 1000 messages in one Gmail call. Same endpoint as `batch_delete_emails` (`users.messages.batchModify`) but with caller-specified add/remove label sets. |
| `get_or_create_label` | `gmail.modify` | Returns the existing label with the given name, or creates one if missing. TOCTOU race: if another caller creates the label between our list and our create, Gmail returns a duplicate-name 409. Name match is case-sensitive ("Important" and "important" are distinct). |
| `create_filter_from_template` | `gmail.settings.basic` | Creates a Gmail filter from a named template. Templates: `auto_archive_sender`, `auto_label_sender`, `auto_label_from_keyword`. Empty / whitespace / single-character `query` rejected before any Gmail call (over-broad queries would label every future message). |

### Filter template matrix

| Template | Criteria | Action | Notes |
|----------|----------|--------|-------|
| `auto_archive_sender` | `from:<sender_email>` literal | Remove `INBOX` label | For domain-wide matching (e.g. anything from `@spam.com`), use `auto_label_from_keyword` with `from:*@spam.com` query syntax. |
| `auto_label_sender` | `from:<sender_email>` literal | Add `<label_id>` | Functionally equivalent to `auto_label_from_keyword` with a `from:` query, exposed separately because the email-address-only case is the most common and giving it a named template makes intent more discoverable. |
| `auto_label_from_keyword` | `query:<arbitrary Gmail search syntax>` | Add `<label_id>` | Caller is responsible for query correctness. Empty / whitespace-only / single-character queries are rejected (would label every future message). Two-character minimum. |

### Draft threading

Gmail's API stitches a draft (or sent message) into an existing thread
only when ALL THREE of these conditions are met
(developers.google.com/gmail/api/guides/sending#threading):

1. The requested `threadId` is set on the `Message` resource in the
   request body. This is the authoritative join.
2. The `In-Reply-To` and `References` headers are RFC 2822 compliant.
3. The `Subject` header matches the existing thread's subject.

The Gmail MCP exposes all three:

- `thread_id` argument on `create_draft` / `update_draft` -> condition 1
.
- `reply_to_message_id` and `reply_to_references` -> condition 2 (set
  via `message_format.build_email_message`).
- `subject` argument -> condition 3 (caller supplies).

When `thread_id` is omitted, Gmail falls back to header-only inference
which is best-effort and fails on edge cases (long subjects,
mid-thread subject edits, missing References on the original
message). For reliable thread joining always set `thread_id`.

### Delete-tool semantics

Gmail's API has a sharp split between recoverable and permanent delete
of messages:

- `users.messages.trash` (POST `/users/me/messages/{id}/trash`) requires
  `gmail.modify` and moves to TRASH (recoverable for 30 days).
- `users.messages.delete` (DELETE `/users/me/messages/{id}`) requires
  `mail.google.com/` (full mailbox) and is PERMANENT.
- `users.messages.batchDelete` (POST `/users/me/messages/batchDelete`)
  requires `mail.google.com/` and is PERMANENT.
- `users.messages.batchModify` (POST `/users/me/messages/batchModify`)
  requires `gmail.modify` and accepts add/remove label IDs across up
  to 1000 messages per call.

The service chose the recoverable path for both delete tools (resolution 1A):

- `delete_email` calls `users.messages.trash`.
- `batch_delete_emails` calls `users.messages.batchModify` with
  `addLabelIds=['TRASH']`.

The permanent endpoints are deliberately NOT used. The raw
`client.delete_message` and `client.batch_delete_messages` mixin
methods are kept dormant on `gmail_client_write.py` so a future PR
could opt into hard-delete by changing only the tool wiring, but the
default is trash semantics.

## Default OAuth scope (scope policy)

The connector requests only `openid email
https://www.googleapis.com/auth/gmail.readonly` by default. Write tools
will fail with `scope_insufficient` until the user re-links with
broader scopes. We DELIBERATELY do not widen the default to keep
read-only consenters from being prompted for write scopes they will
never use.

When `scope_insufficient` fires, the error response includes a
structured `error_data` payload:

```json
{
  "code": -32004,
  "message": "insufficient OAuth scope: required ['https://www.googleapis.com/auth/gmail.send']",
  "data": {
    "error_data": {
      "required_scopes": [
        "https://www.googleapis.com/auth/gmail.send"
      ],
      "granted_scope": "openid email https://www.googleapis.com/auth/gmail.readonly",
      "reconnect_hint": "Re-link the account at /oauth/start to grant additional scopes"
    }
  }
}
```

To enable write tools, an operator can override `GMAIL_OAUTH_SCOPES` in
the Railway env to include the appropriate scopes, then prompt users to
re-link. The connector does not require this to be set; it is purely
opt-in.

## Audit log shape

Every tool dispatch emits exactly one log line at INFO level (or WARN
for malformed identifiers) via `gmail_tools/audit_log.py::audit`. The
helper accepts ONLY the fields below, by keyword. Adding a field is a
deliberate code change.

| Field | Always emitted | Type | Notes |
|-------|---------------|------|-------|
| `tool` | yes | str | Tool name (e.g. `read_email`). |
| `auth0_sub` | yes | str \| None | JWT sub of the human invoking the tool. |
| `account_email` | yes | str \| None | Linked Gmail address. |
| `outcome` | yes | str | `ok`, `error`, `needs_reauth`, `scope_insufficient`, `not_found`, `rate_limited`, `upstream_error`. |
| `message_id` | when applicable | str | Validated against Gmail ID shape; mismatches are logged at WARN level. |
| `thread_id` | when applicable | str | Same WARN shape rule. |
| `label_id` | when applicable | str | |
| `attachment_id` | when applicable | str | |
| `draft_id` | when applicable | str | Set by the draft tools (create_draft, update_draft, send_draft, delete_draft). |
| `filter_id` | when applicable | str | Set by the filter tools (delete_filter; create_filter does not have a pre-existing id). |
| `mime_type` | when applicable | str | Set when an attachment was downloaded; deliberately replaces filename. |
| `size_bytes` | when applicable | int | Set when an attachment was downloaded. |
| `error_code` | on error outcomes | int | Stable JSON-RPC code from `errors.py::ToolErrorCode`. |

Fields that are NEVER logged:

- Subject lines
- Recipient addresses
- Body text
- Snippet text
- Search query strings
- Filter criteria
- Label names (only label IDs)
- **Attachment filenames**: the `audit()` helper has no `filename`
  parameter; passing one raises TypeError because the signature is
  keyword-only.
- Tokens of any kind (refresh, access, id, code). The
  `RedactingFilter` in `logging_filters.py` is a defense-in-depth
  backstop for these.

## Latency targets

These are the operational targets the build is sized against. Numbers
are end-to-end including JWT validation, scope check, token refresh
(if any), Gmail HTTP call, and audit log write. Network-bound work
dominates.

| Tool group | P50 | P95 |
|------------|-----|-----|
| Read tools (cached access token) | < 500 ms | < 2 s |
| Read tools (cold access token, refresh required) | < 1 s | < 3 s |
| Send / draft tools | < 2 s | < 4 s |
| Bulk delete | < 3 s | < 6 s |

Tool-level performance regression alarms should fire above the P95
target. P95 is the planning number; P50 should stay comfortably below
P95 by half or more.

## Attachment size cap

Gmail's hard ceiling on `users.messages.send` is 25 MB on the FINAL
encoded RFC 5322 message size. Base64 inflates binary attachments by
~33%, so raw attachment data caps at ~18 MB.

`message_format.py::build_email_message` enforces the cap on
`msg.as_bytes()` (the bytes the send tool actually transmits).
Boundary tests:

- 25 \* 1024 \* 1024 bytes -> pass
- 25 \* 1024 \* 1024 + 1 bytes -> raise `OversizeMessage`

The cap ships so the send tool can reuse the helper
without re-implementing.

## Idempotency cache (used by send_email)

`gmail_tools/idempotency.py` provides an LRU + TTL cache. The
`send_email` tool uses it when the caller supplies an
`idempotency_key`. Default configuration:

- TTL: 60 seconds (Claude.ai's tool-retry window).
- Capacity: 1000 entries (LRU eviction).
- Key: `(auth0_sub, account_email, idempotency_key)` tuple.

The cache is process-local. Multi-replica deployments would observe a
cache miss across replicas, which matches token_store's per-key
asyncio.Lock single-replica caveat. The mcp-gmail service deploys at
1 replica today.

Behavior under cache hit: `send_email` returns the cached Gmail
response WITHOUT calling Gmail (zero POSTs). Behavior under cache
miss: exactly one POST to `users.messages.send`, then the response is
cached for the TTL.

Disconnect flow calls
`default_cache.clear_for_actor(auth0_sub=..., account_email=...)` so a
re-link does not return the previous link's cached result. The cleanup pass
shipped this integration: `token_manager.disconnect_account` calls
`clear_for_actor` at the end of its critical section, and
`oauth_routes/disconnect.py` does a belt-and-braces second clear at
the route boundary. A late cache write that lands after the clear is
unreachable because the next `get_access_token` for that
`(auth0_sub, account_email)` returns `TokenUnavailableError` (revoked
row), blocking re-link callers from cache_hit on a revoked-actor
key.

## Cross-user isolation

Tool dispatch is scoped to a `(auth0_sub, account_email)` pair derived
from the JWT claims and tool arguments. The token row lookup
(`token_store.get_token`) filters on both columns; a request for one
user's claims with another user's account_email returns no row, which
the dispatcher surfaces as `needs_reauth` (no row, no token, no Gmail
call). The result is cross-user isolation by construction; the
regression test in `tests/test_gmail_tools_dispatch.py` makes the
property explicit.
