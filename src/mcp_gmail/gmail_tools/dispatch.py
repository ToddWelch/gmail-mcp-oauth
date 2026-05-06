"""Tool dispatch: orchestrates token resolution, scope check, Gmail call, audit log.

Called from mcp_protocol.py's tools/call branch. The function
`dispatch_tool_call` is the single entry point for every tool;
TOOL_DEFINITIONS lists the 11 tools available, and the
dispatcher routes by name (via tool_router.route_tool) to the
appropriate read-side helper.

Session boundaries
------------------------------------------------
The dispatcher MUST keep all Gmail HTTP calls OUTSIDE any open DB
session. Each session_scope() block is narrowly scoped:

    1. session_scope() to look up the token row + cached scope.
       Closes immediately.
    2. token_manager.get_access_token(...) opens its OWN sessions
       internally for refresh + persist. Not nested.
    3. Gmail HTTP call: ZERO open sessions during this.
    4. session_scope() to call mark_used(session, row). Closes.

This keeps Postgres connections free during multi-second Gmail calls.
The pattern is enforced by code structure (no `with session_scope()`
wraps a Gmail call) and verified by tests that assert no Gmail mock
fires while a session is open.

Audit log discipline
--------------------
Exactly one audit() call per dispatch, on outcome. The call site
sees `auth0_sub` (from claims), `account_email` (from arguments),
`outcome` ("ok" | "needs_reauth" | "scope_insufficient" | "not_found"
| "rate_limited" | "upstream_error" | "error"), plus tool-specific
identifiers (message_id, thread_id, attachment_id). Filename is NOT a
parameter; the audit() helper rejects it structurally.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from ..config import Settings
from ..db import session_scope
from ..token_manager import TokenUnavailableError, get_access_token
from ..token_store import get_token, mark_used
from .audit_log import audit
from .bootstrap import handle_connect_gmail_account, is_bootstrap_tool
from .errors import (
    bad_request_error,
    needs_reauth_error,
    scope_insufficient_error,
    unknown_error,
)
from .gmail_client import GmailClient
from .scope_check import ScopeInsufficient, UnknownTool, check_scopes
from .tool_router import route_tool

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# ToolContext: the bundle of identifiers and crypto material a tool needs.
# ---------------------------------------------------------------------------


@dataclass
class ToolContext:
    """Per-dispatch context. Built from claims + Settings + tool arguments.

    Why a dataclass: the dispatcher needs four or five values from
    config + claims, and passing them positionally invites mistakes.
    """

    auth0_sub: str
    account_email: str
    encryption_key: str
    # prior key-ring forwarded into get_access_token so a
    # rotation in progress can decrypt rows under the old key while the
    # primary key encrypts new ciphertext. Default empty tuple keeps
    # existing tests green; production runs may pass a non-empty tuple
    # via Settings.prior_encryption_keys.
    prior_encryption_keys: tuple[str, ...]
    google_client_id: str
    google_client_secret: str


# ---------------------------------------------------------------------------
# Dispatch entry point
# ---------------------------------------------------------------------------


async def dispatch_tool_call(
    *,
    tool_name: str,
    arguments: dict[str, Any],
    claims: dict[str, Any] | None,
    settings: Settings,
) -> dict[str, Any]:
    """Run one tool by name.

    Returns either:
      - The tool's success result dict.
      - A tool-error dict (from errors.py) suitable for placement in
        a JSON-RPC `error` field. The caller (mcp_protocol.py) is
        responsible for that wrapping.

    The function NEVER raises ScopeInsufficient, TokenUnavailableError,
    or GmailApiError up the stack; it catches and converts each into
    the appropriate JSON-shaped error.
    """
    if not isinstance(arguments, dict):
        return bad_request_error("arguments must be an object")
    sub = (claims or {}).get("sub")
    if not sub:
        # Defense in depth. The auth layer already rejected unsigned
        # tokens, but a future test path that bypasses auth shouldn't
        # produce a bad audit log line.
        return needs_reauth_error("no auth0_sub in claims")

    # bootstrap-tool short-circuit. The bootstrap path
    # runs BEFORE SESSION BOUNDARY #1 because the tool's job is to
    # CREATE the conditions a token-bound dispatch flow assumes
    # (existing token row + granted scope). Token lookup, scope check,
    # token resolution, and Gmail HTTP call are all skipped. The
    # bootstrap handler does its own argument validation (email shape)
    # and audit() runs once at outcome with the same fields the
    # token-bound path would have used.
    if is_bootstrap_tool(tool_name):
        result = await handle_connect_gmail_account(
            auth0_sub=sub,
            arguments=arguments,
            settings=settings,
        )
        is_error = isinstance(result, dict) and isinstance(result.get("code"), int)
        outcome = "error" if is_error else "ok"
        # Audit-log discipline: only the standard whitelist fields.
        # NEVER pass authorization_url, state, or nonce as kwargs;
        # the audit() helper has no such parameters and would raise
        # TypeError if attempted (structural defense, audit-allowlist spirit).
        # account_email is taken from arguments AFTER the bootstrap
        # handler's own normalization is applied; the dispatcher's
        # raw-arguments echo here ensures audit captures whatever the
        # caller passed even on the failure path.
        raw_email = arguments.get("account_email")
        audit_email = raw_email.strip().lower() if isinstance(raw_email, str) else None
        audit(
            tool=tool_name,
            auth0_sub=sub,
            account_email=audit_email,
            outcome=outcome,
            error_code=result.get("code") if is_error else None,
        )
        return result

    account_email = arguments.get("account_email")
    if not isinstance(account_email, str) or not account_email:
        return bad_request_error("account_email is required")

    ctx = ToolContext(
        auth0_sub=sub,
        account_email=account_email.strip().lower(),
        encryption_key=settings.encryption_key,
        prior_encryption_keys=settings.prior_encryption_keys,
        google_client_id=settings.google_oauth_client_id,
        google_client_secret=settings.google_oauth_client_secret,
    )

    # SESSION BOUNDARY #1: look up the token row + granted scope.
    # Close the session immediately so no HTTP call holds it open.
    with session_scope() as session:
        row = get_token(
            session,
            auth0_sub=ctx.auth0_sub,
            account_email=ctx.account_email,
        )
        if row is None:
            audit(
                tool=tool_name,
                auth0_sub=ctx.auth0_sub,
                account_email=ctx.account_email,
                outcome="needs_reauth",
                error_code=-32003,
            )
            return needs_reauth_error(
                f"no Google account linked for {ctx.account_email}; user must run /oauth/start"
            )
        if row.revoked_at is not None:
            audit(
                tool=tool_name,
                auth0_sub=ctx.auth0_sub,
                account_email=ctx.account_email,
                outcome="needs_reauth",
                error_code=-32003,
            )
            return needs_reauth_error(
                f"Google account {ctx.account_email} is soft-revoked; user must re-link"
            )
        granted_scope = row.scope or ""
    # END SESSION BOUNDARY #1.

    # Scope check happens BEFORE any Gmail HTTP call. If the granted
    # scope is insufficient, we surface the scope_insufficient
    # response shape without spending a Google round trip.
    try:
        check_scopes(tool_name=tool_name, granted_scope=granted_scope)
    except UnknownTool:
        return unknown_error(f"unknown tool: {tool_name}")
    except ScopeInsufficient as exc:
        audit(
            tool=tool_name,
            auth0_sub=ctx.auth0_sub,
            account_email=ctx.account_email,
            outcome="scope_insufficient",
            error_code=-32004,
        )
        return scope_insufficient_error(
            required_scopes=exc.required_scopes,
            granted_scope=exc.granted_scope,
            sufficient_alternatives=exc.sufficient_alternatives,
        )

    # Resolve the access token. token_manager.get_access_token opens
    # its own session(s) for refresh + persist; we do NOT wrap that
    # call in session_scope().
    try:
        access_token = await get_access_token(
            auth0_sub=ctx.auth0_sub,
            account_email=ctx.account_email,
            google_client_id=ctx.google_client_id,
            google_client_secret=ctx.google_client_secret,
            encryption_key=ctx.encryption_key,
            prior_encryption_keys=ctx.prior_encryption_keys,
        )
    except TokenUnavailableError as exc:
        audit(
            tool=tool_name,
            auth0_sub=ctx.auth0_sub,
            account_email=ctx.account_email,
            outcome="needs_reauth",
            error_code=-32003,
        )
        return needs_reauth_error(str(exc))

    # SESSION BOUNDARY: NONE during the Gmail call. GmailClient +
    # tool dispatch run with no open Postgres connection (db.py
    # contract). granted_scope flows to route_tool so send_draft
    # can gate post-send actions at handler entry.
    async with GmailClient(access_token=access_token) as client:
        result = await route_tool(
            tool_name=tool_name,
            arguments=arguments,
            client=client,
            auth0_sub=ctx.auth0_sub,
            account_email=ctx.account_email,
            granted_scope=granted_scope,
        )

    # `result` is either a success dict (Gmail's response body) or an
    # error dict from errors.py. We pick the audit outcome from its
    # shape: a dict with a top-level "code" int is an error; anything
    # else is success.
    is_error = isinstance(result, dict) and isinstance(result.get("code"), int)
    outcome = "error" if is_error else "ok"

    # SESSION BOUNDARY #2 (success path only): bump last_used_at on the
    # token row. mark_used is best-effort; a DB error here should not
    # cascade into a tool-call failure that the user sees.
    if outcome == "ok":
        try:
            with session_scope() as session:
                row = get_token(
                    session,
                    auth0_sub=ctx.auth0_sub,
                    account_email=ctx.account_email,
                )
                if row is not None:
                    mark_used(session, row)
        except Exception:  # noqa: BLE001
            logger.warning("mark_used failed for tool=%s", tool_name)
    # END SESSION BOUNDARY #2.

    def _str_or_none(name: str) -> str | None:
        v = arguments.get(name)
        return v if isinstance(v, str) else None

    audit(
        tool=tool_name,
        auth0_sub=ctx.auth0_sub,
        account_email=ctx.account_email,
        outcome=outcome,
        message_id=_str_or_none("message_id"),
        thread_id=_str_or_none("thread_id"),
        attachment_id=_str_or_none("attachment_id"),
        draft_id=_str_or_none("draft_id"),
        filter_id=_str_or_none("filter_id"),
        error_code=result.get("code") if is_error else None,
    )
    return result
