"""connect_gmail_account bootstrap tool (capability unblock).

The 30th MCP tool. Unlike the other 29 (which all act on an
already-linked Gmail mailbox), this tool's job is to MINT a Google
OAuth handshake URL so a user who has not yet linked any account can
do so from inside Claude.ai without ever opening
docs/GMAIL_MCP_OAUTH.md to find the /oauth/start endpoint.

Why a tool, not just /oauth/start
---------------------------------
The bearer-authenticated /oauth/start endpoint already exists and the
bootstrap handler here is essentially a thin facade over the same
flow (mint nonce -> sign state -> build auth URL). The tool surface
matters because:

1. Claude.ai's connector already has a bearer token, so it can call
   tools by name. Asking the user to paste a URL in their browser
   when they could just ask Claude "connect my gmail" is a UX cliff.
2. Keeping the handshake URL minting on the MCP side means the
   bootstrap path consumes the same nonce table, the same HMAC
   signing key, and the same audit log. No parallel flow.

Why not run scope_check on it
-----------------------------
The bootstrap tool is the ONE tool that runs before a token row
exists. The dispatcher's normal flow (look up token row -> check
scopes -> resolve access token -> call Gmail) cannot apply to it
because there is no row to look up. The dispatcher recognizes the
bootstrap tool name and routes through this module's `handle()`
BEFORE SESSION BOUNDARY #1 (no DB session, no token resolution, no
scope check, no Gmail HTTP call).

This is enforced by `is_bootstrap_tool()` returning True for the
exact tool name, which dispatch.py checks before doing anything
else. Adding additional bootstrap tools in the future means adding
to this module's `_BOOTSTRAP_TOOL_NAMES` set, not generalizing the
dispatch path.

Audit-log discipline
--------------------
The audit() call from dispatch.py for the bootstrap tool emits
ONLY the standard whitelist fields: tool, auth0_sub, account_email,
outcome, error_code. The keyword-only signature of audit() makes
it structurally impossible to pass authorization_url, state, or
nonce as kwargs (audit() has no such parameters; passing them would
raise TypeError at runtime). This is a hard constraint enforced
structurally; the test suite asserts it.

Email-shape validation
----------------------
A revision added a hard email-shape check in this handler BEFORE
state_store.create_nonce is called. The check is intentionally
conservative: contains '@', total length 3..320 (Gmail / RFC 5321).
A failed check returns bad_request_error and create_nonce is NEVER
called (a passing test asserts the latter via mock-call-count).
"""

from __future__ import annotations

import logging
from typing import Any

from .. import oauth_state
from ..config import Settings
from ..db import session_scope
from ..state_store import create_nonce
from .errors import bad_request_error

logger = logging.getLogger(__name__)


# The set of tool names that route through this module instead of the
# normal token-bound dispatch flow. Currently one entry; adding a
# second is a deliberate change reviewed in its own PR.
_BOOTSTRAP_TOOL_NAMES = frozenset({"connect_gmail_account"})


def is_bootstrap_tool(tool_name: str) -> bool:
    """Return True iff `tool_name` should bypass token-bound dispatch.

    Called from dispatch.py BEFORE any token lookup or scope check.
    Treating bootstrap tools as a closed set (no glob, no prefix
    match) keeps the carve-out narrow.
    """
    return tool_name in _BOOTSTRAP_TOOL_NAMES


async def handle_connect_gmail_account(
    *,
    auth0_sub: str,
    arguments: dict[str, Any],
    settings: Settings,
) -> dict[str, Any]:
    """Mint a Google OAuth handshake URL for the calling user.

    Returns either:
      - {"authorization_url": "..."} on success
      - bad_request_error dict if account_email is missing/invalid

    The shape mirrors the JSON return of GET /oauth/start?redirect=false
    so a caller (Claude.ai, programmatic test) can compare the two.

    The handler does NOT log the authorization_url, state, or nonce
    at any level. Audit logging is the dispatcher's job, and the
    audit() helper's signature has no fields for those values.
    """
    # allowlist gate, mirrors oauth_routes/start.py.
    # bad_request_error (BAD_REQUEST -32001) is the closest match in
    # the existing tool error namespace; the wire shape carries the
    # same non-leaky message as the HTTP path so an attacker cannot
    # enumerate the allowlist by varying tool inputs. create_nonce is
    # NEVER called when the check fails (regression-guarded by tests).
    if not settings.is_auth0_sub_allowed(auth0_sub):
        logger.warning("connect_gmail_account: rejected disallowed auth0_sub=%s", auth0_sub)
        return bad_request_error("your Auth0 user is not authorized to link Gmail accounts")

    # Email-shape validation BEFORE create_nonce.
    # Contains '@' (RFC 5321 / 5322 minimum), length 3..320 (the
    # JSON Schema upper bound matches RFC 5321's documented cap).
    # The handler returns bad_request_error and create_nonce is
    # NEVER called when the check fails; this is regression-guarded
    # by test_connect_rejects_email_without_at_symbol.
    raw = arguments.get("account_email")
    account_email = (raw or "").strip().lower() if isinstance(raw, str) else ""
    if (
        not account_email
        or "@" not in account_email
        or len(account_email) < 3
        or len(account_email) > 320
    ):
        return bad_request_error("account_email is not an email address")

    # Mint nonce. Mirrors oauth_routes/start.py:oauth_start. The
    # nonce + HMAC-signed state + redemption check on /oauth2callback
    # is documented in docs/GMAIL_MCP_OAUTH.md.
    with session_scope() as session:
        nonce = create_nonce(
            session,
            auth0_sub=auth0_sub,
            account_email=account_email,
        )

    state = oauth_state.sign_state(
        nonce=nonce,
        auth0_sub=auth0_sub,
        account_email=account_email,
        signing_key=settings.state_signing_key,
    )
    auth_url = oauth_state.build_authorization_url(
        client_id=settings.google_oauth_client_id,
        redirect_uri=settings.google_oauth_redirect_url,
        scopes=list(settings.gmail_oauth_scopes),
        state=state,
        login_hint=account_email,
    )
    # No log line for the URL or state. The dispatcher's outcome-side
    # audit() call records tool=connect_gmail_account + auth0_sub +
    # account_email + outcome=ok and that is the entirety of the audit
    # signal. Logging the URL here would inject the state token into
    # log aggregation; leaking the (single-use) state would still be
    # an unnecessary information disclosure.
    return {"authorization_url": auth_url}
