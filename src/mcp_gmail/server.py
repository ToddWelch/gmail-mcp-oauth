"""FastAPI application exposing the MCP endpoint, health, and PRM.

Endpoints
---------
GET  /health                                  Liveness for Railway.
GET  /ready                                   Readiness probe (JWKS + DB).
GET  /.well-known/oauth-protected-resource    RFC 9728 PRM document.
POST /mcp                                     MCP JSON-RPC over HTTP.

Auth
----
/mcp requires a valid bearer token. Failures return 401 with a
WWW-Authenticate header pointing at the PRM URL. /health and PRM are
public.

Logging
-------
Token values never reach logs. We log the kid, issuer, and failure
reason, but never the raw token or claim payload beyond `iss` and `sub`.

Route surface
-------------
The `/mcp` route is wired to the JSON-RPC dispatcher; the registered
Gmail tools are listed via tools/list and routed via tools/call. The
/oauth/start, /oauth2callback, /oauth/status, and /oauth/disconnect
routes consume state_store + token_store.

Replica-count guard
-------------------
Per token_store.py's docstring, the per-key asyncio.Lock for refresh
serialization assumes a single replica. The lifespan handler in
`lifespan.py` invokes `_enforce_replica_constraint` to fail closed
when MCP_GMAIL_REPLICA_COUNT > 1 without an explicit override.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response

from . import health as health_module
from . import oauth_routes
from .auth import AuthError, build_www_authenticate, validate_bearer_token

# Backward compatibility re-exports; canonical homes are
# mcp_gmail.lifespan.{lifespan, _enforce_replica_constraint,
# _maybe_warn_about_replicas}. Tests at tests/test_server.py:19-23
# import _enforce_replica_constraint and _maybe_warn_about_replicas
# from mcp_gmail.server, and the FastAPI(lifespan=lifespan) below
# binds the lifespan handler.
from .lifespan import (
    _enforce_replica_constraint,  # noqa: F401
    _maybe_warn_about_replicas,  # noqa: F401
    lifespan,
)
from .mcp_protocol import handle_jsonrpc
from .middleware import BodySizeLimitMiddleware, ErrorEnvelopeMiddleware

logger = logging.getLogger("mcp_gmail")


app = FastAPI(
    title="mcp-gmail",
    description="MCP wrapper over the Google Gmail API with multi-account OAuth.",
    version="0.1.0",
    lifespan=lifespan,
)

# + Item 5: body-size cap + correlation-id error envelope.
# Order matters: BodySizeLimitMiddleware is the outermost so it fires
# BEFORE the body is buffered into request.body() inside FastAPI.
# ErrorEnvelopeMiddleware is the next inner so request.state.correlation_id
# is available to downstream handlers (mcp_protocol uses it).
app.add_middleware(ErrorEnvelopeMiddleware)
app.add_middleware(BodySizeLimitMiddleware)

# Mount the Google OAuth flow routes (/oauth/start, /oauth2callback,
# /oauth/status, /oauth/disconnect). Defined in a separate module so
# server.py stays focused on bearer-gated /mcp + public health/PRM.
app.include_router(oauth_routes.router)


# ---------------------------------------------------------------------------
# Public endpoints (no auth)
# ---------------------------------------------------------------------------


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/ready")
async def ready() -> Response:
    """readiness probe (split from /health).

    Returns 200 only when ALL boot-time checks succeeded:
      - Settings loaded (env vars valid)
      - DB engine bound and SELECT 1 returned
      - JWKS document fetched and parsed at least once

    Returns 503 with the same JSON shape when any check is unmet so a
    load balancer or orchestrator can hold traffic off this instance
    while the underlying issue is being fixed. /health stays a cheap
    process-liveness probe and continues returning 200 either way.

    No auth: like /health, /ready must be reachable from network
    probes that have no bearer token.
    """
    snapshot = health_module.snapshot()
    status = 200 if snapshot["ready"] else 503
    return JSONResponse(snapshot, status_code=status)


@app.get("/.well-known/oauth-protected-resource")
async def protected_resource_metadata(request: Request) -> dict[str, Any]:
    """RFC 9728 Protected Resource Metadata.

    Tells Claude.ai which authorization server to use when it receives
    a 401 from this resource. Points at the configured OIDC issuer URL,
    which serves its own OAuth2 authorization server metadata.
    """
    settings = request.app.state.settings
    return {
        "resource": settings.mcp_resource_url,
        "authorization_servers": list(settings.authorization_servers),
        "bearer_methods_supported": ["header"],
        "scopes_supported": list(settings.mcp_expected_scopes),
    }


# ---------------------------------------------------------------------------
# Authenticated MCP endpoint
# ---------------------------------------------------------------------------


def _extract_bearer(request: Request) -> str | None:
    auth_header = request.headers.get("Authorization", "")
    prefix = "Bearer "
    if not auth_header.startswith(prefix):
        return None
    return auth_header[len(prefix) :].strip()


@app.post("/mcp")
async def mcp_endpoint(request: Request) -> Response:
    settings = request.app.state.settings

    token = _extract_bearer(request)
    if token is None:
        return JSONResponse(
            {"error": "missing_bearer_token"},
            status_code=401,
            headers={"WWW-Authenticate": build_www_authenticate(settings, "invalid_token")},
        )

    try:
        claims = await validate_bearer_token(token, settings)
    except AuthError as exc:
        # log the structured detail at INFO (operator
        # visibility) but DO NOT echo it on the wire. The exc.detail
        # may contain library-internal text from PyJWT that future
        # versions could change; the client-visible response carries
        # only the curated reason code.
        logger.info("Auth rejected: reason=%s detail=%s", exc.reason, exc.detail)
        return JSONResponse(
            {"error": exc.reason},
            status_code=401,
            headers={"WWW-Authenticate": build_www_authenticate(settings, exc.reason)},
        )

    # Sub is useful audit context; never log the raw token.
    logger.info("Auth ok: sub=%s iss=%s", claims.get("sub"), claims.get("iss"))

    # allowlist gate. binds the response
    # shape to 403 + {"error": "auth0_sub_not_allowlisted"} with NO
    # WWW-Authenticate (bearer is valid; only principal is denied).
    sub = claims.get("sub")
    if not settings.is_auth0_sub_allowed(sub if isinstance(sub, str) else None):
        logger.warning("mcp: rejected disallowed auth0_sub=%s", sub)
        return JSONResponse({"error": "auth0_sub_not_allowlisted"}, status_code=403)

    try:
        body = await request.json()
    except ValueError:
        raise HTTPException(status_code=400, detail="request body is not valid JSON") from None

    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="request body must be a JSON object")

    # ErrorEnvelopeMiddleware stamps a per-request
    # correlation_id on request.state. Hand it to mcp_protocol so the
    # -32603 internal-error path embeds it in the message rather than
    # leaking exception text.
    cid = getattr(request.state, "correlation_id", None)
    response = await handle_jsonrpc(body, claims=claims, correlation_id=cid)
    if response is None:
        # Notification: JSON-RPC says no response. Use HTTP 204.
        return Response(status_code=204)
    return JSONResponse(response)
