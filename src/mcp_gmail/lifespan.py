"""FastAPI lifespan and boot-time orchestration for mcp-gmail.

Extracted from server.py so the runtime route surface (server.py)
stays focused on app construction, middleware, and request handling.
This module owns:

- `_enforce_replica_constraint`: hard fail-closed when more than one
  replica is detected (the in-process refresh-token lock assumes a
  single replica).
- `_maybe_warn_about_replicas`: backward-compatibility alias for the
   name; same callable.
- `lifespan`: the FastAPI startup context manager. Loads settings,
  installs the redacting log filter, initializes the DB engine,
  probes SELECT 1, warms JWKS, and stamps `app.state.settings`.

Public symbols also re-exported from `server.py` so existing imports
(`from mcp_gmail.server import _enforce_replica_constraint, ...`)
continue to resolve.
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from sqlalchemy import text

from . import config as config_module
from . import db as db_module
from . import health as health_module
from .auth import warm_jwks
from .logging_filters import install_redacting_filter

logger = logging.getLogger("mcp_gmail")


def _enforce_replica_constraint() -> None:
    """(medium-severity hardening): fail-closed when MCP_GMAIL_REPLICA_COUNT > 1.

    The per-(auth0_sub, account_email) asyncio.Lock token_store uses
    to serialize refresh-token calls is in-process. Running >1 replica
    breaks the serialization invariant and creates a real refresh-token
    race against Google. Earlier behavior was a WARN log; the current behavior
    upgrades this to a hard RuntimeError at startup so a misconfigured
    multi-replica deploy fails to come up rather than silently
    introducing a token-rotation race.

    Override: set MCP_GMAIL_ALLOW_MULTI_REPLICA=true to acknowledge
    the risk and proceed. The override is intended for the brief
    window where the operator has migrated to row-level SELECT FOR
    UPDATE locks but has not yet removed the env-var check.

    The fallback heuristic (RAILWAY_REPLICA_ID present alone) is
    still informational; we do NOT fail-close on it because Railway
    sets it on single-replica deploys too. Only the explicit count
    triggers the hard stop.

    Production guard
    ----------------
    In production (RAILWAY_ENVIRONMENT_NAME=production) the boot also
    fails closed when MCP_GMAIL_REPLICA_COUNT is unset or fails to
    parse as an int. Outside production the original permissive
    behavior is preserved so local dev and tests do not need to set
    the variable. Mirrors the production fail-closed pattern in
    `_settings_loader.py` for empty allowlist + scope config.
    """
    is_production = os.environ.get("RAILWAY_ENVIRONMENT_NAME", "").strip().lower() == "production"
    explicit = os.environ.get("MCP_GMAIL_REPLICA_COUNT", "").strip()
    if not explicit:
        if is_production:
            raise RuntimeError(
                "MCP_GMAIL_REPLICA_COUNT is not set in production "
                "(RAILWAY_ENVIRONMENT_NAME=production). The replica guard "
                "cannot detect actual scale-out without it; set the variable "
                "to the configured replica count (1 for single-replica deploys) "
                "to acknowledge the refresh-token serialization invariant."
            )
    elif explicit not in ("1",):
        try:
            n = int(explicit)
        except ValueError:
            if is_production:
                raise RuntimeError(
                    "MCP_GMAIL_REPLICA_COUNT is set to a non-integer value in "
                    "production (RAILWAY_ENVIRONMENT_NAME=production). The "
                    "replica guard cannot interpret the configuration; set the "
                    "variable to an integer matching the configured replica count."
                ) from None
            return
        if n > 1:
            allow = os.environ.get("MCP_GMAIL_ALLOW_MULTI_REPLICA", "").strip().lower()
            if allow != "true":
                raise RuntimeError(
                    f"Multiple replicas detected (MCP_GMAIL_REPLICA_COUNT={n}). "
                    "Per-key asyncio.Lock for token refresh assumes a single "
                    "replica; running >1 replica creates a refresh-token race "
                    "against Google. Set MCP_GMAIL_ALLOW_MULTI_REPLICA=true to "
                    "acknowledge after switching to SELECT FOR UPDATE row locks."
                )
            logger.warning(
                "Multiple replicas allowed via MCP_GMAIL_ALLOW_MULTI_REPLICA "
                "(MCP_GMAIL_REPLICA_COUNT=%d). Refresh-token races are "
                "possible unless row-level locking is in place.",
                n,
            )
            return
    # Informational-only RAILWAY_REPLICA_ID note. NOT a fail-close.
    replica_id = os.environ.get("RAILWAY_REPLICA_ID", "").strip()
    if replica_id:
        logger.info(
            "RAILWAY_REPLICA_ID is set (=%s). Set MCP_GMAIL_REPLICA_COUNT "
            "explicitly if scaled to >1 replica; without it, the in-process "
            "refresh lock has no enforced cap.",
            replica_id,
        )


# backward-compat alias for callers that still import
# the old name. The lifespan handler below uses the new name; tests
# can import either.
_maybe_warn_about_replicas = _enforce_replica_constraint


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Reset readiness state on every lifespan entry. In tests the same
    # process re-enters lifespan many times; without a reset the
    # readiness booleans would carry over from a prior test and mask
    # boot-step regressions.
    health_module.reset_for_tests()
    settings = config_module.load()
    health_module.mark_settings_loaded()
    logging.basicConfig(
        level=settings.log_level,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # Install the redacting filter immediately after basicConfig and
    # BEFORE init_engine. SQLAlchemy emits its first log line on engine
    # creation; the filter must be in place to scrub any URL-credential
    # fragments that show up there. Defense in depth: every callsite
    # MUST already avoid logging tokens; this catches accidents.
    install_redacting_filter()
    logger.info(
        "mcp-gmail starting: resource=%s issuer=%s",
        settings.mcp_resource_url,
        settings.oauth_issuer_url,
    )
    db_module.init_engine(settings.database_url)
    # a SELECT 1 probe confirms the engine can actually
    # talk to the database, not just that it was constructed. We do
    # NOT fail-close on probe failure; the lifespan must continue so
    # /health and /ready remain addressable while operators
    # investigate. Readiness flag stays clear until the probe passes
    # (either now or on the next on-demand reattempt; a future
    # follow-up may add a periodic re-check).
    try:
        with db_module.get_engine().connect() as conn:
            conn.execute(text("SELECT 1"))
        health_module.mark_db_ready()
    except Exception as exc:  # noqa: BLE001
        # Log the exception type only; a full repr can leak a DSN
        # fragment from SQLAlchemy's connection-error message.
        logger.warning("startup db probe failed: %s", type(exc).__name__)
        health_module.record_failure("db", type(exc).__name__)

    _enforce_replica_constraint()

    # warm the JWKS cache so first authenticated /mcp
    # call does not pay the fetch latency. Best-effort: if JWKS is
    # unreachable at boot we log a warning, leave the readiness flag
    # clear, and let the on-demand path retry on the first request
    # (which is also throttled).
    try:
        await warm_jwks(settings)
        health_module.mark_jwks_warm()
    except Exception as exc:  # noqa: BLE001
        logger.warning("startup jwks warm-fetch failed: %s", type(exc).__name__)
        health_module.record_failure("jwks", type(exc).__name__)

    app.state.settings = settings
    try:
        yield
    finally:
        # Engine pool teardown happens automatically via the engine's
        # finalizer; nothing to close explicitly.
        pass
