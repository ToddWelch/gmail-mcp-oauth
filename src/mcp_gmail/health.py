"""Readiness state shared between server.py and lifespan.

(low-severity hardening): split readiness from liveness. /health stays
a cheap liveness probe (process is up, the event loop is responsive).
/ready is the deeper check: DB engine bound, JWKS warmed, settings
loaded.

Why a separate module
---------------------
The lifespan handler in server.py is the only writer (it sets the
flags after each successful boot step). The /ready route handler is
the only reader. Keeping them apart in their own module avoids a
circular-import knot (server -> health -> nothing) and gives tests a
narrow surface to monkeypatch.

State shape
-----------
A frozen-ish module-level dataclass holding three booleans plus an
optional reason string. We deliberately do NOT model "degraded" as a
third state. Either every check passed and we're ready to serve
authenticated traffic, or we're not. /health continues to return 200
either way so the underlying service stays addressable for ops.

Single-process semantics
------------------------
The state is in-process. Each replica computes its own readiness.
Railway's load balancer treats 503 from /ready as "do not route
traffic here" once readiness probes are wired (a future
ships the endpoint without flipping Railway's probe yet so a bad
warm-fetch can't wedge production at deploy time before operators
have observed the new shape).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class _ReadinessState:
    db_ready: bool = False
    jwks_warm: bool = False
    settings_loaded: bool = False
    last_error: str | None = None
    failures: dict[str, str] = field(default_factory=dict)


_state = _ReadinessState()


def mark_settings_loaded() -> None:
    """Lifespan calls this after Settings.load() succeeds."""
    _state.settings_loaded = True
    _state.failures.pop("settings", None)


def mark_db_ready() -> None:
    """Lifespan calls this after init_engine + a SELECT 1 probe succeeds."""
    _state.db_ready = True
    _state.failures.pop("db", None)


def mark_jwks_warm() -> None:
    """Lifespan calls this after warm_jwks(settings) returns successfully."""
    _state.jwks_warm = True
    _state.failures.pop("jwks", None)


def record_failure(component: str, reason: str) -> None:
    """Record a boot-time failure for a specific component.

    Lifespan calls this when a non-critical readiness step fails. The
    component string ("db", "jwks", "settings") is used as the dict
    key so a later success replaces the entry.
    """
    _state.failures[component] = reason
    _state.last_error = f"{component}: {reason}"


def is_ready() -> bool:
    """Return True only when ALL readiness flags are set."""
    return _state.settings_loaded and _state.db_ready and _state.jwks_warm


def snapshot() -> dict[str, object]:
    """Return a JSON-serializable view of the current state.

    Used by GET /ready. Includes per-component booleans plus a
    consolidated `ready` boolean and any recent failure reasons.
    """
    return {
        "ready": is_ready(),
        "settings_loaded": _state.settings_loaded,
        "db_ready": _state.db_ready,
        "jwks_warm": _state.jwks_warm,
        "failures": dict(_state.failures),
    }


def reset_for_tests() -> None:
    """Test helper: wipe state between tests."""
    _state.db_ready = False
    _state.jwks_warm = False
    _state.settings_loaded = False
    _state.last_error = None
    _state.failures.clear()
