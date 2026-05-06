"""OAuth 2.1 bearer token validation against an OIDC provider's JWKS.

Validates: signature, iss, aud, exp, nbf. Scopes checked against
MCP_EXPECTED_SCOPES if set. JWKS fetched from settings.oauth_jwks_url
and cached.

MCP_ACCEPT_CLIENT_ID_AUD=true accepts non-resource-URL aud values
(DCR-minted client_ids on some OIDC providers); default false. The
MCP_ACCEPTED_CLIENT_IDS allowlist narrows that tolerance further.
JWKS fetches are async with a 30-second throttle and a 60-second
negative cache so a transient issuer outage does not stampede the
endpoint.
"""

from __future__ import annotations

import asyncio
import collections
import logging
import time
from dataclasses import dataclass, field
from typing import Any

import httpx
import jwt
from jwt.algorithms import RSAAlgorithm

from .config import Settings

logger = logging.getLogger(__name__)


# (medium-severity hardening): JWKS refresh hardening.
# 30s throttle + 60s negative cache (FIFO-bounded) + async fetch
# under a lazy asyncio.Lock. Bounds outbound JWKS calls so a flood
# of malformed-JWT requests with random kids cannot amplify into a
# JWKS-fetch flood. Lock is lazy so module import has no running-loop
# requirement and reset_cache_for_tests can re-allocate cleanly.
REFRESH_THROTTLE_SECONDS = 30.0
NEGATIVE_CACHE_TTL_SECONDS = 60.0
NEGATIVE_CACHE_MAX_ENTRIES = 256


class AuthError(Exception):
    """Raised when token validation fails. Carries a short reason code."""

    def __init__(self, reason: str, detail: str | None = None):
        super().__init__(detail or reason)
        self.reason = reason
        self.detail = detail


@dataclass
class _JWKSCache:
    """TTL cache holding parsed JWKS keys + throttle/negative-cache state.

    last_refresh_attempt: monotonic timestamp of last refresh attempt
    (success or failure); drives the 30s throttle. negative_cache:
    ordered dict of kid -> first-miss monotonic time; FIFO-bounded
    at NEGATIVE_CACHE_MAX_ENTRIES.
    """

    keys_by_kid: dict[str, Any] = field(default_factory=dict)
    fetched_at: float = 0.0
    last_refresh_attempt: float = 0.0
    negative_cache: "collections.OrderedDict[str, float]" = field(
        default_factory=collections.OrderedDict
    )


_cache = _JWKSCache()

# Lazy asyncio.Lock per the prescribed pattern.
_jwks_refresh_lock: asyncio.Lock | None = None


def _get_refresh_lock() -> asyncio.Lock:
    """Lazily construct the JWKS refresh lock inside the running event loop."""
    global _jwks_refresh_lock
    if _jwks_refresh_lock is None:
        _jwks_refresh_lock = asyncio.Lock()
    return _jwks_refresh_lock


async def _fetch_jwks(url: str, timeout: int) -> dict[str, Any]:
    """Fetch the JWKS document asynchronously."""
    async with httpx.AsyncClient(timeout=timeout) as client:
        response = await client.get(url)
        response.raise_for_status()
        return response.json()


async def _refresh_cache(settings: Settings) -> None:
    """Refresh JWKS from the issuer, parsing each key into an RSA verifier."""
    logger.info("Refreshing JWKS from %s", settings.oauth_jwks_url)
    _cache.last_refresh_attempt = time.monotonic()
    doc = await _fetch_jwks(settings.oauth_jwks_url, settings.http_timeout_seconds)
    keys = doc.get("keys") or []
    parsed: dict[str, Any] = {}
    for jwk in keys:
        kid = jwk.get("kid")
        if not kid:
            continue
        # RSAAlgorithm.from_jwk accepts either a JSON string or dict.
        parsed[kid] = RSAAlgorithm.from_jwk(jwk)
    _cache.keys_by_kid = parsed
    _cache.fetched_at = time.monotonic()
    # Successful refresh clears any negative-cache entries that the
    # new key set now resolves.
    if _cache.negative_cache:
        for kid in list(_cache.negative_cache):
            if kid in parsed:
                _cache.negative_cache.pop(kid, None)


def _record_negative(kid: str) -> None:
    """Add a kid to the negative cache with FIFO eviction at the cap."""
    now = time.monotonic()
    nc = _cache.negative_cache
    nc.pop(kid, None)
    nc[kid] = now
    while len(nc) > NEGATIVE_CACHE_MAX_ENTRIES:
        nc.popitem(last=False)


def _negative_cache_hit(kid: str) -> bool:
    """Return True if kid is in the negative cache and not yet expired."""
    entry = _cache.negative_cache.get(kid)
    if entry is None:
        return False
    if time.monotonic() - entry > NEGATIVE_CACHE_TTL_SECONDS:
        _cache.negative_cache.pop(kid, None)
        return False
    return True


async def _get_signing_key(token: str, settings: Settings) -> Any:
    """Return the public key matching the token's kid (hardened)."""
    try:
        header = jwt.get_unverified_header(token)
    except jwt.exceptions.DecodeError as exc:
        raise AuthError("invalid_token", f"token is not a valid JWT: {exc}") from exc
    kid = header.get("kid")
    if not kid:
        raise AuthError("invalid_token", "token header has no kid")
    if _negative_cache_hit(kid):
        raise AuthError("invalid_token", f"no JWKS key matches kid={kid}")

    ttl = settings.jwks_cache_ttl_seconds
    lock = _get_refresh_lock()
    now = time.monotonic()
    if not _cache.keys_by_kid or (now - _cache.fetched_at) > ttl:
        async with lock:
            now = time.monotonic()
            stale = not _cache.keys_by_kid or (now - _cache.fetched_at) > ttl
            throttle_ok = (now - _cache.last_refresh_attempt) > REFRESH_THROTTLE_SECONDS
            if stale and throttle_ok:
                await _refresh_cache(settings)

    key = _cache.keys_by_kid.get(kid)
    if key is not None:
        return key

    # kid not found: try one throttled refresh, then negative-cache.
    async with lock:
        if kid in _cache.keys_by_kid:
            return _cache.keys_by_kid[kid]
        if (time.monotonic() - _cache.last_refresh_attempt) > REFRESH_THROTTLE_SECONDS:
            await _refresh_cache(settings)
        key = _cache.keys_by_kid.get(kid)
        if key is None:
            _record_negative(kid)
            raise AuthError("invalid_token", f"no JWKS key matches kid={kid}")
        return key


def reset_cache_for_tests() -> None:
    """Test helper: wipe the JWKS cache + lock between tests."""
    global _jwks_refresh_lock
    _cache.keys_by_kid = {}
    _cache.fetched_at = 0.0
    _cache.last_refresh_attempt = 0.0
    _cache.negative_cache.clear()
    _jwks_refresh_lock = None


async def warm_jwks(settings: Settings) -> None:
    """Public wrapper that primes the JWKS cache at boot.

    Lifespan startup calls this so the first authenticated /mcp request
    does not pay the JWKS-fetch latency, and so a misconfigured issuer
    URL surfaces during boot rather than at the first user-visible 401.

    The wrapper exists because `_refresh_cache` is module-private (the
    underscore prefix is load-bearing: external callers should not
    reach across the boundary). `warm_jwks` is the supported entry
    point. It acquires the same refresh lock the on-demand path uses
    so a parallel first request that races startup cannot duplicate
    the fetch.

    Failure mode: any exception raised by `_refresh_cache` (network
    error, bad JWKS document, etc.) propagates to the caller.
    Lifespan catches it and degrades gracefully (logs a warning,
    leaves the readiness flag clear, but lets the service serve
    /health and /ready=503 until the next on-demand refresh succeeds).
    """
    lock = _get_refresh_lock()
    async with lock:
        await _refresh_cache(settings)


def _validate_audience(claims: dict[str, Any], settings: Settings) -> None:
    """Audience check with MCP_ACCEPT_CLIENT_ID_AUD tolerance applied.

    Tolerance ON (conservative interpretation): EVERY
    aud entry must match the resource URL OR be in the
    MCP_ACCEPTED_CLIENT_IDS allowlist. Missing aud always fails.
    """
    aud = claims.get("aud")
    if aud is None:
        raise AuthError("invalid_aud", "token has no aud claim")

    aud_values: list[str]
    if isinstance(aud, str):
        aud_values = [aud]
    elif isinstance(aud, list):
        aud_values = [str(v) for v in aud]
    else:
        raise AuthError("invalid_aud", f"aud has unexpected type: {type(aud).__name__}")

    # Tolerance OFF: resource URL must appear; this is the default behavior.
    if not settings.mcp_accept_client_id_aud:
        if settings.mcp_resource_url in aud_values:
            return
        raise AuthError("invalid_aud", f"aud {aud_values!r} does not match resource URL")

    # Tolerance ON: every entry must be the resource
    # URL OR in the MCP_ACCEPTED_CLIENT_IDS allowlist (empty allowlist
    # + true bool rejected at config load).
    accepted = set(settings.mcp_accepted_client_ids)
    unrecognized = [v for v in aud_values if v != settings.mcp_resource_url and v not in accepted]
    if not unrecognized:
        logger.info(
            "Accepting token aud=%s (resource URL or allowlisted client_id, "
            "per MCP_ACCEPT_CLIENT_ID_AUD + MCP_ACCEPTED_CLIENT_IDS)",
            aud_values,
        )
        return
    raise AuthError(
        "invalid_aud",
        f"aud entries {unrecognized!r} are not allowlisted client_ids",
    )


def _validate_scopes(claims: dict[str, Any], settings: Settings) -> None:
    """Check that every expected scope is present in the token's scope claim."""
    if not settings.mcp_expected_scopes:
        return
    raw = claims.get("scope") or claims.get("scp") or ""
    if isinstance(raw, list):
        token_scopes = set(str(s) for s in raw)
    else:
        token_scopes = set(str(raw).split())
    missing = [s for s in settings.mcp_expected_scopes if s not in token_scopes]
    if missing:
        raise AuthError("insufficient_scope", f"missing scopes: {missing}")


async def validate_bearer_token(token: str, settings: Settings) -> dict[str, Any]:
    """Validate a JWT and return its claims dict. Async to support concurrent JWKS fetches.

    Raises AuthError on any validation failure.
    """
    if not token:
        raise AuthError("invalid_token", "empty token")

    try:
        signing_key = await _get_signing_key(token, settings)
    except AuthError:
        raise
    except httpx.HTTPError as exc:
        raise AuthError("jwks_unavailable", f"could not fetch JWKS: {exc}") from exc

    try:
        # Disable PyJWT's built-in audience check. We do our own so we
        # can apply the MCP_ACCEPT_CLIENT_ID_AUD tolerance.
        claims = jwt.decode(
            token,
            signing_key,
            algorithms=["RS256"],
            issuer=settings.oauth_issuer_url,
            options={"verify_aud": False, "require": ["exp", "iss"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise AuthError("expired_token", str(exc)) from exc
    except jwt.InvalidIssuerError as exc:
        raise AuthError("invalid_issuer", str(exc)) from exc
    except jwt.InvalidTokenError as exc:
        raise AuthError("invalid_token", str(exc)) from exc

    _validate_audience(claims, settings)
    _validate_scopes(claims, settings)
    return claims


def build_www_authenticate(settings: Settings, reason: str | None = None) -> str:
    """Build the WWW-Authenticate header (RFC 9728 + MCP auth spec)."""
    parts = [f'Bearer realm="{settings.mcp_resource_url}"']
    # rstrip avoids `//.well-known/...`; resource URL itself preserved
    # for byte-exact aud match elsewhere.
    resource_for_metadata = settings.mcp_resource_url.rstrip("/")
    parts.append(
        f'resource_metadata="{resource_for_metadata}/.well-known/oauth-protected-resource"'
    )
    if reason:
        parts.append(f'error="{reason}"')
    return ", ".join(parts)
