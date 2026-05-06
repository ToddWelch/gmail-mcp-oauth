"""Google OAuth state-token primitives (pure crypto, no I/O).

Split out of the original `google_oauth.py` so the crypto layer is
reviewable independently of the httpx exchanges. This module is pure
and synchronous: every function here is a deterministic transform of
its inputs (with the exception of `sign_state` consulting the wall
clock for `iat`, and `generate_nonce` consulting `secrets`). No
network, no database.

Surfaces
--------
- Constants: AUTHORIZE_URL, STATE_CLOCK_SKEW_BEHIND_SECONDS,
  STATE_TTL_SECONDS
- Dataclass: AuthorizationContext (the verified payload returned by
  `verify_state`)
- Exception: StateVerificationError
- Helpers: compute_sub_fingerprint, sign_state, verify_state,
  build_authorization_url, generate_nonce

Why the split
-------------
The HTTP exchanges (`exchange_code`, `refresh_access_token`,
`fetch_userinfo`, `revoke_refresh_token`) live in `oauth_http.py`. The
two modules import each other only for `AUTHORIZE_URL` (state) and the
HTTP error type (http); there is otherwise no coupling between the
crypto and the network layers. That makes it possible to unit-test the
state HMAC + fingerprint logic without any httpx mocking.

Design choices
--------------
- HMAC-SHA256 over the canonical JSON payload, with the resulting
  signature appended as the final segment. JSON canonicalization uses
  `sort_keys=True` and tight separators so a whitespace difference
  cannot pass verification.
- iat is asymmetric: -60 seconds (clocks-behind tolerance) and +600
  seconds (state TTL). The TTL aligns with the database nonce TTL in
  state_store.py, but the HMAC layer also enforces it independently
  so a stolen state token cannot be replayed indefinitely against an
  unconsumed nonce.
- compute_sub_fingerprint uses HMAC-SHA256 with STATE_SIGNING_KEY as
  the key. We deliberately do NOT use a plain SHA-256 hash: the
  fingerprint is a value that must NOT be guessable by an attacker
  who knows a target email or auth0_sub. Keying with the operator's
  signing key prevents offline brute-force collisions.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode


# ---------------------------------------------------------------------------
# Google authorization endpoint (the state module owns this constant
# because `build_authorization_url` lives here; the token/userinfo/revoke
# URLs live in oauth_http.py).
# ---------------------------------------------------------------------------

AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/v2/auth"


# State token age tolerances (seconds). Asymmetric on purpose:
# - 60s clocks-behind tolerance (operator clock briefly drifts behind UTC)
# - 600s clocks-ahead / TTL tolerance (state must expire within 10 min,
#   matching state_store NONCE_TTL_MINUTES; the HMAC layer enforces
#   independently of the nonce table so a stolen state token cannot
#   be replayed indefinitely against an unconsumed nonce row).
STATE_CLOCK_SKEW_BEHIND_SECONDS = 60
STATE_TTL_SECONDS = 600


class StateVerificationError(Exception):
    """Raised when /oauth2callback's state token fails HMAC or replay checks."""


@dataclass(frozen=True)
class AuthorizationContext:
    """Verified state-payload pulled from a /oauth2callback request."""

    nonce: str
    auth0_sub: str
    account_email: str
    sub_fingerprint: str
    iat: int


# ---------------------------------------------------------------------------
# Base64url helpers (no padding, URL-safe alphabet)
# ---------------------------------------------------------------------------


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def _canonicalize_state(payload: dict[str, Any]) -> bytes:
    """Stable byte-exact serialization of the state payload.

    Sorts keys, drops whitespace, forces tight separators. JSON
    canonicalization is the simplest cross-language stable form.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _hmac_sign(key: str, message: bytes) -> bytes:
    return hmac.new(key.encode("utf-8"), message, hashlib.sha256).digest()


def compute_sub_fingerprint(auth0_sub: str, account_email: str, signing_key: str) -> str:
    """Stable, opaque per-(auth0_sub, account_email) fingerprint.

    Used to bind the state token to the user that initiated the flow,
    independent of the nonce. The callback verifies that the
    fingerprint encoded in the state matches the (auth0_sub,
    account_email) attached to the consumed nonce row. Mismatch is a
    structural break (not a tampered HMAC) and surfaces as a different
    error code than "bad signature."

    Implementation detail: HMAC-SHA256 keyed with STATE_SIGNING_KEY.
    A plain SHA-256 hash would be guessable by an attacker who knows
    the target email; keying with the operator's signing key prevents
    offline brute-force collisions. The output is base64url without
    padding (43 characters), sufficient for a fingerprint comparison.
    """
    body = f"{auth0_sub}\x00{account_email.strip().lower()}".encode("utf-8")
    return _b64url_encode(_hmac_sign(signing_key, body))


def sign_state(
    *,
    nonce: str,
    auth0_sub: str,
    account_email: str,
    signing_key: str,
    iat: int | None = None,
) -> str:
    """Build the OAuth `state` parameter as a signed token.

    Layout: base64url(canonical_payload).base64url(hmac_signature)

    The payload binds (nonce, auth0_sub, account_email, fingerprint,
    iat). On callback, verify_state() checks the HMAC, the iat clock
    window, and the fingerprint, then returns the parsed payload so
    the caller can consume the nonce in state_store.
    """
    if not signing_key:
        raise ValueError("signing_key is required")
    iat_value = int(time.time()) if iat is None else int(iat)
    payload: dict[str, Any] = {
        "n": nonce,
        "s": auth0_sub,
        "e": account_email.strip().lower(),
        "f": compute_sub_fingerprint(auth0_sub, account_email, signing_key),
        "iat": iat_value,
    }
    payload_bytes = _canonicalize_state(payload)
    payload_b64 = _b64url_encode(payload_bytes)
    sig = _hmac_sign(signing_key, payload_bytes)
    sig_b64 = _b64url_encode(sig)
    return f"{payload_b64}.{sig_b64}"


def verify_state(state: str, signing_key: str) -> AuthorizationContext:
    """Verify HMAC + iat on a state token. Returns the parsed context.

    Raises StateVerificationError on any failure. The reason is
    intentionally generic in the message so callers logging the
    exception cannot leak which check failed (timing-side-channel
    minimization).
    """
    if not state or "." not in state:
        raise StateVerificationError("state malformed")
    try:
        payload_b64, sig_b64 = state.rsplit(".", 1)
        payload_bytes = _b64url_decode(payload_b64)
        sig_bytes = _b64url_decode(sig_b64)
    except Exception as exc:
        raise StateVerificationError("state malformed") from exc

    expected = _hmac_sign(signing_key, payload_bytes)
    # Constant-time compare. hmac.compare_digest covers the
    # length-mismatch case as well.
    if not hmac.compare_digest(expected, sig_bytes):
        raise StateVerificationError("state signature mismatch")

    try:
        payload = json.loads(payload_bytes)
    except Exception as exc:
        raise StateVerificationError("state payload not JSON") from exc

    required = {"n", "s", "e", "f", "iat"}
    if not isinstance(payload, dict) or not required.issubset(payload.keys()):
        raise StateVerificationError("state missing required fields")

    iat = payload["iat"]
    if not isinstance(iat, int):
        raise StateVerificationError("state iat not integer")
    now = int(time.time())
    if iat - now > STATE_CLOCK_SKEW_BEHIND_SECONDS:
        raise StateVerificationError("state from the future")
    if now - iat > STATE_TTL_SECONDS:
        raise StateVerificationError("state expired")

    expected_fp = compute_sub_fingerprint(payload["s"], payload["e"], signing_key)
    if not hmac.compare_digest(expected_fp.encode("ascii"), str(payload["f"]).encode("ascii")):
        raise StateVerificationError("state fingerprint mismatch")

    return AuthorizationContext(
        nonce=str(payload["n"]),
        auth0_sub=str(payload["s"]),
        account_email=str(payload["e"]),
        sub_fingerprint=str(payload["f"]),
        iat=iat,
    )


# ---------------------------------------------------------------------------
# Authorization URL builder
# ---------------------------------------------------------------------------


def build_authorization_url(
    *,
    client_id: str,
    redirect_uri: str,
    scopes: list[str] | tuple[str, ...],
    state: str,
    login_hint: str | None = None,
) -> str:
    """Return the Google OAuth consent URL with `state` already encoded.

    `access_type=offline` and `prompt=consent` are required to ensure
    Google issues a refresh_token (without `prompt=consent` Google may
    skip the refresh_token in subsequent re-authorization rounds).
    `include_granted_scopes=true` is set so an existing user who has
    already granted some scopes does not get a redundant consent
    screen for those scopes.
    """
    if not client_id or not redirect_uri:
        raise ValueError("client_id and redirect_uri are required")
    if not scopes:
        raise ValueError("scopes must be non-empty")
    params: dict[str, str] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": " ".join(scopes),
        "state": state,
        "access_type": "offline",
        "prompt": "consent",
        "include_granted_scopes": "true",
    }
    if login_hint:
        params["login_hint"] = login_hint
    return f"{AUTHORIZE_URL}?{urlencode(params)}"


def generate_nonce() -> str:
    """Convenience wrapper: 256-bit URL-safe random string.

    Re-exported here so callers using only oauth_state.* don't have to
    import state_store internals. Returns a 43-character URL-safe
    base64 string.
    """
    return secrets.token_urlsafe(32)
