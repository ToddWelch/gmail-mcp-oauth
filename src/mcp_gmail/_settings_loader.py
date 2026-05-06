"""Settings construction from the environment.

`load()` reads every required and optional environment variable, runs
the cross-cutting validations (key distinctness, Fernet shape,
production-mode fail-closed behaviour), and returns a frozen Settings
snapshot. Extracted from `config.py` so the dataclass + property
surface stays under the project's 300 LOC discipline; `config.py`
re-exports `load` from here so the public import path
`mcp_gmail.config.load` is unchanged.

Canonical home for `load`. Depends on `_env_parsers` (env-var
primitives), `_key_validators` (Fernet shape), and `config.Settings`
(the construction target).
"""

from __future__ import annotations

import os

from ._env_parsers import _bool, _int, _optional, _require
from ._key_validators import _validate_fernet_key
from .config import Settings


def load() -> Settings:
    """Read env and construct Settings. Raises RuntimeError on missing keys."""
    # OAUTH_ISSUER_URL and MCP_RESOURCE_URL are preserved exactly as
    # configured. They are used for strict string matches against JWT
    # `iss` and `aud` claims per RFC 7519, and Auth0 (and other
    # providers) emit the issuer with a trailing slash. Any
    # normalization here silently breaks token validation.
    issuer = _require("OAUTH_ISSUER_URL")
    jwks = _require("OAUTH_JWKS_URL")
    resource = _require("MCP_RESOURCE_URL")

    scopes_raw = _optional("MCP_EXPECTED_SCOPES", "")
    scopes = tuple(s for s in scopes_raw.split() if s)

    # (medium-severity hardening): in production environments the
    # MCP_EXPECTED_SCOPES list must be non-empty so the bearer token
    # validator actually enforces a scope check. The  default
    # of "" silently disabled scope enforcement, which made the
    # MCP_ACCEPT_CLIENT_ID_AUD tolerance window dangerously wide.
    # MCP_REQUIRE_SCOPES_OVERRIDE=false lets an operator bypass the
    # check for a brief migration window when a tightened scope set
    # is being staged. Default behavior in production is fail-closed.
    is_production = os.environ.get("RAILWAY_ENVIRONMENT_NAME", "").strip().lower() == "production"
    require_scopes_override = os.environ.get("MCP_REQUIRE_SCOPES_OVERRIDE", "").strip().lower()
    if is_production and not scopes and require_scopes_override != "false":
        raise RuntimeError(
            "MCP_EXPECTED_SCOPES is empty in production "
            "(RAILWAY_ENVIRONMENT_NAME=production). Configure at least one "
            "scope or set MCP_REQUIRE_SCOPES_OVERRIDE=false to acknowledge."
        )

    database_url = _require("DATABASE_URL")
    encryption_key = _require("ENCRYPTION_KEY")
    state_signing_key = _require("STATE_SIGNING_KEY")

    if encryption_key == state_signing_key:
        # Defense-in-depth: if an operator copy-pastes one value into
        # both slots we refuse to start. See config.py module docstring
        # for why the keys must be distinct.
        raise RuntimeError(
            "ENCRYPTION_KEY and STATE_SIGNING_KEY must be different values. "
            "Generate two separate keys with Fernet.generate_key()."
        )

    # Both keys must be Fernet-shaped (32 bytes URL-safe base64). See
    # _validate_fernet_key for rationale; STATE_SIGNING_KEY does not
    # technically need the Fernet shape (it feeds HMAC-SHA256), but
    # constraining it makes operator setup uniform and future-proofs
    # MultiFernet rotation.
    _validate_fernet_key(encryption_key, "ENCRYPTION_KEY")
    _validate_fernet_key(state_signing_key, "STATE_SIGNING_KEY")

    # PRIOR_ENCRYPTION_KEYS is an optional comma-separated
    # list of previous ENCRYPTION_KEY values. MultiFernet uses these
    # to decrypt ciphertext written under the old key while encrypting
    # new ciphertext under the current `encryption_key`. The list:
    #   - is order-sensitive (newest first; older keys later)
    #   - must contain only Fernet-shaped values
    #   - must NOT contain `encryption_key` (would be an operator
    #     mistake; suggests the rotation completed and the env was not
    #     trimmed) or `state_signing_key` (cross-trust-domain leak)
    # The validation runs at boot so misconfiguration surfaces before
    # the first OAuth callback rather than at decrypt time.
    prior_keys_raw = _optional("PRIOR_ENCRYPTION_KEYS", "")
    prior_keys = tuple(s.strip() for s in prior_keys_raw.split(",") if s.strip())
    seen_prior: set[str] = set()
    for idx, prior in enumerate(prior_keys):
        _validate_fernet_key(prior, f"PRIOR_ENCRYPTION_KEYS[{idx}]")
        if prior == encryption_key:
            raise RuntimeError(
                f"PRIOR_ENCRYPTION_KEYS[{idx}] equals ENCRYPTION_KEY. After "
                "rotation completes, remove the now-current key from the "
                "prior list to avoid silent confusion."
            )
        if prior == state_signing_key:
            raise RuntimeError(
                f"PRIOR_ENCRYPTION_KEYS[{idx}] equals STATE_SIGNING_KEY. The "
                "two trust domains must stay separate; do not pool them."
            )
        if prior in seen_prior:
            raise RuntimeError(
                f"PRIOR_ENCRYPTION_KEYS[{idx}] is duplicated. Each prior key "
                "must appear at most once."
            )
        seen_prior.add(prior)

    google_client_id = _require("GOOGLE_OAUTH_CLIENT_ID")
    google_client_secret = _require("GOOGLE_OAUTH_CLIENT_SECRET")
    google_redirect_url = _require("GOOGLE_OAUTH_REDIRECT_URL")

    # Default scopes: openid + email (for userinfo lookup) + minimal
    # Gmail readonly. Operators may extend this when send/draft tools
    # land; the env var lets operators tighten or loosen without a
    # code change. Whitespace-separated.
    scopes_default = " ".join(
        [
            "openid",
            "email",
            "https://www.googleapis.com/auth/gmail.readonly",
        ]
    )
    gmail_scopes_raw = _optional("GMAIL_OAUTH_SCOPES", scopes_default)
    gmail_scopes = tuple(s for s in gmail_scopes_raw.split() if s)
    if not gmail_scopes:
        raise RuntimeError("GMAIL_OAUTH_SCOPES must list at least one scope")

    # MCP_ACCEPTED_CLIENT_IDS is a comma-separated
    # allowlist of provider-minted client_id strings that are
    # acceptable as JWT `aud` values when MCP_ACCEPT_CLIENT_ID_AUD is
    # true. The plan trade-off: the bool acts as the safety latch
    # ("am I willing to accept anything other than the resource URL
    # at all?"); the allowlist is the substantive policy ("which
    # specific client_ids do I accept?"). Empty allowlist + true
    # bool is a misconfiguration; we refuse to start so it surfaces
    # at boot instead of validating wide-open at the first /mcp call.
    accept_client_id_aud = _bool("MCP_ACCEPT_CLIENT_ID_AUD", False)
    accepted_client_ids_raw = _optional("MCP_ACCEPTED_CLIENT_IDS", "")
    accepted_client_ids = tuple(s.strip() for s in accepted_client_ids_raw.split(",") if s.strip())
    if accept_client_id_aud and not accepted_client_ids:
        raise RuntimeError(
            "MCP_ACCEPT_CLIENT_ID_AUD=true requires MCP_ACCEPTED_CLIENT_IDS "
            "to list at least one allowed client_id. Configure both, or set "
            "MCP_ACCEPT_CLIENT_ID_AUD=false."
        )

    # Auth0-sub allowlist + allow_any toggle. Parser
    # is comma-separated, whitespace-tolerant; empty entries dropped.
    # No `auth0|<id>` shape validation (Auth0 namespaces vary by
    # connection); we compare verbatim against the JWT `sub` claim.
    # Hard fail-closed in production when allowlist empty AND
    # allow_any!=true so misconfiguration surfaces at deploy.
    allowed_subs_raw = _optional("MCP_ALLOWED_AUTH0_SUBS", "")
    allowed_subs = tuple(s.strip() for s in allowed_subs_raw.split(",") if s.strip())
    allow_any_auth0_sub = _bool("MCP_ALLOW_ANY_AUTH0_SUB", False)
    if is_production and not allowed_subs and not allow_any_auth0_sub:
        raise RuntimeError(
            "MCP_ALLOWED_AUTH0_SUBS is empty in production "
            "(RAILWAY_ENVIRONMENT_NAME=production). Configure at least "
            "one allowed Auth0 sub or set MCP_ALLOW_ANY_AUTH0_SUB=true "
            "to acknowledge multi-user opt-in."
        )

    return Settings(
        oauth_issuer_url=issuer,
        oauth_jwks_url=jwks,
        mcp_resource_url=resource,
        mcp_expected_scopes=scopes,
        mcp_accept_client_id_aud=accept_client_id_aud,
        mcp_accepted_client_ids=accepted_client_ids,
        jwks_cache_ttl_seconds=_int("JWKS_CACHE_TTL_SECONDS", 300),
        http_timeout_seconds=_int("HTTP_TIMEOUT_SECONDS", 10),
        database_url=database_url,
        encryption_key=encryption_key,
        prior_encryption_keys=prior_keys,
        state_signing_key=state_signing_key,
        log_level=_optional("LOG_LEVEL", "INFO"),
        port=_int("PORT", 8000),
        google_oauth_client_id=google_client_id,
        google_oauth_client_secret=google_client_secret,
        google_oauth_redirect_url=google_redirect_url,
        gmail_oauth_scopes=gmail_scopes,
        allowed_auth0_subs=allowed_subs,
        allow_any_auth0_sub=allow_any_auth0_sub,
    )
