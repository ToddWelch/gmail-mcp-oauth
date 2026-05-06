"""Environment-driven configuration.

All settings come from environment variables. Fail fast at import time
if a required variable is missing, so the service never starts in a
misconfigured state.

Two-key model
-------------
ENCRYPTION_KEY and STATE_SIGNING_KEY are both required and MUST be
distinct. The former is the Fernet key that encrypts OAuth refresh
tokens at rest; the latter signs OAuth `state` parameters during the
Google OAuth handshake. Sharing one key across both responsibilities
would cross-contaminate trust domains: a leak of either key would
compromise both the token store and the OAuth flow. We enforce the
"distinct" rule at config load time.

Both keys are validated against the Fernet shape (32 bytes URL-safe
base64) at load time. STATE_SIGNING_KEY is consumed by HMAC-SHA256
in oauth_state.py, which only requires "any sufficiently long byte
string." Constraining it to the same shape as ENCRYPTION_KEY makes
the operator experience uniform: one generator command, two distinct
outputs, paste both into the env. It also future-proofs the option to
swap in MultiFernet for state token rotation without a config break.

Key rotation
------------------
PRIOR_ENCRYPTION_KEYS is an optional comma-separated list of previous
ENCRYPTION_KEY values. The crypto layer uses MultiFernet to read old
ciphertext while writing new ciphertext under the current key. After
a re-encrypt pass, drop the old keys from the env. See
docs/GMAIL_MCP_DR_RUNBOOK.md for the full rotation procedure.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

# Backward compatibility re-exports; canonical home for these helpers
# is mcp_gmail._env_parsers and mcp_gmail._key_validators. Imports such
# as `from mcp_gmail.config import _validate_fernet_key` and
# `config_module._require` continue to resolve via these names.
from ._env_parsers import _bool, _int, _optional, _require  # noqa: F401
from ._key_validators import _validate_fernet_key  # noqa: F401


@dataclass(frozen=True)
class Settings:
    """Runtime configuration snapshot. Immutable after load()."""

    oauth_issuer_url: str
    oauth_jwks_url: str
    mcp_resource_url: str
    mcp_expected_scopes: tuple[str, ...]
    mcp_accept_client_id_aud: bool
    # Allowlist of provider-minted client_id values
    # whose presence in the JWT `aud` claim is acceptable when
    # `mcp_accept_client_id_aud` is True. Empty tuple disables the
    # tolerance even if the bool is true; load() refuses to start in
    # that combination so misconfiguration surfaces at boot rather
    # than at the first /mcp call. Source env var:
    # MCP_ACCEPTED_CLIENT_IDS (comma-separated).
    mcp_accepted_client_ids: tuple[str, ...]
    jwks_cache_ttl_seconds: int
    http_timeout_seconds: int
    database_url: str
    encryption_key: str
    state_signing_key: str
    log_level: str
    port: int
    # Google OAuth. Required when /oauth/start, /oauth2callback,
    # /oauth/disconnect are used; the bearer-only /mcp endpoint does
    # NOT require these. They are still required at load time so the
    # service refuses to start if Google integration is misconfigured;
    # the alternative (lazy-load + first-call error) hides the
    # misconfiguration until a user attempts to link an account.
    google_oauth_client_id: str
    google_oauth_client_secret: str
    google_oauth_redirect_url: str
    gmail_oauth_scopes: tuple[str, ...]
    # (low-severity hardening): MultiFernet key-ring support. When
    # `PRIOR_ENCRYPTION_KEYS` is set (comma-separated Fernet keys), the
    # crypto layer uses MultiFernet to read ciphertext that was written
    # under any prior key while writing new ciphertext under
    # `encryption_key`. Empty tuple is the default (single-key mode);
    # in that case the crypto layer instantiates a plain Fernet and
    # the hot path costs the same as it did . Field defaulted
    # to `()` so existing test constructors that build Settings
    # directly (without going through `load()`) keep working without
    # an explicit prior_encryption_keys argument.
    prior_encryption_keys: tuple[str, ...] = ()
    # MCP_ALLOWED_AUTH0_SUBS allowlist + allow_any
    # opt-in. Source env vars same names. Production fails to start
    # when allowlist empty AND allow_any=false.
    allowed_auth0_subs: tuple[str, ...] = ()
    allow_any_auth0_sub: bool = False

    @property
    def authorization_servers(self) -> tuple[str, ...]:
        """Authorization server URLs advertised in the PRM document.

        Standard OIDC providers serve OAuth2 metadata at the issuer
        domain, so the issuer URL doubles as the AS identifier. Listed
        as a tuple so future multi-AS configurations can be added
        without a breaking change to the PRM shape.
        """
        return (self.oauth_issuer_url,)

    @property
    def is_production(self) -> bool:
        """Railway production-environment detection.

        Railway sets RAILWAY_ENVIRONMENT_NAME for every deploy. The
        value is "production" (lowercased) on production deploys.
        Read here as a property so tests can monkeypatch the env var
        per-test without re-loading Settings.
        """
        return os.environ.get("RAILWAY_ENVIRONMENT_NAME", "").strip().lower() == "production"

    @property
    def requires_confirm_page(self) -> bool:
        """activate post-callback confirmation flow.

        True when allowlist length > 1 OR allow_any. In single-user
        mode the flow is dormant; callback persists inline directly
        into gmail_oauth_tokens. Matrix exercised by
        test_requires_confirm_page_matrix.
        """
        if self.allow_any_auth0_sub:
            return True
        return len(self.allowed_auth0_subs) > 1

    def is_auth0_sub_allowed(self, sub: str | None) -> bool:
        """allowlist membership check.

        True when allow_any OR `sub` is non-empty and in
        allowed_auth0_subs. A None/empty sub is always rejected
        even under allow_any so missing bearer claims never resolve
        to a valid principal.
        """
        if not sub or not isinstance(sub, str):
            return False
        if self.allow_any_auth0_sub:
            return True
        return sub in self.allowed_auth0_subs


# Backward compatibility re-export; canonical home for `load` is
# mcp_gmail._settings_loader. The import sits at module-tail to avoid a
# circular import: _settings_loader imports `Settings` from this
# module, so `Settings` must be defined first. Existing callers that do
# `from mcp_gmail.config import load` or `config_module.load()` continue
# to resolve through this re-export.
from ._settings_loader import load  # noqa: E402, F401
