# Gmail MCP OAuth Flow

This document covers the operator setup, trust-chain rationale, and
smoke steps for the Google OAuth 2.0 authorization-code flow added in
the `mcp-gmail` service. The allowlist + post-callback-confirmation defenses described below add
two new layers to that flow: the `MCP_ALLOWED_AUTH0_SUBS` allowlist
gate and the `/oauth/confirm` post-callback confirmation page.

The flow lets a Claude.ai user (authenticated via Auth0 to mcp-gmail)
link one or more Google mailboxes. Each link produces an encrypted
refresh token persisted in `gmail_oauth_tokens`.

## Endpoints

| Endpoint | Auth | Purpose |
|----------|------|---------|
| `GET /oauth/start?account_email=...&redirect=true` | Bearer (Auth0) + allowlist | Begin the handshake. Allowlist gate returns 403 if the bearer's `auth0_sub` is not in `MCP_ALLOWED_AUTH0_SUBS`. Mints a single-use nonce, signs an HMAC state token, returns Google's consent URL (or 302-redirects). |
| `GET /oauth2callback?code=...&state=...` | None | Google's redirect target. Verifies state HMAC + nonce + sub fingerprint, exchanges the code. In single-user mode (allowlist length 1, `MCP_ALLOW_ANY_AUTH0_SUB=false`) persists the encrypted refresh token inline. In multi-user mode (allowlist length > 1, OR `MCP_ALLOW_ANY_AUTH0_SUB=true`) stashes the verified data in `oauth_pending_links` and 303-redirects to `/oauth/confirm`. |
| `GET /oauth/confirm?pending_token=...` | None | Renders the confirmation page in multi-user mode. Returns the generic "invalid or expired" page when called outside multi-user mode. |
| `POST /oauth/confirm` | None | Form-encoded body with `pending_token` + `action=confirm` or `action=cancel`. Confirm consumes the pending row and upserts to `gmail_oauth_tokens` atomically. Cancel drops the pending row. Re-checks the allowlist before consuming so a sub removed during the 10-minute window cannot finalize. |
| `GET /oauth/status[?include_revoked=true]` | Bearer (Auth0) | List the bearer's linked accounts. Defaults to active rows only; pass `include_revoked=true` to include soft-revoked rows. Never returns secret material; only `has_token` and `is_revoked` booleans plus metadata. |
| `POST /oauth/disconnect` (`{"account_email": "..."}`) | Bearer (Auth0) | Soft-revoke the link. Best-effort revocation at Google. |

## Operator setup

### 1. Google Cloud Console

1. Open [Google Cloud Console > APIs & Services > Credentials](https://console.cloud.google.com/apis/credentials).
2. Create a project (or select an existing one).
3. Configure the OAuth consent screen:
   - User type: External (so any Google account can link).
   - App name, support email.
   - Scopes: add `openid`, `email`, and `https://www.googleapis.com/auth/gmail.readonly` for now. Send/draft tools require additional scopes; see GMAIL_MCP_TOOLS.md for the full list.
4. Create credentials > OAuth client ID:
   - Application type: Web application.
   - Authorized redirect URIs: add the EXACT value of `GOOGLE_OAUTH_REDIRECT_URL` (e.g. `https://gmail-mcp.example.com/oauth2callback`). Google compares byte-for-byte; trailing slash differences will fail.
5. Copy the Client ID and Client Secret.

### 2. Railway env vars

Set on the `mcp-gmail` Railway service:

| Variable | Source |
|----------|--------|
| `GOOGLE_OAUTH_CLIENT_ID` | Step 1, Client ID. |
| `GOOGLE_OAUTH_CLIENT_SECRET` | Step 1, Client Secret. |
| `GOOGLE_OAUTH_REDIRECT_URL` | Same value pasted into Google Cloud Console. Conventionally `<MCP_RESOURCE_URL>/oauth2callback`. |
| `GMAIL_OAUTH_SCOPES` | Optional. Defaults to `openid email https://www.googleapis.com/auth/gmail.readonly`. Whitespace-separated. |

The service refuses to start if any of `GOOGLE_OAUTH_CLIENT_ID`, `GOOGLE_OAUTH_CLIENT_SECRET`, or `GOOGLE_OAUTH_REDIRECT_URL` is missing.

### 3. Auth0-sub allowlist

Production operators MUST set `MCP_ALLOWED_AUTH0_SUBS` to a comma-separated, whitespace-tolerant list of `auth0|<id>` values that are permitted to call `/oauth/start`, the `connect_gmail_account` MCP tool, and `/mcp`. The service fails to start in production (`RAILWAY_ENVIRONMENT_NAME=production`) when the allowlist is empty AND `MCP_ALLOW_ANY_AUTH0_SUB=true` is not set.

| Variable | Required in prod? | Source / Format |
|----------|-------------------|------------------|
| `MCP_ALLOWED_AUTH0_SUBS` | yes (or set `MCP_ALLOW_ANY_AUTH0_SUB=true`) | Comma-separated `auth0\|<id>` strings. Whitespace around entries is stripped. Empty entries are dropped. |
| `MCP_ALLOW_ANY_AUTH0_SUB` | optional | `true` waives the allowlist gate (any bearer with a valid sub is allowed) AND forces the post-callback confirmation page on every callback. |

The allowlist gate fires at three boundaries:
- HTTP `/oauth/start`: 403 with non-leaky message.
- MCP tool `connect_gmail_account`: `bad_request_error` with the same message.
- HTTP `/mcp`: 403 with body `{"error": "auth0_sub_not_allowlisted"}`. NO `WWW-Authenticate` header (the bearer is valid; only the principal is denied).

## Operations: managing `MCP_ALLOWED_AUTH0_SUBS`

### Adding a new allowed sub

1. Identify the new user's Auth0 `sub` from the Auth0 dashboard (Users tab) or from a logged JWT payload.
2. In Railway, open the `mcp-gmail` service env editor.
3. Append the new sub to `MCP_ALLOWED_AUTH0_SUBS` (comma-separated, e.g. `auth0|sample-user,auth0|new-user`).
4. Save. Railway redeploys automatically.
5. Verify: Watch the deploy logs for "mcp-gmail starting"; the service must come up cleanly. Run `curl -i -H "Authorization: Bearer $NEW_USER_TOKEN" https://gmail-mcp.example.com/oauth/start?account_email=test@example.com` and confirm a 200 with `authorization_url` rather than a 403.

NOTE: When the allowlist length crosses from 1 to 2+, the service automatically activates `requires_confirm_page=True` and every subsequent OAuth callback (including for the previously-only-user) will redirect to `/oauth/confirm` for a click-to-confirm step. This is by design (Layer 2 of the consent-phishing defense activates only when the consent-phishing risk model becomes relevant).

### Removing an allowed sub

1. In Railway, open the `mcp-gmail` service env editor.
2. Edit `MCP_ALLOWED_AUTH0_SUBS` and delete the entry.
3. Save. Railway redeploys automatically.
4. Once the redeploy completes, the removed sub immediately loses access to all Gmail tools on the next `/mcp` request: the allowlist gate runs on every request (not only at link time), so a disallowed sub is rejected with HTTP 403 `{"error": "auth0_sub_not_allowlisted"}` before any tool dispatch. Revocation on the request path is effectively immediate.
5. Existing `gmail_oauth_tokens` rows for the removed sub remain in the database as orphaned encrypted ciphertext until a separate cleanup pass. The rows are unreachable through the API once the sub is delisted, but cleaning them up is a deliberate operator action: revoke the refresh token at Google (so the credential is dead even if the row is later exfiltrated) and `DELETE FROM gmail_oauth_tokens` for the affected sub.
6. If the removed sub had a pending row in flight (the user was on the `/oauth/confirm` page), the re-check at confirm POST drops the row when the action arrives. Worst case the row expires by the 10-minute TTL.

### Emergency multi-user opt-in

If you need to grant link permission to any bearer with a valid sub (e.g. demo flow with multiple test accounts) and don't want to enumerate them in the allowlist:

1. Set `MCP_ALLOW_ANY_AUTH0_SUB=true` in Railway.
2. Save. Railway redeploys.
3. Setting this flag automatically activates the post-callback confirmation page; every callback will redirect to `/oauth/confirm` so the user can confirm or cancel before any token is persisted.

The override is not appropriate for production multi-tenant traffic (it bypasses the allowlist defense entirely). Use it for demo / debug flows and revert when finished.

## Trust chain

### Why no bearer at `/oauth2callback`

Google performs the redirect from a third-party browser context where the original Auth0 bearer is not available. The trust mechanism at the callback is layered:

1. **HMAC-SHA256 over the state payload**, verified with `STATE_SIGNING_KEY`. Tampering breaks the signature; the constant-time `hmac.compare_digest` rejects it.
2. **Single-use nonce table** (`oauth_state_nonces`), consumed atomically with a conditional `UPDATE ... WHERE consumed_at IS NULL AND created_at >= cutoff`. A replay attempt fails because the second `consume_nonce` call returns 0 affected rows.
3. **`sub_fingerprint`** inside the state payload, recomputed from the verified payload's `auth0_sub` + `account_email` and the signing key. The fingerprint is base64url-encoded HMAC-SHA256 (43 characters, no padding) keyed with `STATE_SIGNING_KEY` over the concatenation `auth0_sub + "\x00" + lowercased(account_email)`. A structural mismatch (e.g. an attacker who somehow swaps the email field after a forgery) is caught here even if the HMAC happened to validate.
4. **Userinfo email check** after the code exchange. Google's `/userinfo` returns the actual logged-in email. The mailbox we persist under is always Google's userinfo email (the source of truth); if it differs from the email the flow was started for, we still persist the row, log a `WARN` with both addresses, and return an HTTP 200 JSON body of the shape `{"status": "connected_with_different_email", "requested": "...", "actual": "..."}` so the connector UI can display the discrepancy. The matching-email path returns the standard "Connected" HTML page.

### consent-phishing fix

The threat model: an attacker with a valid bearer to mcp-gmail can call `/oauth/start` (or `connect_gmail_account`) with `account_email=victim@example.com`, get a state-bound authorization URL, and lure the victim into clicking it. The state's HMAC + nonce + sub-fingerprint chain validates the URL's structure but says nothing about whether the browser hitting `/oauth2callback` belongs to the attacker or the victim. Without these defenses, a victim who completed the consent step would land their refresh token in `gmail_oauth_tokens` keyed under the ATTACKER's `auth0_sub`.

the service ships two layers, both active in code today:

1. **Allowlist gate (active in single-user mode).** `MCP_ALLOWED_AUTH0_SUBS` lists which Auth0 subs may call the OAuth-link entry points. In single-user mode the list typically contains exactly one sub: the operator who owns the deployment. The attack surface collapses to "an allowlisted user phishing another allowlisted user," which is structurally impossible with one entry.

2. **Post-callback confirmation page (dormant in single-user mode, automatic in multi-user).** When `requires_confirm_page=True` (allowlist length > 1, OR `MCP_ALLOW_ANY_AUTH0_SUB=true`), the callback does NOT persist the refresh token inline. Instead it stashes the verified userinfo + encrypted refresh token in `oauth_pending_links` (10-minute TTL, single-use, ciphertext NULLed in the same transaction as row delete on every exit path) and 303-redirects to `/oauth/confirm`. The confirmation page displays the principal label that owns the linkage; a victim sees "This service is asking to link <victim_email> under the user: <attacker_principal>" and clicks Cancel.

The confirmation page anti-phishing wording is bound verbatim:

> If you did not start this connection request yourself, click Cancel. Someone may be trying to gain access to your mail.

The two layers compose: an allowlisted attacker who phishes an allowlisted victim still loses because Layer 2 fires automatically when the allowlist expands beyond one entry.

Single-user residual risk: in the current single-user deployment, the allowlist length is 1, the confirmation page is dormant, and the consent-phishing risk is bounded by Layer 1 alone. The architectural fix in code (Layer 2) means the multi-user transition does not require a separate "remember to ship the consent-phishing fix" hop.

### PKCE (RFC 7636)

The service runs PKCE on every authorization-code flow. Confidential clients (server-side mcp-gmail with a `client_secret` that never reaches the browser) are not strictly required to use PKCE, but adopting it closes the residual stolen-code class without operator effort and aligns with OAuth 2.1's direction of travel.

Per-flow shape:

1. `/oauth/start` (and the `connect_gmail_account` MCP tool) calls `pkce.generate_verifier()` to mint a fresh 64-character base64url code verifier, then `pkce.compute_challenge(verifier)` to derive the S256 challenge.
2. The verifier is embedded inside the HMAC-signed state token under the `v` field. It rides round-trip in the state blob; no DB column is added. The state HMAC integrity-protects the verifier the same way it protects `nonce` / `sub` / `email`.
3. `build_authorization_url` appends `code_challenge=<challenge>` and `code_challenge_method=S256` to the consent URL.
4. `/oauth2callback` verifies state (HMAC + nonce + fingerprint), extracts `ctx.code_verifier`, and passes it as the `code_verifier` form field to Google's token endpoint. Google checks it against the challenge it saw at consent time.

The verifier is treated as a flow-scoped secret. It is never logged at any level: there is no log call that takes the verifier as a value, the `audit()` helper's keyword-only signature has no `code_verifier` parameter (so a future regression that tries to add one would raise `TypeError` at runtime), and the redacting filter in `logging_filters.py` is the defense-in-depth backstop. On the wire, the verifier appears only inside the form-urlencoded POST to Google's token endpoint over TLS.

`refresh_access_token` does not use PKCE. RFC 7636 applies to the authorization-code grant only; refresh-token grants are a separate flow with its own integrity protections (the refresh token itself is the secret bound to the original consent).

Legacy state tokens (minted before this rollout) have no `v` field. `verify_state` decodes them with `code_verifier=None`, and `/oauth2callback` hard-rejects rather than silently downgrade. The deploy window is short and the user can simply restart the flow; the security property holds for every accepted callback.

`STATE_SIGNING_KEY` rotation falls into the existing HMAC-failure path: a state minted under the old key fails signature verification under the new key and the user is sent through `/oauth/start` again, which mints a fresh state under the rotated key.

### Scope downgrade

Google may grant fewer scopes than the request asked for: the user can uncheck specific permissions on the consent screen. This is not an error in our flow.

- The `scope` field on the `gmail_oauth_tokens` row records the GRANTED scope returned in the token response, not the requested scope.
- Gmail tool dispatch checks the granted scope against the tool's required scopes before invocation. A Gmail-readonly link will refuse a `gmail_send` call cleanly rather than fail mid-API-call.

### User revoked at Google

If the user revokes the app at <https://myaccount.google.com/permissions>, our refresh token is dead from Google's side. The next call to `token_manager.get_access_token` triggers a refresh, Google returns `400 invalid_grant`, and the manager:

1. Soft-revokes the row (`revoked_at = now`, `updated_at = now`).
2. Drops the in-memory access-token cache.
3. Raises `TokenUnavailableError` so the tool dispatcher can surface "user must re-link" instead of a transient retry.

This is the expected behavior, not a bug. The `/oauth/status` endpoint will then show `has_token: false` and `revoked_at` populated for that account.

### Clock skew tolerance

State tokens carry an `iat` (issued-at) integer. Verification accepts:

- `iat` up to 60 seconds in the future (operator clock briefly behind UTC).
- `iat` up to 600 seconds in the past (10-minute TTL, matching `state_store.NONCE_TTL_MINUTES`).

The asymmetry is intentional: clocks drift behind much more often than ahead, but a state token older than 10 minutes is almost certainly a stale browser tab and a fresh `/oauth/start` is the safer move.

The `access_token_expires_at` column may be in the past on a brand-new row if the test fixture or operator backdated it; the `token_manager` treats any expiry within 60 seconds (or in the past) as "needs refresh" and triggers a refresh on first call. No special handling required.

## Local smoke steps

### Prerequisites

- Local Postgres available at `DATABASE_URL`. Suggested:

  ```bash
  docker run --rm -d -p 5433:5432 \
    -e POSTGRES_USER=gmail_mcp \
    -e POSTGRES_PASSWORD=gmail_mcp \
    -e POSTGRES_DB=gmail_mcp \
    postgres:16
  ```

- A real Google Cloud OAuth client. Add `http://localhost:8000/oauth2callback` to its Authorized Redirect URIs.
- An Auth0 access token for the configured tenant (the same kind the service verifies for `/mcp`). For local smoke you can mint one via the Auth0 dashboard's "Test" tab on the API or use any MCP-compatible CLI client.

### Run the service

```bash
cd mcp-gmail
source .venv/bin/activate
cp .env.example .env  # edit the Google fields + ENCRYPTION_KEY/STATE_SIGNING_KEY
alembic upgrade head
uvicorn mcp_gmail.server:app --port 8000 --reload
```

### Round trip

1. Start a flow:

   ```bash
   curl -i \
     -H "Authorization: Bearer $AUTH0_ACCESS_TOKEN" \
     "http://localhost:8000/oauth/start?account_email=you@example.com"
   ```

   Returns `{"authorization_url": "https://accounts.google.com/..."}`.

2. Open the `authorization_url` in a browser. Sign in with the matching Google account, accept the scopes. Google redirects back to `http://localhost:8000/oauth2callback?code=...&state=...`.

3. The callback page should render "Connected you@example.com." If you signed in with a different Google account than the one you passed as `account_email`, the response is HTTP 200 JSON of the shape `{"status": "connected_with_different_email", "requested": "you@example.com", "actual": "what-you-actually-signed-in-as@example.com"}` and the row is persisted under `actual`. If the response is an HTML error page (state expired, refresh-token-not-issued, code-exchange failure), check the service logs for the specific reason; errors in the user-facing page are intentionally generic to avoid leaking flow internals.

4. Status:

   ```bash
   curl -H "Authorization: Bearer $AUTH0_ACCESS_TOKEN" \
     http://localhost:8000/oauth/status
   ```

   Expect `{"accounts": [{"account_email": "you@example.com", "has_token": true, "is_revoked": false, ...}]}`. Default response is active rows only. Add `?include_revoked=true` to include soft-revoked rows; revoked rows return `is_revoked: true` and `has_token: false`.

5. Disconnect:

   ```bash
   curl -X POST \
     -H "Authorization: Bearer $AUTH0_ACCESS_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"account_email": "you@example.com"}' \
     http://localhost:8000/oauth/disconnect
   ```

   Expect `{"disconnected": true}`. A second call returns `{"disconnected": true}` (idempotent on already-revoked rows). A call with an unknown email returns `{"disconnected": false}`.

### What to verify in logs

- No `1//...` substrings (refresh tokens) anywhere.
- No `Bearer <opaque>...` substrings (the redacting filter rewrites these to `Bearer <redacted>` even if a callsite slips up).
- No `code=...` form values from authorization-code exchanges.
- Audit-shaped lines like `oauth_start: auth0_sub=auth0|... account_email=you@example.com` are expected and acceptable.

The redacting filter (`mcp_gmail.logging_filters.RedactingFilter`) is mounted on every root-logger handler at startup, so even third-party libraries (httpx, sqlalchemy, uvicorn) pass through it. The filter is defense-in-depth; the primary control is "do not log tokens at the callsite at all," verified by grep at PR review time.
