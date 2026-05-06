# gmail-mcp-oauth

Multi-tenant Gmail MCP server with OAuth hardening. Drop in for any MCP-compatible client. FastAPI, Postgres, Railway-ready.

## What this is

mcp-gmail speaks MCP over HTTP. It is a production-shaped reference:
two-stage trust chain (Auth0 / OIDC for the operator, Google OAuth
2.0 per linked mailbox), Fernet-at-rest encryption for refresh
tokens, MultiFernet for online key rotation, an Auth0-sub allowlist
that can be updated without redeploy, and a post-callback
confirmation page that defeats consent-phishing in multi-user
deployments. The current tool surface is 32 tools (13 read + 14
write + 4 cleanup + 1 bootstrap).

## Who this is for

Developers evaluating an OAuth-authenticated Gmail MCP server for
use with their own MCP-compatible client, or security reviewers
walking through the JWT + OAuth + token-storage chain. The codebase
is sized as a portfolio piece: every file is under 300 LOC, every
behavior change ships with a test, and the OAuth security surface
is documented end-to-end in the operator guide.

## Architecture at a glance

```
+-----------+   OAuth 2.1 / DCR    +-----------+
| MCP       |  --------- bearer -> | mcp-gmail |
| client    |                      +-----------+
| (Claude,  |                            |
|  CLI,     |     Google OAuth 2.0       |
|  custom)  |  <----- per user ------->  |
+-----------+         each mailbox       v
                                  +-----------+
                                  | Gmail API |
                                  +-----------+
```

The MCP client authenticates to mcp-gmail via OAuth 2.1 / DCR
against an OIDC issuer (Auth0 in the reference deployment). That
bearer identifies the human operating the connector. Per linked
mailbox, mcp-gmail runs a Google OAuth 2.0 authorization-code flow;
the resulting refresh token is encrypted at rest and keyed under
the operator's Auth0 sub plus the Google mailbox address.

Two layers gate the `/oauth/start` and post-callback flow against
consent-phishing:

1. An allowlist of Auth0 subs (`MCP_ALLOWED_AUTH0_SUBS`) controls
   who may begin a link.
2. In multi-user mode (allowlist length > 1, or
   `MCP_ALLOW_ANY_AUTH0_SUB=true`), the callback stashes the
   verified refresh token in a short-lived `oauth_pending_links`
   row and 303-redirects to a confirmation page. The user clicks
   Confirm or Cancel; only Confirm persists the token.

See [`docs/GMAIL_MCP_OAUTH.md`](docs/GMAIL_MCP_OAUTH.md) for the
full trust-chain walkthrough.

## Quickstart

### 1. OIDC / Auth0 setup

1. Create an Auth0 application (or its OIDC-provider equivalent).
2. Create an Auth0 API; the API Identifier becomes
   `MCP_RESOURCE_URL` and is the audience the JWT must carry.
3. Allow Dynamic Client Registration on the application if your MCP
   client requires it.
4. Note the issuer URL, JWKS URL, and the API Identifier.

### 2. Google Cloud Console setup

1. Open Google Cloud Console > APIs & Services > Credentials.
2. Create or select a project; enable the Gmail API.
3. Configure the OAuth consent screen (External, app name, support
   email, scopes).
4. Create an OAuth 2.0 Client ID (Web application).
5. Add `<MCP_RESOURCE_URL>/oauth2callback` to Authorized Redirect
   URIs. Google compares byte-for-byte; trailing slash differences
   will fail.
6. Copy the Client ID and Client Secret.

### 3. Local development

```bash
cd mcp-gmail
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env
# Generate two distinct Fernet keys:
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
# Paste the two outputs into ENCRYPTION_KEY and STATE_SIGNING_KEY.

# Start a local Postgres (e.g. via docker run --rm -p 5433:5432 ...)
# and set DATABASE_URL accordingly. Then:
alembic upgrade head
uvicorn mcp_gmail.server:app --port 8000 --reload
```

Smoke checks:

```bash
# Health
curl http://localhost:8000/health

# Protected Resource Metadata (PRM)
curl http://localhost:8000/.well-known/oauth-protected-resource

# MCP unauthenticated (should 401 with WWW-Authenticate)
curl -i -X POST http://localhost:8000/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

### 4. Deploy on Railway (or any container platform)

The Dockerfile, `.env.example`, `DATABASE_URL`, and the listed
environment variables are sufficient for any container platform
that provides an attached Postgres. Railway is the reference
because the maintainer runs the service there; nothing in the code
is Railway-specific beyond reading `DATABASE_URL` at boot.

## Environment variables

| Variable | Required | Default | Purpose |
|----------|----------|---------|---------|
| `OAUTH_ISSUER_URL` | yes | | OIDC issuer URL, e.g. `https://dev-xxx.us.auth0.com`. |
| `OAUTH_JWKS_URL` | yes | | Usually `OAUTH_ISSUER_URL + /.well-known/jwks.json`. |
| `MCP_RESOURCE_URL` | yes | | Public URL of this service. Must match the API Identifier configured in your authorization server. |
| `MCP_EXPECTED_SCOPES` | optional | "" | Space-separated required scopes on inbound bearers. Empty by default. |
| `MCP_ACCEPT_CLIENT_ID_AUD` | optional | `false` | Tolerate `aud == client_id` on DCR-minted tokens. |
| `MCP_ACCEPTED_CLIENT_IDS` | optional | "" | Comma-separated allowlist of client IDs accepted as `aud` when tolerance is on. |
| `JWKS_CACHE_TTL_SECONDS` | optional | 300 | How long to cache the JWKS document. |
| `HTTP_TIMEOUT_SECONDS` | optional | 10 | Outbound timeout to JWKS / Google. |
| `MCP_ALLOWED_AUTH0_SUBS` | yes (in prod) | "" | Comma-separated allowlist of Auth0 subs permitted to link Gmail accounts and call Gmail tools. Required in production unless `MCP_ALLOW_ANY_AUTH0_SUB=true`. |
| `MCP_ALLOW_ANY_AUTH0_SUB` | optional | `false` | Emergency opt-in. When `true`, any authenticated sub is permitted, AND the post-callback confirmation page auto-activates. Bypasses the allowlist defense; revert when finished. |
| `DATABASE_URL` | yes | | Postgres connection URL. Railway injects automatically; the service accepts both `postgresql://` and `postgres://` forms. |
| `ENCRYPTION_KEY` | yes | | Fernet key for refresh-token at-rest encryption. |
| `PRIOR_ENCRYPTION_KEYS` | optional | | Comma-separated prior Fernet keys for online MultiFernet rotation. |
| `STATE_SIGNING_KEY` | yes | | HMAC key for OAuth state signing. Must NOT equal `ENCRYPTION_KEY`. |
| `LOG_LEVEL` | optional | INFO | Python logging level. |
| `PORT` | optional | 8000 | Bind port. Railway injects this automatically. |
| `MCP_GMAIL_REPLICA_COUNT` | optional | | If set to >1, startup fails closed (the per-key refresh-token lock is in-process, not cross-replica). |
| `GOOGLE_OAUTH_CLIENT_ID` | yes | | Google OAuth client id (from Google Cloud Console). |
| `GOOGLE_OAUTH_CLIENT_SECRET` | yes | | Google OAuth client secret. |
| `GOOGLE_OAUTH_REDIRECT_URL` | yes | | Public URL for Google's redirect. Must match exactly an Authorized Redirect URI in Google Cloud Console. Conventionally `<MCP_RESOURCE_URL>/oauth2callback`. |
| `GMAIL_OAUTH_SCOPES` | optional | `openid email gmail.readonly` | Whitespace-separated Gmail OAuth scopes to request. Override to broaden the default grant. |

## Tool reference

The service exposes 32 tools to MCP clients:

- 13 read tools (`read_email`, `search_emails`, `multi_search_emails`,
  `batch_read_emails`, `download_attachment`, `download_email`,
  `get_thread`, `list_inbox_threads`, `get_inbox_with_threads`,
  `modify_thread`, `list_email_labels`, `list_filters`, `get_filter`).
- 14 write tools (`send_email`, `create_draft`, `update_draft`,
  `list_drafts`, `send_draft`, `delete_draft`, `create_label`,
  `update_label`, `delete_label`, `modify_email_labels`,
  `create_filter`, `delete_filter`, `delete_email`,
  `batch_delete_emails`).
- 4 cleanup tools (`reply_all`, `batch_modify_emails`,
  `get_or_create_label`, `create_filter_from_template`).
- 1 bootstrap tool (`connect_gmail_account`).

See [`docs/GMAIL_MCP_TOOLS.md`](docs/GMAIL_MCP_TOOLS.md) for the
per-tool reference, scope table, audit log shape, and operational
notes.

## OAuth flow

See [`docs/GMAIL_MCP_OAUTH.md`](docs/GMAIL_MCP_OAUTH.md) for the
operator setup walkthrough, the trust-chain rationale, and the
allowlist + post-callback-confirmation defenses.

## Disaster recovery

See [`docs/GMAIL_MCP_DR_RUNBOOK.md`](docs/GMAIL_MCP_DR_RUNBOOK.md)
for MultiFernet key rotation, /ready vs /health semantics, and
operator runbooks for common failure modes.

## Two-key encryption model

The service requires TWO distinct cryptographic keys at boot:

| Variable | Algorithm | Purpose | Why separate |
|----------|-----------|---------|--------------|
| `ENCRYPTION_KEY` | Fernet (AES-128-CBC + HMAC-SHA256) | Encrypts Google refresh tokens at rest in Postgres. | The most sensitive secret in the system. A leak grants long-lived mailbox access. |
| `STATE_SIGNING_KEY` | HMAC-SHA256 | Signs the OAuth `state` parameter on `/oauth/start`, verifies it on `/oauth2callback`. | Tampering with state is a CSRF-on-OAuth vector. Compromise has different blast radius than `ENCRYPTION_KEY`. |

Both keys must be 32-byte URL-safe base64-encoded strings. The
service refuses to start if `ENCRYPTION_KEY == STATE_SIGNING_KEY`,
or if the new key is in `PRIOR_ENCRYPTION_KEYS`.

## Implementation notes

- **Use `email.message.EmailMessage`, not `email.mime.*`**. The
  legacy `MIMEText` / `MIMEMultipart` API has long-standing bugs
  with non-ASCII content, attachments, and message structure
  introspection. `EmailMessage` is the modern Python email API and
  is the only acceptable path for the `send_email` tool. Enforced
  in `gmail_tools/message_format.py`.
- **`send_email` accepts an optional `idempotency_key`**. When
  supplied, the server dedupes calls in-process for 60 seconds. The
  cache key is `(auth0_sub, account_email, idempotency_key)`, so
  two distinct callers can use the same opaque key without
  collision.
- **Attachment size cap is 25 MiB on the FINAL encoded message
  size**, not on raw input bytes. Base64 inflates binary by ~33%,
  so raw attachment data caps at ~18 MiB. Enforced in
  `gmail_tools/message_format.py::build_email_message`.
- **OAuth scope expansion is opt-in, not default-on**. The default
  `GMAIL_OAUTH_SCOPES` is `openid email gmail.readonly`. Write
  tools surface `scope_insufficient` with a structured
  `required_scopes` hint; users re-link with broader scopes from
  `/oauth/start` when needed. The default is NOT widened.

## Operations notes

- Allowlist add/remove: edit `MCP_ALLOWED_AUTH0_SUBS` and redeploy.
- Online key rotation: see the DR runbook.
- `/health` vs `/ready`: `/health` is liveness; `/ready` is full
  readiness including Postgres reachability and JWKS-fetch success.

## Per-replica concurrency constraint

`token_store.py` uses a per-(auth0_sub, account_email)
`asyncio.Lock` to serialize Google refresh-token requests. This
guarantees at most one in-flight refresh per token, which Google's
docs require to avoid invalidating the older access token mid-flight.

The lock dict lives in-process. Single-replica deployments are
correct; multi-replica deployments raise at startup unless
`MCP_GMAIL_REPLICA_COUNT` is explicitly cleared. The eventual
remediation when the service must scale out is a database row lock
(`SELECT FOR UPDATE` on the token row inside a transaction
spanning the refresh call).

## Testing

```bash
cd mcp-gmail
pytest -v
# Coverage gate fails below 80%.
ruff check .
ruff format --check .
```

### Postgres-in-CI regression lane

The mcp-gmail CI job boots a stock `postgres:16` service container,
runs `alembic upgrade head` against it, then runs the full pytest
suite with `MCPGMAIL_POSTGRES_TEST_URL` exported. That env var
unlocks the cases in `tests/test_postgres_migration.py`, which
exercise both the Alembic path and the runtime engine path against
a real Postgres. The CI workflow and the test fixtures both
deliberately use the bare `postgresql://` form (no `+psycopg`, no
`+psycopg2`); `_normalize_database_url` in `src/mcp_gmail/db.py`
rewrites the URL before it reaches SQLAlchemy. Rewriting the test
URL to a driver-explicit form silently disables the regression
guard.

## Related work

This implementation is a fresh Python rewrite. Prior art and
inspiration:

- [ArtyMcLabin/Gmail-MCP-Server](https://github.com/ArtyMcLabin/Gmail-MCP-Server)
  is the active community fork.
- [GongRzhe/Gmail-MCP-Server](https://github.com/GongRzhe/Gmail-MCP-Server)
  is the root upstream.

The Python rewrite was chosen for type safety, async-native HTTP,
and better fit with the OAuth + Postgres + Fernet stack. We monitor
both upstreams for issues, releases, and security advisories.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Security

See [`SECURITY.md`](SECURITY.md).

## License

MIT. See [`LICENSE`](LICENSE).
