# Gmail MCP Disaster Recovery and Key Rotation Runbook

This runbook covers the secrets and disasters that the mcp-gmail
service is most exposed to. Each scenario lists detection, immediate
mitigation, and full recovery steps.

This document refers to the following primitives that ship with the service:
- MultiFernet via `PRIOR_ENCRYPTION_KEYS` for online ENCRYPTION_KEY
  rotation
- `/ready` for orchestrator-level readiness probes (separate from
  liveness `/health`)
- Hash-pinned dependencies via `requirements.lock` so a compromised
  upstream wheel cannot land in a routine deploy
- Non-root container user so a code-execution exploit has reduced
  filesystem reach

## 1. ENCRYPTION_KEY rotation (planned)

### Why rotate

ENCRYPTION_KEY is the Fernet key that encrypts every Google refresh
token at rest. The longer a single key has been in use, the larger
the blast radius if it leaks.

Quarterly rotation cadence is the suggested baseline. Trigger an
unscheduled rotation if any of the following has happened:
- The key was logged accidentally and the log destination is not
  fully under your control
- The key was sent over an unencrypted channel
- A staff member with key access has departed
- A subprocessor that handled the key has had a breach

### Procedure

The MultiFernet design lets the service decrypt under any prior key
while always writing new ciphertext under the current key. Rotation
is online; no user re-link is required.

1. Generate a fresh key:
   ```
   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
   ```
2. In Railway env vars for the production mcp-gmail service:
   - Set `PRIOR_ENCRYPTION_KEYS` to the CURRENT value of `ENCRYPTION_KEY`
     (so the service can still read existing rows during the cutover).
     If `PRIOR_ENCRYPTION_KEYS` already had a value, prepend the
     previous current key, comma-separated.
   - Set `ENCRYPTION_KEY` to the new key.
3. Save and let Railway redeploy. Watch the deploy logs:
   - `mcp-gmail starting:` line confirms boot.
   - `/health` returns 200 immediately.
   - `/ready` should return 200 within ~10 seconds.
4. Hit `GET /oauth/status` from a connected user to confirm reads
   still work (the existing rows decrypt under the prior key,
   transparently to the caller).
5. Run a re-encrypt sweep to migrate every existing row to the new
   key. The simplest path is "let natural traffic do it": every
   token-refresh path calls `upsert_token`, which encrypts the new
   refresh token under the current primary. After ~7 days every
   active row has been re-encrypted by ordinary refresh activity.

   For a faster sweep (e.g. when the rotation is response to a leak),
   run a one-shot re-encrypt script: read each row, decrypt with
   MultiFernet, re-encrypt under the primary key alone, write back.
   The script does not currently exist as a committed tool; write it
   ad hoc and discard. (Future work: ship `scripts/reencrypt.py`.)
6. Once all rows are re-encrypted, drop the prior key from
   `PRIOR_ENCRYPTION_KEYS` and redeploy. The service will refuse to
   start if the prior list contains the current key (defense against
   an operator forgetting step 6).

### Rollback

If the new key turns out to be wrong (paste error, etc.):
1. Restore `ENCRYPTION_KEY` to the previous value
2. Drop the new key from `PRIOR_ENCRYPTION_KEYS`
3. Redeploy

The service can decrypt under the prior key as long as
`PRIOR_ENCRYPTION_KEYS` carries it; rolling back is the same operation
as rolling forward, in reverse.

## 2. ENCRYPTION_KEY leak (unplanned)

### Detection

- Key appears in a logged stdout line (CI run, container log, etc.)
- Key appears in a leaked .env or screenshot
- Static analysis (e.g. GitGuardian) reports the key in a public repo

### Immediate mitigation (within minutes)

1. Generate a new key (per section 1).
2. Rotate per section 1 procedure.
3. Force-revoke every existing Google refresh token. Database query:
   ```sql
   UPDATE gmail_oauth_tokens
   SET revoked_at = NOW(),
       encrypted_refresh_token = ''::bytea,
       updated_at = NOW();
   ```
   This forces every user to re-link via `/oauth/start`. Painful but
   necessary: the leaked key plus a database snapshot would otherwise
   give an attacker every refresh token.
4. Notify users (out of band) that they must reconnect their Gmail
   accounts.

### Forensics

- Search container logs for the key string: `grep -F "<key>" *.log`
- Search GitHub history: `git log --all -p -S '<key>'`
- Check Railway env-var change history (Railway's env vars panel
  shows when each value was last modified)

## 3. Database compromise (unplanned)

### Scenarios

- Postgres connection string + credentials leaked
- Backup snapshot exfiltrated
- VPS storage cloned

### Immediate mitigation

1. Rotate the database password (Railway: Postgres -> Settings -> Reset).
2. Rotate ENCRYPTION_KEY (per section 2; the leaked DB without the
   key is safe-ish but treat both as compromised).
3. Force-revoke every refresh token (per section 2 step 3).
4. Notify users.

### Recovery

After rotation, users re-link normally. The mcp-gmail service does
not store anything else worth recovering: state nonces are short-lived
and self-expire; access tokens were never persisted; audit logs (if
enabled) live in Railway's log retention, not the application DB.

## 4. STATE_SIGNING_KEY leak

### Detection

Same surfaces as ENCRYPTION_KEY (logs, .env, repo).

### Mitigation

The blast radius is narrower: a leaked STATE_SIGNING_KEY lets an
attacker forge `/oauth2callback` state tokens and (with a stolen
nonce) complete an in-flight handshake under a different identity.
The nonce table's single-use invariant blocks replay, but a freshly
forged state can still win against a user who hasn't completed their
own /oauth/start within 10 minutes.

1. Generate a new STATE_SIGNING_KEY:
   ```
   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
   ```
2. Update the Railway env var; redeploy.
3. Existing in-flight /oauth/start handshakes (within 10 min) will
   fail at /oauth2callback because the cookie HMAC and state HMAC
   no longer verify under the new key. Users retry from the
   connector UI.

The service refuses to start if STATE_SIGNING_KEY equals
ENCRYPTION_KEY (or is in PRIOR_ENCRYPTION_KEYS), so an operator
typo cannot conflate the two.

## 5. Container compromise

### Scenarios

- A future code-execution vulnerability lets an attacker run shell
  commands inside the container.

### Mitigation built in

- The container runs as `appuser` (UID 10001), not root.
- Dependencies are hash-pinned, so the attacker cannot install a
  backdoored wheel by triggering a pip install at runtime (no pip
  inside the running container; install happens at build time only).

### Response

1. Rotate ENCRYPTION_KEY (the attacker may have read the env at runtime).
2. Rotate STATE_SIGNING_KEY (same reason).
3. Rotate the database password.
4. Force-revoke all refresh tokens.
5. Investigate the entry point (CVE in a dep, regression in our code,
   etc.) and patch.
6. Redeploy.

The hash-pinned lockfile means a routine `git pull` + Railway
redeploy after the fix will rebuild the container with the SAME
known-good wheels until you intentionally regenerate the lock.

## 6. Forced re-link (any scenario)

The user-visible procedure for "every user must reconnect" is:
1. Application UI shows that the Gmail connector is disconnected.
2. User clicks Reconnect, which hits `/oauth/start`.
3. Google consent screen appears.
4. User approves; `/oauth2callback` persists a fresh refresh token
   under the current ENCRYPTION_KEY.
5. Tools resume working.

There is no "log everyone out" admin action; the disconnect is
implicit in revoking + wiping every row's ciphertext. Users see
their connector as disconnected on their next attempted use.

## 7. Useful one-liners

Count active and revoked rows:
```sql
SELECT
    COUNT(*) FILTER (WHERE revoked_at IS NULL) AS active,
    COUNT(*) FILTER (WHERE revoked_at IS NOT NULL) AS revoked
FROM gmail_oauth_tokens;
```

Find the freshest row (sanity check that writes are happening):
```sql
SELECT auth0_sub, account_email, updated_at
FROM gmail_oauth_tokens
ORDER BY updated_at DESC
LIMIT 5;
```

Probe `/ready` from the VPS:
```bash
curl -sS https://<mcp-gmail-host>/ready | jq .
```

A 200 means the service is fully ready. A 503 with a body containing
`failures` tells you which boot step did not complete.

## 8. Open follow-ups (not)

- `scripts/reencrypt.py` for a fast post-rotation re-encrypt sweep.
- Periodic `/ready` re-check from the lifespan path so a JWKS issuer
  recovery flips readiness back to True without a full redeploy.
- DB-backed idempotency cache so a multi-replica deploy is safe (the
  replica guard's fail-closed gate goes away once this lands).
- A scheduled job that emails the on-call operator if /ready has
  been 503 for more than 5 minutes.
