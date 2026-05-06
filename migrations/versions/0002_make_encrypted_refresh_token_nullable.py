"""make encrypted_refresh_token nullable for disconnect-wipe path

Revision ID: 0002
Revises: 0001
Create Date: 2026-04-29

(medium-severity hardening): the disconnect path now wipes the
encrypted refresh token at rest the moment a soft-revoke is recorded.
Wipe semantics: rather than blanking the column to NULL, we set it to
an empty BYTEA (`b""`) so that the column-level "row is non-empty"
invariants in `oauth_routes/status.py` continue to evaluate
`encrypted_refresh_token is not None`. The `has_token` invariant on
the status route remains:

    has_token = (encrypted_refresh_token is not None) AND (revoked_at is None)

After disconnect (which calls `soft_revoke` BEFORE the wipe), both
fields cooperate so `has_token` becomes False on a wiped row:
- `b""` is not None  -> True (left side)
- `revoked_at is None` -> False (right side, populated by soft_revoke)
- AND -> False

The "soft_revoke before wipe" ordering is non-negotiable. The wipe
helper itself enforces it by setting `revoked_at` if it is not already
populated.

Why nullable rather than NOT NULL with `b""`
--------------------------------------------
A security review called out that retaining the ciphertext at rest
gives an attacker who later compromises the database an offline
target for Fernet brute-force on revoked accounts. Setting it to
`b""` (still NOT NULL) would technically satisfy "no ciphertext at
rest" but loses the ability to model an empty-by-NULL state for any
future migration that wants a tri-state (active / revoked / never-set).
We make the column nullable here so a follow-up that prefers NULL on
revoked rows is not blocked by the schema. The disconnect-wipe code path writes
`b""` for compatibility with the existing `has_token` check on
status.py:88, which the design notes document.

Forward-revert recipe (schema only moves forward in this project)
-----------------------------------------------------------------
A `downgrade()` that restored NOT NULL would refuse on any row whose
`encrypted_refresh_token` was already wiped to NULL by a future code
revision. Per project policy, schema only moves forward. To "revert"
this migration:

1. Open a new revert PR with a new forward migration (e.g. 0003) that
   re-applies NOT NULL after first backfilling any NULL rows to `b""`:

       UPDATE gmail_oauth_tokens
       SET encrypted_refresh_token = ''
       WHERE encrypted_refresh_token IS NULL;
       ALTER TABLE gmail_oauth_tokens
       ALTER COLUMN encrypted_refresh_token SET NOT NULL;

2. Land that migration through the standard branch + PR review
   flow.

The `downgrade()` below raises NotImplementedError to enforce the
forward-only policy. Local dev iterating with `alembic downgrade` will
hit the explicit error rather than silently corrupting the schema.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0002"
down_revision: Union[str, Sequence[str], None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # batch_alter_table emits Postgres ALTER COLUMN directly and drops
    # back to SQLite's "rebuild table" recipe transparently. Without
    # batch mode, SQLite parses but does not implement
    # `ALTER COLUMN ... DROP NOT NULL`, which would block local
    # dev/test environments using SQLite.
    with op.batch_alter_table("gmail_oauth_tokens") as batch_op:
        batch_op.alter_column(
            "encrypted_refresh_token",
            existing_type=sa.LargeBinary(),
            nullable=True,
        )


def downgrade() -> None:
    raise NotImplementedError(
        "Schema only moves forward in this project. To re-tighten this column "
        "to NOT NULL, write a new forward migration that backfills NULL "
        "rows to b'' and then issues ALTER COLUMN ... SET NOT NULL. See "
        "the module docstring for the full recipe."
    )
