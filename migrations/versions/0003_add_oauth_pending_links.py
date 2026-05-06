"""create oauth_pending_links for the post-callback confirmation flow

Revision ID: 0003
Revises: 0002
Create Date: 2026-05-04

Layer 2 of the OAuth identity-binding fix. Adds the
`oauth_pending_links` table that backs the post-callback confirmation
page. When the service runs in multi-user mode
(`requires_confirm_page=True`), the OAuth callback writes its
verified userinfo and encrypted refresh token here, then redirects
the user's browser to /oauth/confirm. Only after the user clicks
Confirm does the row migrate into `gmail_oauth_tokens`.

The table is pure ADDITIVE schema. No changes to existing
`gmail_oauth_tokens` or `oauth_state_nonces`. Single-deploy safe (no
expand-and-contract needed).

Idempotency notes
-----------------
- Postgres + SQLite both honor the CREATE TABLE / CREATE INDEX
  primitives used here.
- The CHECK constraint on `account_email = LOWER(account_email)`
  matches the discipline already established for `gmail_oauth_tokens`
  (see migration 0001).
- Re-running the migration on a fresh DB creates the table cleanly;
  re-running on a DB that already has it raises a duplicate-table
  error, which is the correct Alembic behavior (use `alembic stamp
  head` to recover from a manually pre-created table).

Forward-only policy
-------------------
Per project policy, schema only moves forward. The `downgrade()` below
raises NotImplementedError so an accidental `alembic downgrade -1`
fails loudly instead of silently dropping a table that operators may
have started writing pending rows into. To "revert" this migration, use
`git revert` on the squash commit; the orphaned `oauth_pending_links`
table is harmless because the reverted code never reads or writes it.
A follow-up forward migration can drop the table once the revert is
permanent.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0003"
down_revision: Union[str, Sequence[str], None] = "0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "oauth_pending_links",
        sa.Column("pending_token", sa.String(length=64), primary_key=True),
        sa.Column("auth0_sub", sa.String(length=255), nullable=False),
        sa.Column("account_email", sa.String(length=320), nullable=False),
        sa.Column("requested_account_email", sa.String(length=320), nullable=False),
        sa.Column("google_sub", sa.String(length=255), nullable=True),
        # Nullable so the consume/cancel/cleanup paths can NULL the
        # ciphertext in the same transaction as the row delete
        # (ciphertext-lifecycle requirement).
        sa.Column("encrypted_refresh_token", sa.LargeBinary(), nullable=True),
        sa.Column("granted_scope", sa.String(length=2048), nullable=False),
        sa.Column(
            "access_token_expires_at",
            sa.TIMESTAMP(timezone=True),
            nullable=True,
        ),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint(
            "account_email = LOWER(account_email)",
            name="ck_oauth_pending_links_email_lowercase",
        ),
    )
    op.create_index(
        "ix_oauth_pending_links_created_at",
        "oauth_pending_links",
        ["created_at"],
    )


def downgrade() -> None:
    raise NotImplementedError(
        "Schema only moves forward in this project. To remove "
        "oauth_pending_links, write a new forward migration that "
        "drops the table after confirming no pending rows are "
        "in flight. See migration 0002 for the documented pattern."
    )
