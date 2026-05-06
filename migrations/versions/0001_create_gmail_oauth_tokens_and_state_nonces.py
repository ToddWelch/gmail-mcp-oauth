"""create gmail_oauth_tokens and oauth_state_nonces

Revision ID: 0001
Revises:
Create Date: 2026-04-28

Initial table-creation migration for the mcp-gmail service. Creates
the two tables that the Google OAuth flow and the Gmail tools consume:

1. gmail_oauth_tokens: one row per (auth0_sub, account_email). Holds
   a Fernet-encrypted Google OAuth refresh token plus metadata.
2. oauth_state_nonces: single-use nonces backing the OAuth state
   parameter. Created at /oauth/start, consumed at /oauth2callback.

Schema notes
------------
- account_email is constrained CHECK(account_email = LOWER(account_email))
  so that future code paths writing mixed-case email values fail at the
  database boundary rather than silently bypass the case-insensitive
  unique constraint.
- The UNIQUE(auth0_sub, account_email) index doubles as the lookup
  index for queries by auth0_sub alone (Postgres uses left-prefix), so
  no separate single-column index on auth0_sub is created.
- google_sub is NULL until populated by the OAuth callback. Stable
  identity check across re-link events.
- last_used_at is NULL until populated by the tool dispatch path.
  Indexed so the day-6 re-auth ping cron can scan efficiently.
- revoked_at is NULL on active rows; soft-delete column for
  gmail_account_disconnect.
- nonce is the primary key on oauth_state_nonces. Conditional UPDATE
  on consume guarantees single-use atomicity.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0001"
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "gmail_oauth_tokens",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("auth0_sub", sa.String(length=255), nullable=False),
        sa.Column("account_email", sa.String(length=320), nullable=False),
        sa.Column("google_sub", sa.String(length=255), nullable=True),
        sa.Column("encrypted_refresh_token", sa.LargeBinary(), nullable=False),
        sa.Column("scope", sa.String(length=2048), nullable=False),
        sa.Column(
            "access_token_expires_at",
            sa.TIMESTAMP(timezone=True),
            nullable=True,
        ),
        sa.Column("last_used_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.UniqueConstraint(
            "auth0_sub",
            "account_email",
            name="uq_gmail_tokens_user_email",
        ),
        sa.CheckConstraint(
            "account_email = LOWER(account_email)",
            name="ck_gmail_tokens_email_lowercase",
        ),
    )
    op.create_index(
        "ix_gmail_tokens_last_used_at",
        "gmail_oauth_tokens",
        ["last_used_at"],
    )

    op.create_table(
        "oauth_state_nonces",
        sa.Column("nonce", sa.String(length=64), primary_key=True),
        sa.Column("auth0_sub", sa.String(length=255), nullable=False),
        sa.Column("account_email", sa.String(length=320), nullable=False),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("consumed_at", sa.TIMESTAMP(timezone=True), nullable=True),
    )
    op.create_index(
        "ix_oauth_state_nonces_created_at",
        "oauth_state_nonces",
        ["created_at"],
    )


def downgrade() -> None:
    raise NotImplementedError("Schema only moves forward.")
