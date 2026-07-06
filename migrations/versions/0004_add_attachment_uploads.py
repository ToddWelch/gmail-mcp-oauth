"""create attachment_uploads for the large-attachment upload-slot flow

Revision ID: 0004
Revises: 0003
Create Date: 2026-07-02

Adds the `attachment_uploads` table backing the upload-slot + handle
flow for large outbound attachments. An authenticated MCP tool mints a
single-use capability slot; the client curls raw file bytes to the
server referencing the slot; a later send/draft tool references the
slot by handle, attaches the stored bytes, and consumes it.

Pure ADDITIVE schema. No changes to existing tables. Single-deploy safe.

Column notes
------------
- `token_hash` (PK): SHA-256 hex of the raw capability token. The raw
  token is NEVER stored, so a DB leak yields no replayable credential.
- `encrypted_bytes`: Fernet ciphertext of the uploaded file, nullable
  so it is NULL at mint, set at upload, and NULLed again at consume and
  by the purge job (ciphertext-lifecycle requirement, mirrors
  oauth_pending_links.encrypted_refresh_token).
- `size_bytes`: PLAINTEXT byte length (matches Gmail's 25 MiB semantics
  and the per-user byte cap).
- CHECK `account_email = LOWER(account_email)` matches the discipline of
  gmail_oauth_tokens / oauth_pending_links.

Forward-only policy
-------------------
Per project policy schema only moves forward; `downgrade()` raises
NotImplementedError so an accidental `alembic downgrade -1` fails loudly
rather than dropping a table that may hold in-flight slots. To revert,
`git revert` the code and write a forward migration that drops the table.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0004"
down_revision: Union[str, Sequence[str], None] = "0003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "attachment_uploads",
        sa.Column("token_hash", sa.String(length=64), primary_key=True),
        sa.Column("auth0_sub", sa.String(length=255), nullable=False),
        sa.Column("account_email", sa.String(length=320), nullable=False),
        sa.Column("filename", sa.String(length=256), nullable=True),
        sa.Column("mime_type", sa.String(length=128), nullable=True),
        sa.Column("size_bytes", sa.Integer(), nullable=True),
        # Fernet ciphertext; nullable so consume/purge can NULL it in the
        # same transaction as the state change (MVCC tuple-persistence
        # defense).
        sa.Column("encrypted_bytes", sa.LargeBinary(), nullable=True),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("expires_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("uploaded_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("consumed_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.CheckConstraint(
            "account_email = LOWER(account_email)",
            name="ck_attachment_uploads_email_lowercase",
        ),
    )
    op.create_index(
        "ix_attachment_uploads_auth0_sub",
        "attachment_uploads",
        ["auth0_sub"],
    )
    op.create_index(
        "ix_attachment_uploads_expires_at",
        "attachment_uploads",
        ["expires_at"],
    )


def downgrade() -> None:
    raise NotImplementedError(
        "Schema only moves forward in this project. To remove "
        "attachment_uploads, write a new forward migration that drops "
        "the table after confirming no in-flight slots remain."
    )
