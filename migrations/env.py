"""Standalone Alembic env for mcp-gmail.

Unlike a typical Flask app, mcp-gmail is FastAPI-based, so we
configure the Alembic context directly off the DATABASE_URL env var
and the SQLAlchemy 2.0 declarative base from `mcp_gmail.db`. The ORM
models are imported for their side effect of registering against
`Base.metadata`.
"""

from __future__ import annotations

import os
from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool

from alembic import context

# Import the models so SQLAlchemy registers them on Base.metadata. The
# imports look unused but their side effect (registration) is the
# entire point.
from mcp_gmail.db import Base, _normalize_database_url  # noqa: E402
from mcp_gmail import token_store  # noqa: F401, E402
from mcp_gmail import state_store  # noqa: F401, E402
from mcp_gmail import pending_link_store  # noqa: F401, E402

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)


def _database_url() -> str:
    url = os.environ.get("DATABASE_URL", "").strip()
    if not url:
        raise RuntimeError("DATABASE_URL must be set to run mcp-gmail migrations")
    return url


# Order matters here: scheme rewrite FIRST (operates on a literal
# string), THEN the `%` -> `%%` escape (covers ConfigParser
# interpolation in `config.set_main_option`). Reversing the order would
# leave the `%`-escape pass operating on a freshly substituted scheme
# and could mis-handle URLs whose passwords contain literal `%`.
config.set_main_option(
    "sqlalchemy.url",
    _normalize_database_url(_database_url()).replace("%", "%%"),
)


target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
