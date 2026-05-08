# Contributing

Thanks for your interest in mcp-gmail.

## Development setup

1. Clone the repo.
2. `cd mcp-gmail` (if extracting from the monorepo) or stay at the
   repo root for the standalone repo.
3. Set up a Python 3.11 virtual environment.
4. `pip install -e ".[dev]"` (matches the README quickstart and
   installs the package in editable mode plus the dev extras
   declared in `pyproject.toml`). The pinned `requirements.lock`
   and `requirements-dev.lock` files are also checked in for
   reproducible CI installs; use them with
   `pip install -r requirements.lock -r requirements-dev.lock`
   when an exact pin set is required.
5. Copy `.env.example` to `.env` and fill in your Auth0 + Google
   OAuth + database values.
6. Run `pytest` to confirm the test suite is green.

## Code style

- Python: `ruff check .` and `ruff format .` must pass before
  opening a PR. The project uses ruff's default ruleset plus the
  rules configured in `pyproject.toml`.
- All public functions have type hints.
- Files stay under 300 LOC; split when a file has two distinct
  responsibilities.

## Tests

- Every behavior change ships with a test.
- Bug fixes ship with a regression test that fails before the fix.
- `pytest --cov=mcp_gmail` should report >= 90% coverage.

## Design conventions

- Labels like `Decision N` and `Item N` in source comments and
  docstrings reference design discussions captured in the project's
  design history. They are first-party design commentary preserved
  intentionally; do not strip them as stale references.

## Pull requests

- Open against `main`.
- Squash merge.
- Conventional Commits format on the squash commit subject:
  `feat: ...`, `fix: ...`, `chore: ...`, `refactor: ...`,
  `docs: ...`.
- Branch protection requires all CI checks pass before merge.

## Reporting bugs and security issues

- Bugs: open a GitHub issue with reproduction steps.
- Security: see `SECURITY.md`.
