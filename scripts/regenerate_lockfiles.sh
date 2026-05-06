#!/usr/bin/env bash
# Supply-chain hardening: regenerate the
# hash-pinned lockfiles consumed by the Dockerfile and CI.
#
# Usage
# -----
#   cd mcp-gmail
#   bash scripts/regenerate_lockfiles.sh
#
# What it does
# ------------
# Generates requirements.lock (production deps) and
# requirements-dev.lock (dev deps + test deps) from pyproject.toml
# using pip-compile (from pip-tools) with --generate-hashes. The
# resulting files are committed to the repo; the Dockerfile and CI
# install via `pip install --require-hashes -r <lockfile>` so any
# attempt to install a wheel whose SHA256 does not appear in the
# lock is refused.
#
# When to re-run
# --------------
# - After upgrading any direct dependency in pyproject.toml
# - After Dependabot opens a PR bumping a transitive dep
# - On a quarterly cadence even if no version moved (pull in any new
#   wheel hashes for the same versions, in case of compromised
#   mirror replacement)
#
# Prerequisites
# -------------
# pip-tools must be installed in the active Python environment:
#
#   pip install pip-tools
#
# It is NOT a dev dependency in pyproject.toml because the lockfile
# generation is a release-engineering step run by humans/agents, not
# part of the runtime or CI install path.

set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v pip-compile >/dev/null 2>&1; then
    echo "pip-compile not found. Install pip-tools first:"
    echo "    pip install pip-tools"
    exit 1
fi

echo "Regenerating requirements.lock (production deps)..."
pip-compile \
    --generate-hashes \
    --output-file=requirements.lock \
    --strip-extras \
    pyproject.toml

echo "Regenerating requirements-dev.lock (production + dev deps)..."
pip-compile \
    --generate-hashes \
    --extra=dev \
    --output-file=requirements-dev.lock \
    --strip-extras \
    pyproject.toml

echo
echo "Done. Review the diff and commit:"
echo "    git diff requirements.lock requirements-dev.lock"
echo "    git add requirements.lock requirements-dev.lock"
echo "    git commit -m 'chore: regenerate mcp-gmail lockfiles'"
