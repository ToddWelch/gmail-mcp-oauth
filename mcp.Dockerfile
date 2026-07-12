# Railway builds and runs this container. This service has its own
# build context, independent of any other service in your deployment.
#
# Base image is digest-pinned (not just tag-pinned) so a future
# python:3.11-slim retag cannot silently change what we ship. To
# refresh the digest, run:
#   docker pull python:3.11-slim
#   docker inspect --format='{{index .RepoDigests 0}}' python:3.11-slim
# and update the line below.
FROM python:3.14-slim@sha256:b877e50bd90de10af8d82c57a022fc2e0dc731c5320d762a27986facfc3355c1

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

# Patch OS packages against known CVEs present in the pinned base image
# (as of this change: libcap2 CVE-2026-4878, and the openssl /
# libssl3t64 / openssl-provider-legacy CVE-2026-45447 use-after-free).
# `upgrade` only pulls fixes already published to the Debian security
# suite for this release, so the build stays reproducible against the
# digest-pinned base. Placed as an early, stable layer (before the source
# COPY) so it caches across source edits and only re-runs when the base
# digest itself changes. `rm -rf /var/lib/apt/lists/*` keeps the apt index
# out of the shipped image.
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*

# (supply-chain hardening): create a non-root user
# BEFORE copying any files so the source tree can be chowned to the
# user that will execute it. The `appuser` UID/GID are arbitrary
# (10001) but stable so multi-stage builds and external volumes are
# predictable. `--no-create-home` because the runtime never reads
# /home/appuser; keeping the home dir absent shrinks the image and
# removes a writable mount target.
RUN useradd --system --no-create-home --uid 10001 --shell /usr/sbin/nologin appuser

WORKDIR /app

# copy the lockfile + project metadata FIRST so layer
# caching keys on dependency changes, not source changes. The lock
# is what `--require-hashes` consumes; sharing the layer means a
# typo in src/mcp_gmail/<x>.py does NOT bust the dependency layer.
COPY requirements.lock ./
COPY pyproject.toml ./

# hash-pinned install. `--require-hashes` makes pip
# refuse any wheel/sdist whose SHA256 does not appear in the lock,
# so a compromised mirror or transient typo squat cannot inject a
# malicious package at build time. After the deps are locked in we
# install the local package itself with --no-deps so the lockfile
# remains the single source of truth for everything pulled from the
# index. NOT `pip install -e` (editable belongs in dev only).
#
# We deliberately do NOT run `pip install --upgrade pip` here. The
# previous unpinned upgrade pulled a fresh pip from PyPI on every
# build, which defeats the supply-chain story `--require-hashes`
# tells. The pip that ships with the digest-pinned base image is the
# one we audit. Add a hash-pinned pip upgrade to requirements.lock
# (or a separate constraints file) if a CVE forces a bump.
RUN pip install --require-hashes -r requirements.lock

# Copy the application source AFTER the dependency layer so source
# edits do not bust dependency caching.
COPY src/ ./src/
COPY migrations/ ./migrations/
COPY alembic.ini ./

# Install the local package itself (no-deps; deps already locked above).
RUN pip install . --no-deps

# Hand /app over to appuser so alembic upgrade can write its own
# bookkeeping (alembic_version row in the DB itself, but also any
# transient files alembic touches under the project root). The
# runtime image is read-only-ish: only paths owned by appuser are
# writable, which is exactly what we want.
RUN chown -R appuser:appuser /app

# Railway injects PORT; default to 8000 for local docker runs.
ENV PORT=8000
EXPOSE 8000

USER appuser

# Apply migrations on every boot, then start uvicorn. If the migration
# fails, the container fails to start and the previous deploy keeps
# serving traffic; this is a standard fail-fast safety net pattern.
CMD ["sh", "-c", "alembic upgrade head && uvicorn mcp_gmail.server:app --host 0.0.0.0 --port ${PORT}"]
