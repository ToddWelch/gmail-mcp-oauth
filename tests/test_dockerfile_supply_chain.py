"""supply-chain Dockerfile constraints.

Targets: mcp-gmail/mcp.Dockerfile

These tests are static string asserts on the Dockerfile contents. They
don't build the image; that's left to local verification + CI's docker
build step. The point here is to catch regressions where someone
casually re-introduces `pip install .` (without --require-hashes) or
removes the non-root USER directive.
"""

from __future__ import annotations

from pathlib import Path

DOCKERFILE = Path(__file__).resolve().parents[1] / "mcp.Dockerfile"


def test_dockerfile_uses_require_hashes():
    """The pip install step must enforce --require-hashes against the lockfile."""
    content = DOCKERFILE.read_text()
    assert "--require-hashes" in content
    assert "requirements.lock" in content


def test_dockerfile_runs_as_non_root():
    """A non-root USER directive must appear before the CMD."""
    content = DOCKERFILE.read_text()
    assert "USER appuser" in content
    # USER appuser must come before CMD (find both indexes).
    user_idx = content.index("USER appuser")
    cmd_idx = content.index("CMD ")
    assert user_idx < cmd_idx, "USER appuser must precede CMD"


def test_dockerfile_creates_appuser():
    """The image must have an appuser created (useradd or adduser)."""
    content = DOCKERFILE.read_text()
    # Accept either useradd (standard) or adduser (alpine).
    assert "useradd" in content or "adduser" in content


def test_dockerfile_no_editable_install():
    """Production image must NOT use `pip install -e` (editable).

    Editable installs depend on the source tree staying writable and
    matching the .egg-link layout; that is dev ergonomics, not a
    production concern.
    """
    content = DOCKERFILE.read_text()
    # Strip line comments before checking.
    code_lines = [ln for ln in content.splitlines() if not ln.lstrip().startswith("#")]
    code = "\n".join(code_lines)
    assert "pip install -e" not in code
    assert "pip install --editable" not in code
