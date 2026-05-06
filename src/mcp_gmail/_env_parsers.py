"""Environment-variable parsing primitives used by config.load().

Pure os.environ readers with type coercion. None of these helpers know
about which fields Settings carries; they are deliberately decoupled
from the Settings dataclass so a future refactor can reuse them
elsewhere (or unit-test them in isolation) without dragging the
Settings construction surface along.

Canonical home for `_require`, `_optional`, `_int`, `_bool`. The
public-looking import path `mcp_gmail.config._require` is preserved as
a backward-compatibility re-export from `config.py` so test scaffolding
or out-of-tree monkeypatches keep working.
"""

from __future__ import annotations

import os


def _require(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(
            f"Required environment variable {name} is not set. "
            "See mcp-gmail/README.md for the full list."
        )
    return value


def _optional(name: str, default: str) -> str:
    value = os.environ.get(name)
    if value is None or value == "":
        return default
    return value


def _int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer, got: {raw!r}") from exc


def _bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")
