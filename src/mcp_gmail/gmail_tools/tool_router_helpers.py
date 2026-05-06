"""Argument-shape validation helpers for the per-tool routers.

Split out of tool_router.py to honor the 300-LOC-per-file rule once
the multi_search_emails / batch_read_emails branches landed in the
read-side router. This module owns:

- ToolValidation exception class.
- Eight argument-validator helpers: require_str, require_str_list,
  optional_str, optional_str_list, optional_int, optional_bool,
  require_dict, optional_dict.

Import shape:
- tool_router.py imports the helpers from this module and passes
  them to route_write_tool() as keyword args. tool_router_write.py
  receives the helpers as keyword arguments rather than importing
  them directly; that keeps the helpers' single home here and avoids
  a name clash with the read-side router that imports them at module
  scope. The route_write_tool signature is the single touch point
  for any new helper (the send-draft branch added `granted_scope`
  and `optional_bool` to that signature when post-send-actions
  landed).

The helpers raise ToolValidation on shape mismatch; the outer router
catches that exception and returns a typed bad_request_error response.
The exception lives here (not in errors.py) because it is purely a
router-internal control-flow primitive, not a public error shape.
"""

from __future__ import annotations

from typing import Any


# ---------------------------------------------------------------------------
# Internal validation exception
# ---------------------------------------------------------------------------


class ToolValidation(Exception):
    """Internal exception for argument-shape failures inside route_tool."""


# ---------------------------------------------------------------------------
# Argument-shape helpers used by every tool router.
# ---------------------------------------------------------------------------


def require_str(args: dict[str, Any], name: str) -> str:
    v = args.get(name)
    if not isinstance(v, str) or v == "":
        raise ToolValidation(f"{name} is required and must be a non-empty string")
    return v


def optional_str(args: dict[str, Any], name: str) -> str | None:
    v = args.get(name)
    if v is None:
        return None
    if not isinstance(v, str):
        raise ToolValidation(f"{name} must be a string")
    return v


def optional_int(args: dict[str, Any], name: str) -> int | None:
    v = args.get(name)
    if v is None:
        return None
    if not isinstance(v, int) or isinstance(v, bool):
        raise ToolValidation(f"{name} must be an integer")
    return v


def optional_bool(args: dict[str, Any], name: str) -> bool:
    """Optional boolean; missing or None coerces to False.

    Used by the send_draft branch for `archive_thread`. We do NOT
    accept truthy ints/strings; only an explicit boolean or absence
    is valid (defense-in-depth around the schema layer's `type:
    boolean` declaration).
    """
    v = args.get(name)
    if v is None:
        return False
    if not isinstance(v, bool):
        raise ToolValidation(f"{name} must be a boolean")
    return v


def optional_str_list(args: dict[str, Any], name: str) -> list[str] | None:
    v = args.get(name)
    if v is None:
        return None
    if not isinstance(v, list):
        raise ToolValidation(f"{name} must be a list of strings")
    out: list[str] = []
    for i, item in enumerate(v):
        if not isinstance(item, str):
            raise ToolValidation(f"{name}[{i}] must be a string")
        out.append(item)
    return out


def require_str_list(args: dict[str, Any], name: str) -> list[str]:
    """Require a non-empty list of strings under `name`."""
    v = args.get(name)
    if not isinstance(v, list) or not v:
        raise ToolValidation(f"{name} is required and must be a non-empty list of strings")
    out: list[str] = []
    for i, item in enumerate(v):
        if not isinstance(item, str):
            raise ToolValidation(f"{name}[{i}] must be a string")
        out.append(item)
    return out


def require_dict(args: dict[str, Any], name: str) -> dict[str, Any]:
    """Require an object (dict) value under `name`."""
    v = args.get(name)
    if not isinstance(v, dict):
        raise ToolValidation(f"{name} is required and must be an object")
    return v


def optional_dict(args: dict[str, Any], name: str) -> dict[str, Any] | None:
    v = args.get(name)
    if v is None:
        return None
    if not isinstance(v, dict):
        raise ToolValidation(f"{name} must be an object")
    return v


def optional_int_list(args: dict[str, Any], name: str) -> list[int] | None:
    """Optional list of ints. Currently unused by any tool but
    included alongside require_dict / optional_dict per the plan as a
    finished helper surface for follow-up tools that take numeric ID
    lists.
    """
    v = args.get(name)
    if v is None:
        return None
    if not isinstance(v, list):
        raise ToolValidation(f"{name} must be a list of integers")
    out: list[int] = []
    for i, item in enumerate(v):
        if not isinstance(item, int) or isinstance(item, bool):
            raise ToolValidation(f"{name}[{i}] must be an integer")
        out.append(item)
    return out
