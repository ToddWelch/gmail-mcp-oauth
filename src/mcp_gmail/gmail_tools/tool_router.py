"""Per-tool name routing + argument validation.

Split out of dispatch.py to keep both files under the project's 300-LOC
rule. Imports the per-tool modules (messages, threads, labels_read,
filters_read, plus the drafts, send, messages_write, labels_write,
filters_write) and dispatches by name.

Argument validation is deliberately minimal: types and required-ness.
JSON Schema in tool_definitions.py is what Claude validates against
client-side; this layer is the server-side guard against malformed
calls that bypass the schema (programmatic clients, tests, future
non-Claude callers).

validator helpers + ToolValidation exception live in
tool_router_helpers.py so this file stays under the 300-LOC ceiling
once the new multi_search_emails / batch_read_emails branches landed.
The helpers are still passed to route_write_tool as keyword args so
tool_router_write.py is unaffected.
"""

from __future__ import annotations

from typing import Any

from . import filters_read, labels_read, messages, messages_extras, threads
from .errors import (
    bad_request_error,
    needs_reauth_error,
    not_found_error,
    rate_limited_error,
    unknown_error,
    upstream_error,
)
from .gmail_client import GmailApiError, GmailClient
from .tool_router_helpers import (
    ToolValidation,
    optional_bool,
    optional_int,
    optional_str,
    optional_str_list,
    require_dict,
    require_str,
    require_str_list,
)
from .tool_router_helpers import (
    optional_dict as _optional_dict,
)
from .tool_router_write import _NOT_HANDLED, route_write_tool


# ---------------------------------------------------------------------------
# Tool routing
# ---------------------------------------------------------------------------


async def route_tool(
    *,
    tool_name: str,
    arguments: dict[str, Any],
    client: GmailClient,
    auth0_sub: str = "",
    account_email: str = "",
    granted_scope: str = "",
) -> dict[str, Any]:
    """Route to the named tool. Catches GmailApiError -> typed error dicts.

    The dispatcher converts every Gmail status into a typed error so
    the caller layer (mcp_protocol.py) sees one consistent shape.
    Tool-internal validation (e.g. malformed attachment_id) returns
    bad_request_error directly without an HTTP call.

    `auth0_sub` and `account_email` flow through to send_email's
    idempotency cache key. They are defaulted to empty strings only so
    test cases that route a read tool can omit them; in production the
    dispatcher always supplies both.

    `granted_scope` is passed through so send_draft can detect
    the "post-send actions requested but caller granted only SEND
    scope" case at handler entry and return bad_request_error before
    any Gmail HTTP call . Default empty string preserves
    test backwards compatibility for callers that route read tools
    without supplying scope.
    """
    try:
        if tool_name == "read_email":
            return await messages.read_email(
                client=client,
                message_id=require_str(arguments, "message_id"),
                format=arguments.get("format", "full"),
            )

        if tool_name == "search_emails":
            return await messages.search_emails(
                client=client,
                q=optional_str(arguments, "q"),
                label_ids=optional_str_list(arguments, "label_ids"),
                page_token=optional_str(arguments, "page_token"),
                max_results=optional_int(arguments, "max_results"),
            )

        if tool_name == "download_attachment":
            return await messages.download_attachment(
                client=client,
                message_id=require_str(arguments, "message_id"),
                attachment_id=require_str(arguments, "attachment_id"),
            )

        if tool_name == "download_email":
            return await messages.download_email(
                client=client,
                message_id=require_str(arguments, "message_id"),
            )

        if tool_name == "get_thread":
            return await threads.get_thread(
                client=client,
                thread_id=require_str(arguments, "thread_id"),
                format=arguments.get("format", "full"),
            )

        if tool_name == "list_inbox_threads":
            return await threads.list_inbox_threads(
                client=client,
                page_token=optional_str(arguments, "page_token"),
                max_results=optional_int(arguments, "max_results"),
            )

        if tool_name == "get_inbox_with_threads":
            return await threads.get_inbox_with_threads(
                client=client,
                max_results=optional_int(arguments, "max_results"),
            )

        if tool_name == "modify_thread":
            return await threads.modify_thread(
                client=client,
                thread_id=require_str(arguments, "thread_id"),
                add_label_ids=optional_str_list(arguments, "add_label_ids"),
                remove_label_ids=optional_str_list(arguments, "remove_label_ids"),
            )

        if tool_name == "list_email_labels":
            return await labels_read.list_email_labels(client=client)

        if tool_name == "list_filters":
            return await filters_read.list_filters(client=client)

        if tool_name == "get_filter":
            return await filters_read.get_filter(
                client=client,
                filter_id=require_str(arguments, "filter_id"),
            )

        # multi_search_emails. Read-side tool (gmail.readonly).
        if tool_name == "multi_search_emails":
            return await messages_extras.multi_search_emails(
                client=client,
                queries=require_str_list(arguments, "queries"),
                max_results_per_query=optional_int(arguments, "max_results_per_query"),
                label_ids=optional_str_list(arguments, "label_ids"),
            )

        # batch_read_emails. Read-side tool (gmail.readonly).
        if tool_name == "batch_read_emails":
            return await messages_extras.batch_read_emails(
                client=client,
                message_ids=require_str_list(arguments, "message_ids"),
                format=arguments.get("format", "metadata"),
                metadata_headers=optional_str_list(arguments, "metadata_headers"),
            )

        # Fall through to write-tool dispatch. Returns
        # `_NOT_HANDLED` if the tool name is unknown so the outer
        # function can surface unknown_error.
        write_result = await route_write_tool(
            tool_name=tool_name,
            arguments=arguments,
            client=client,
            auth0_sub=auth0_sub,
            account_email=account_email,
            granted_scope=granted_scope,
            require_str=require_str,
            require_str_list=require_str_list,
            optional_str=optional_str,
            optional_str_list=optional_str_list,
            optional_int=optional_int,
            optional_bool=optional_bool,
            require_dict=require_dict,
            optional_dict=_optional_dict,
        )
        if write_result is _NOT_HANDLED:
            return unknown_error(f"tool not implemented: {tool_name}")
        return write_result

    except ToolValidation as exc:
        return bad_request_error(str(exc))
    except ValueError as exc:
        # gmail_id.validate_gmail_id raises ValueError
        # at every Gmail-ID interpolation site (URL paths + JSON bodies).
        # The handler-level catch translates it into a typed
        # bad_request_error response so the caller sees the standard
        # JSON-RPC error shape rather than an unhandled exception.
        return bad_request_error(str(exc))
    except GmailApiError as exc:
        return gmail_error_to_dict(exc)


# ---------------------------------------------------------------------------
# Gmail error -> typed error dict
# ---------------------------------------------------------------------------


def gmail_error_to_dict(exc: GmailApiError) -> dict[str, Any]:
    """Translate a GmailApiError into one of our typed error shapes."""
    if exc.status == 404:
        return not_found_error(str(exc))
    if exc.status == 401 or exc.status == 403:
        # 401: token rejected (refresh-eligible at token_manager). 403:
        # usually scope. Either way, surface as needs_reauth so the
        # caller knows the right next step. The dispatcher's pre-call
        # scope check should have caught most 403 cases.
        return needs_reauth_error(f"gmail returned {exc.status}; user may need to re-link")
    if exc.status == 429:
        return rate_limited_error(
            "gmail rate limit exceeded",
            retry_after_seconds=exc.retry_after_seconds,
        )
    if exc.status >= 500:
        return upstream_error("gmail upstream error", status=exc.status)
    return unknown_error(f"gmail error: {exc}")
