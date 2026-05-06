"""Write-side tool dispatch (the 14 tools + the 4 tools = 18 total).

Split out of tool_router.py to honor the 300-LOC-per-file rule. The
read-side router (tool_router.py) calls into _route_write_tool here
when the tool name doesn't match a read tool. There is no behavioral
split: the contract for `route_tool` in tool_router.py is unchanged.

The 18 write tools, in this canonical order:

    Send, drafts, and reply (7 tools):
        send_email, create_draft, update_draft, list_drafts,
        send_draft, delete_draft, reply_all
    Label management (5 tools):
        create_label, update_label, delete_label, modify_email_labels,
        get_or_create_label
    Filter management (3 tools):
        create_filter, delete_filter,
        create_filter_from_template
    Delete and bulk modify (3 tools):
        delete_email, batch_delete_emails,
        batch_modify_emails

Each branch validates argument shape via the require_/optional_ helpers
defined in tool_router.py, then calls into the relevant tool module
(send.py, reply.py, drafts.py, labels_write.py, filters_write.py,
messages_write.py).

Sentinel return value
---------------------
`_NOT_HANDLED` is returned when the tool name is not one of the 18
write tools. The caller (route_tool in tool_router.py) translates that
into an unknown_error response. We use a unique-per-module sentinel
dict rather than None because some Gmail responses are legitimately
{} (empty dict, also falsy).
"""

from __future__ import annotations

from typing import Any

from . import drafts, filters_write, labels_write, messages_write, reply, send
from .errors import bad_request_error
from .gmail_client import GmailClient
from .message_format import Attachment


# Sentinel for write-tool dispatch. Re-exported via tool_router so the
# read-side outer function can compare results against it.
_NOT_HANDLED: dict[str, Any] = {"__not_handled__": True}


def _decode_attachments_arg(
    raw: list[dict[str, Any]] | None,
) -> list[Attachment] | None | dict[str, Any]:
    """Decode the `attachments` argument for create_draft / update_draft.

    Returns either a list of Attachment dataclasses, None (when raw is
    None), or a bad_request_error dict on malformed input. send_email
    decodes its own attachments inline because it also has to handle
    the idempotency cache in the same flow; drafts.create_draft and
    drafts.update_draft take pre-built Attachment objects, so the
    decoder lives here.
    """
    if raw is None:
        return None
    if not isinstance(raw, list):
        return bad_request_error("attachments must be a list")
    out: list[Attachment] = []
    # The base64 decoder lives once, in send.py. Lazy import here to
    # avoid an import-cycle hazard; the function call still runs at
    # cold-cache speed under pytest.
    from .send import _decode_attachment

    for i, item in enumerate(raw):
        decoded = _decode_attachment(item, index=i)
        if isinstance(decoded, dict):  # error dict
            return decoded
        out.append(decoded)
    return out


async def route_write_tool(
    *,
    tool_name: str,
    arguments: dict[str, Any],
    client: GmailClient,
    auth0_sub: str,
    account_email: str,
    granted_scope: str,
    require_str: Any,
    require_str_list: Any,
    optional_str: Any,
    optional_str_list: Any,
    optional_int: Any,
    optional_bool: Any,
    require_dict: Any,
    optional_dict: Any,
) -> dict[str, Any]:
    """Dispatch the 14 write tools. Returns _NOT_HANDLED on miss.

    The validation helpers are passed in by the caller rather than
    imported, so this module avoids a name clash with tool_router and
    keeps the helpers' single home.

    `granted_scope` is forwarded so the send_draft branch can
    reject post-send actions when the caller granted only gmail.send
    (no gmail.modify) at handler entry, before any Gmail HTTP call.
    """

    # ----- Send + drafts (6 tools) -----------------------------------------
    if tool_name == "send_email":
        return await send.send_email(
            client=client,
            auth0_sub=auth0_sub,
            account_email=account_email,
            sender=require_str(arguments, "sender"),
            to=require_str_list(arguments, "to"),
            subject=require_str(arguments, "subject"),
            body_text=require_str(arguments, "body_text"),
            cc=optional_str_list(arguments, "cc"),
            bcc=optional_str_list(arguments, "bcc"),
            attachments=arguments.get("attachments"),
            reply_to_message_id=optional_str(arguments, "reply_to_message_id"),
            reply_to_references=optional_str_list(arguments, "reply_to_references"),
            idempotency_key=optional_str(arguments, "idempotency_key"),
        )

    if tool_name == "create_draft":
        decoded = _decode_attachments_arg(arguments.get("attachments"))
        if isinstance(decoded, dict):
            return decoded
        return await drafts.create_draft(
            client=client,
            sender=require_str(arguments, "sender"),
            to=require_str_list(arguments, "to"),
            subject=require_str(arguments, "subject"),
            body_text=require_str(arguments, "body_text"),
            cc=optional_str_list(arguments, "cc"),
            bcc=optional_str_list(arguments, "bcc"),
            attachments=decoded,
            reply_to_message_id=optional_str(arguments, "reply_to_message_id"),
            reply_to_references=optional_str_list(arguments, "reply_to_references"),
            # optional Gmail-API threadId. None when omitted so
            # the request body stays exactly the prior shape (back-compat).
            thread_id=optional_str(arguments, "thread_id"),
        )

    if tool_name == "update_draft":
        decoded = _decode_attachments_arg(arguments.get("attachments"))
        if isinstance(decoded, dict):
            return decoded
        return await drafts.update_draft(
            client=client,
            draft_id=require_str(arguments, "draft_id"),
            sender=require_str(arguments, "sender"),
            to=require_str_list(arguments, "to"),
            subject=require_str(arguments, "subject"),
            body_text=require_str(arguments, "body_text"),
            cc=optional_str_list(arguments, "cc"),
            bcc=optional_str_list(arguments, "bcc"),
            attachments=decoded,
            reply_to_message_id=optional_str(arguments, "reply_to_message_id"),
            reply_to_references=optional_str_list(arguments, "reply_to_references"),
            # optional Gmail-API threadId. None when omitted so
            # the request body stays exactly the prior shape (back-compat).
            thread_id=optional_str(arguments, "thread_id"),
        )

    if tool_name == "list_drafts":
        return await drafts.list_drafts(
            client=client,
            q=optional_str(arguments, "q"),
            page_token=optional_str(arguments, "page_token"),
            max_results=optional_int(arguments, "max_results"),
        )

    if tool_name == "send_draft":
        # optional post-send action params. Defaults preserve
        # the prior request shape exactly (back-compat).
        return await drafts.send_draft(
            client=client,
            draft_id=require_str(arguments, "draft_id"),
            archive_thread=optional_bool(arguments, "archive_thread"),
            add_labels=optional_str_list(arguments, "add_labels"),
            remove_labels=optional_str_list(arguments, "remove_labels"),
            granted_scope=granted_scope,
        )

    if tool_name == "delete_draft":
        return await drafts.delete_draft(
            client=client,
            draft_id=require_str(arguments, "draft_id"),
        )

    # ----- reply_all -----------------------------------------------
    if tool_name == "reply_all":
        decoded = _decode_attachments_arg(arguments.get("attachments"))
        if isinstance(decoded, dict):
            return decoded
        return await reply.reply_all(
            client=client,
            auth0_sub=auth0_sub,
            account_email=account_email,
            # `message_id` (not `original_message_id`) so dispatch.py's
            # audit harvest binds the source ID into the audit line.
            message_id=require_str(arguments, "message_id"),
            body_text=require_str(arguments, "body_text"),
            attachments=decoded,
            idempotency_key=optional_str(arguments, "idempotency_key"),
        )

    # ----- Label management (5 tools) ----------------------------
    if tool_name == "create_label":
        return await labels_write.create_label(
            client=client,
            name=require_str(arguments, "name"),
            label_list_visibility=optional_str(arguments, "label_list_visibility"),
            message_list_visibility=optional_str(arguments, "message_list_visibility"),
            color=optional_dict(arguments, "color"),
        )

    if tool_name == "update_label":
        return await labels_write.update_label(
            client=client,
            label_id=require_str(arguments, "label_id"),
            name=optional_str(arguments, "name"),
            label_list_visibility=optional_str(arguments, "label_list_visibility"),
            message_list_visibility=optional_str(arguments, "message_list_visibility"),
            color=optional_dict(arguments, "color"),
        )

    if tool_name == "delete_label":
        return await labels_write.delete_label(
            client=client,
            label_id=require_str(arguments, "label_id"),
        )

    if tool_name == "modify_email_labels":
        return await messages_write.modify_email_labels(
            client=client,
            message_id=require_str(arguments, "message_id"),
            add_label_ids=optional_str_list(arguments, "add_label_ids"),
            remove_label_ids=optional_str_list(arguments, "remove_label_ids"),
        )

    if tool_name == "get_or_create_label":
        return await labels_write.get_or_create_label(
            client=client,
            name=require_str(arguments, "name"),
            label_list_visibility=optional_str(arguments, "label_list_visibility"),
            message_list_visibility=optional_str(arguments, "message_list_visibility"),
            color=optional_dict(arguments, "color"),
        )

    # ----- Filter management (3 tools) ---------------------------
    if tool_name == "create_filter":
        return await filters_write.create_filter(
            client=client,
            criteria=require_dict(arguments, "criteria"),
            action=require_dict(arguments, "action"),
        )

    if tool_name == "delete_filter":
        return await filters_write.delete_filter(
            client=client,
            filter_id=require_str(arguments, "filter_id"),
        )

    if tool_name == "create_filter_from_template":
        return await filters_write.create_filter_from_template(
            client=client,
            template=require_str(arguments, "template"),
            sender_email=optional_str(arguments, "sender_email"),
            query=optional_str(arguments, "query"),
            label_id=optional_str(arguments, "label_id"),
        )

    # ----- Delete + bulk modify (3 tools) ------------------------
    if tool_name == "delete_email":
        return await messages_write.delete_email(
            client=client,
            message_id=require_str(arguments, "message_id"),
        )

    if tool_name == "batch_delete_emails":
        return await messages_write.batch_delete_emails(
            client=client,
            message_ids=require_str_list(arguments, "message_ids"),
        )

    if tool_name == "batch_modify_emails":
        return await messages_write.batch_modify_emails(
            client=client,
            message_ids=require_str_list(arguments, "message_ids"),
            add_label_ids=optional_str_list(arguments, "add_label_ids"),
            remove_label_ids=optional_str_list(arguments, "remove_label_ids"),
        )

    return _NOT_HANDLED
