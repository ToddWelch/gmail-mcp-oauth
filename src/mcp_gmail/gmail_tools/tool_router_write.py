"""Write-side tool dispatch (19 tools: 15 write + 4 cleanup).

Split out of tool_router.py to honor the 300-LOC-per-file rule. The
read-side router (tool_router.py) calls into route_write_tool here when
the tool name doesn't match a read tool; the `route_tool` contract is
unchanged. Canonical order: create_attachment_upload_slot, send_email,
create_draft, update_draft, list_drafts, send_draft, delete_draft,
reply_all, then label / filter / delete / bulk-modify admin tools.

Each branch validates argument shape via the require_/optional_ helpers
passed from tool_router.py, then calls the relevant tool module.

`_NOT_HANDLED` is returned when the tool name is not a write tool; the
caller translates it into unknown_error. A unique sentinel dict (not
None) is used because some Gmail responses are legitimately {}.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from . import drafts, filters_write, labels_write, messages_write, reply, send, upload_slot
from .attachment_source import load_attachments
from .gmail_client import GmailClient

if TYPE_CHECKING:  # pragma: no cover
    from ..config import Settings


# Sentinel for write-tool dispatch. Re-exported via tool_router so the
# read-side outer function can compare results against it.
_NOT_HANDLED: dict[str, Any] = {"__not_handled__": True}


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
    settings: "Settings | None" = None,
) -> dict[str, Any]:
    """Dispatch the write tools. Returns _NOT_HANDLED on miss.

    The validation helpers are passed in by the caller rather than
    imported, so this module avoids a name clash with tool_router and
    keeps the helpers' single home.

    `granted_scope` is forwarded so the send_draft branch can
    reject post-send actions when the caller granted only gmail.send
    (no gmail.modify) at handler entry, before any Gmail HTTP call.

    `settings` is forwarded so the create_attachment_upload_slot branch
    can build the upload URL and so the send/draft/reply branches can
    thread the Fernet key(s) into attachment_source.load_attachments to
    decrypt upload-slot bytes. Draft branches load (decrypt) here and
    hand the token_hashes to drafts.*, which consume AFTER a successful
    build (an oversize draft never burns a slot).
    """
    enc_key = settings.encryption_key if settings is not None else None
    prior_keys = settings.prior_encryption_keys if settings is not None else ()

    # ----- Attachment upload slot ------------------------------------------
    if tool_name == "create_attachment_upload_slot":
        # No Gmail call: `client` is intentionally unused. Routed through
        # the normal dispatch so the token-row lookup + scope check +
        # audit run on the vetted path; a dead Google token fails fast.
        if settings is None:  # pragma: no cover - dispatcher always supplies it
            return _NOT_HANDLED
        return upload_slot.create_upload_slot(
            auth0_sub=auth0_sub,
            account_email=account_email,
            settings=settings,
        )

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
            body_html=optional_str(arguments, "body_html"),
            attachments=arguments.get("attachments"),
            reply_to_message_id=optional_str(arguments, "reply_to_message_id"),
            reply_to_references=optional_str_list(arguments, "reply_to_references"),
            idempotency_key=optional_str(arguments, "idempotency_key"),
            encryption_key=enc_key,
            prior_encryption_keys=prior_keys,
        )

    if tool_name == "create_draft":
        loaded = load_attachments(
            raw=arguments.get("attachments"),
            auth0_sub=auth0_sub,
            account_email=account_email,
            encryption_key=enc_key,
            prior_encryption_keys=prior_keys,
        )
        if isinstance(loaded, dict):
            return loaded
        atts, token_hashes = loaded
        return await drafts.create_draft(
            client=client,
            sender=require_str(arguments, "sender"),
            to=require_str_list(arguments, "to"),
            subject=require_str(arguments, "subject"),
            body_text=require_str(arguments, "body_text"),
            cc=optional_str_list(arguments, "cc"),
            bcc=optional_str_list(arguments, "bcc"),
            body_html=optional_str(arguments, "body_html"),
            attachments=atts or None,
            reply_to_message_id=optional_str(arguments, "reply_to_message_id"),
            reply_to_references=optional_str_list(arguments, "reply_to_references"),
            # optional Gmail-API threadId. None when omitted so
            # the request body stays exactly the prior shape (back-compat).
            thread_id=optional_str(arguments, "thread_id"),
            auth0_sub=auth0_sub,
            account_email=account_email,
            consume_token_hashes=token_hashes,
        )

    if tool_name == "update_draft":
        loaded = load_attachments(
            raw=arguments.get("attachments"),
            auth0_sub=auth0_sub,
            account_email=account_email,
            encryption_key=enc_key,
            prior_encryption_keys=prior_keys,
        )
        if isinstance(loaded, dict):
            return loaded
        atts, token_hashes = loaded
        return await drafts.update_draft(
            client=client,
            draft_id=require_str(arguments, "draft_id"),
            sender=require_str(arguments, "sender"),
            to=require_str_list(arguments, "to"),
            subject=require_str(arguments, "subject"),
            body_text=require_str(arguments, "body_text"),
            cc=optional_str_list(arguments, "cc"),
            bcc=optional_str_list(arguments, "bcc"),
            body_html=optional_str(arguments, "body_html"),
            attachments=atts or None,
            reply_to_message_id=optional_str(arguments, "reply_to_message_id"),
            reply_to_references=optional_str_list(arguments, "reply_to_references"),
            # optional Gmail-API threadId. None when omitted so
            # the request body stays exactly the prior shape (back-compat).
            thread_id=optional_str(arguments, "thread_id"),
            auth0_sub=auth0_sub,
            account_email=account_email,
            consume_token_hashes=token_hashes,
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
        # reply_all resolves/consumes attachments internally, AFTER its
        # Gmail reads, so a bad message_id does not spend an upload slot.
        return await reply.reply_all(
            client=client,
            auth0_sub=auth0_sub,
            account_email=account_email,
            # `message_id` (not `original_message_id`) so dispatch.py's
            # audit harvest binds the source ID into the audit line.
            message_id=require_str(arguments, "message_id"),
            body_text=require_str(arguments, "body_text"),
            body_html=optional_str(arguments, "body_html"),
            attachments=arguments.get("attachments"),
            idempotency_key=optional_str(arguments, "idempotency_key"),
            encryption_key=enc_key,
            prior_encryption_keys=prior_keys,
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
