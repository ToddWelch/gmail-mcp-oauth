"""Build RFC 5322 messages with attachments + enforce Gmail's size cap.

Used by the send tools. Centralizes the EmailMessage construction
and the size-cap test in one reviewable module so write tools share
a single enforcement point.

Hard rules
----------
1. Use email.message.EmailMessage. The legacy email.mime.* family has
   long-standing bugs around non-ASCII payloads, attachment encoding,
   and structural introspection. EmailMessage is the modern Python
   email API and the only acceptable path for outbound mail in this
   service. README.md commits us to this; this module is where the
   commitment is enforced.

2. Gmail's hard ceiling is 25 MB on the FINAL encoded message size,
   including the base64 inflation of any attachments. Base64 inflates
   binary data by ~33%, so the raw attachment cap is ~18 MB. The
   cap is validated against the FINAL encoded byte length, not the
   raw input length.

3. The cap is checked after the message is fully assembled. We do
   that by building the EmailMessage, calling .as_bytes() to render
   it the way Gmail's `users.messages.send` will receive it, and
   measuring the result. The send tool then base64url-encodes the
   bytes for Gmail's `raw` field; the byte length we measure matches
   what Gmail validates against.

   Boundary tests:
     - exactly 25 * 1024 * 1024 bytes -> pass
     - 25 * 1024 * 1024 + 1 bytes     -> raise OversizeMessage
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from email.message import EmailMessage


# Gmail's documented limit on `users.messages.send` is 25 MB on the
# RFC 5322 message size. The number is in mebibytes per Gmail's own
# error messaging, so we use 1024 not 1000.
MAX_ENCODED_BYTES = 25 * 1024 * 1024


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class OversizeMessage(Exception):
    """Raised when the assembled message exceeds Gmail's 25 MB cap."""

    def __init__(self, *, encoded_size: int, max_size: int = MAX_ENCODED_BYTES):
        super().__init__(f"message size {encoded_size} bytes exceeds Gmail cap of {max_size} bytes")
        self.encoded_size = encoded_size
        self.max_size = max_size


# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Attachment:
    """One attachment to include in an outbound message.

    `data` is the raw bytes (NOT base64-encoded). The encoding to base64
    happens inside EmailMessage.add_attachment when needed.

    `filename` is the user-facing name on the attachment. It is NEVER
    written to audit logs ; it lives in
    the wire-level message body only.
    """

    filename: str
    mime_type: str  # e.g. "application/pdf"
    data: bytes


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------


def build_email_message(
    *,
    sender: str,
    to: list[str],
    subject: str,
    body_text: str,
    cc: list[str] | None = None,
    bcc: list[str] | None = None,
    attachments: list[Attachment] | None = None,
    reply_to_message_id: str | None = None,
    reply_to_references: list[str] | None = None,
) -> EmailMessage:
    """Build a fully-formed EmailMessage. Raises OversizeMessage if too big.

    Behaviors:
    - Plain text body via .set_content(body_text). the send tool
      currently assumes plain text. Adding HTML alternative parts is
      a follow-up; if a future caller passes both text and HTML, this
      function will need an `html_body` parameter and EmailMessage's
      .add_alternative() flow.
    - Attachments are added via .add_attachment(data, maintype, subtype,
      filename=...). EmailMessage handles base64 encoding internally.
    - Threading headers (`In-Reply-To`, `References`) are populated
      when reply_to_message_id is supplied. References is the chain of
      ancestor message IDs. Both are required for Gmail to thread the
      reply correctly; the send tool cannot rely on Gmail's threading
      heuristics from subject alone.

    Size cap is checked AFTER the full message is rendered. We render
    once via .as_bytes() and reuse the measurement for the cap check;
    the caller can re-render at send time without functional change
    (EmailMessage rendering is deterministic for the same instance).
    """
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = ", ".join(to)
    if cc:
        msg["Cc"] = ", ".join(cc)
    if bcc:
        msg["Bcc"] = ", ".join(bcc)
    msg["Subject"] = subject

    if reply_to_message_id:
        # RFC 2822 Message-ID values are typically angle-bracketed.
        # We accept either form and re-emit the angle-bracketed shape
        # because RFC 2822 prescribes it for the In-Reply-To header.
        in_reply_to = reply_to_message_id
        if not in_reply_to.startswith("<"):
            in_reply_to = f"<{in_reply_to}>"
        msg["In-Reply-To"] = in_reply_to

        # References should be the full ancestor chain; if the caller
        # only supplied the immediate parent, use that as the chain.
        refs = reply_to_references or [reply_to_message_id]
        bracketed = [f"<{r}>" if not r.startswith("<") else r for r in refs]
        msg["References"] = " ".join(bracketed)

    msg.set_content(body_text)

    if attachments:
        for att in attachments:
            maintype, _, subtype = att.mime_type.partition("/")
            if not subtype:
                # Caller passed e.g. "application" with no slash; default
                # to "octet-stream" rather than crash. Gmail will accept
                # the wrong subtype better than it accepts a malformed
                # message structure.
                maintype, subtype = "application", "octet-stream"
            msg.add_attachment(
                att.data,
                maintype=maintype,
                subtype=subtype,
                filename=att.filename,
            )

    encoded_size = len(msg.as_bytes())
    if encoded_size > MAX_ENCODED_BYTES:
        raise OversizeMessage(encoded_size=encoded_size)

    return msg


def message_to_base64url(msg: EmailMessage) -> str:
    """Render the message as base64url-encoded ASCII suitable for Gmail's `raw` field.

    Gmail's users.messages.send takes a JSON body with a `raw` field
    that is base64url(no padding) of the RFC 5322 bytes. This helper
    centralizes that encoding so the send tool does not hand-roll it.
    """
    raw_bytes = msg.as_bytes()
    return base64.urlsafe_b64encode(raw_bytes).rstrip(b"=").decode("ascii")
