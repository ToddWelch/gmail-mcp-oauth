"""Thin async wrapper around the Gmail REST API.

Every outbound call to gmail.googleapis.com goes through GmailClient.
Owning the full upstream surface in one class (this file plus the
write-side mixin in gmail_client_write.py) makes "what does this
service talk to upstream" trivial to audit. The class is intentionally
boring: HTTP verbs in, JSON dicts out, errors translated to
GmailApiError with the upstream status preserved.

Why httpx (not google-api-python-client)
----------------------------------------
google-api-python-client pulls in google-auth, googleapis-common-protos,
and a transitive list of HTTPS retry shim layers. httpx is already a
dependency for OAuth and gives us:
- Async-native (matches the FastAPI request loop).
- Cleanly mockable via respx in tests.
- Direct visibility into request/response (the audit story is "look
  at this file"; nothing happens behind a generated client surface).
- Smaller dependency surface (security review reads the diff, not a
  client SDK release).

Authentication
--------------
Every method takes a non-expired Google access token (passed at
construction). Token refresh / cache lookup belongs to
token_manager.py; this module is purely a transport. The token is
sent as Authorization: Bearer <token>.

Error mapping
-------------
- 401 from Gmail -> GmailApiError(status=401). Caller decides whether
  to refresh + retry or surface to the user.
- 403 -> GmailApiError(status=403). Usually a scope issue.
- 404 -> GmailApiError(status=404). Usually a missing message ID.
- 429 -> GmailApiError(status=429, retry_after_seconds=...).
- 5xx -> GmailApiError(status=5xx).

We do NOT retry inside the client. Retry policy is a higher layer
concern.

Layout
------
This file holds the base class (HTTP plumbing) and the READ methods
that the tools call. Write methods (send, draft, modify, label
mgmt, filter mgmt) live in gmail_client_write.py and are mixed in via
inheritance so the file-size rule is honored without splitting the
public class surface.
"""

from __future__ import annotations

from typing import Any

import httpx

from .gmail_client_write import _GmailWriteMixin
from .gmail_id import validate_gmail_id


GMAIL_API_BASE = "https://gmail.googleapis.com/gmail/v1"


class GmailApiError(Exception):
    """Wrap a non-2xx Gmail API response.

    The body is captured verbatim and exposed via .body for the
    dispatcher's error mapper. Tests assert on .status. Callers MUST
    NOT log .body raw because Gmail occasionally echoes user-supplied
    data (recipients, subject) back in error responses.
    """

    def __init__(
        self,
        message: str,
        *,
        status: int,
        body: str = "",
        retry_after_seconds: int | None = None,
    ):
        super().__init__(message)
        self.status = status
        self.body = body
        self.retry_after_seconds = retry_after_seconds


def _retry_after_from(headers: httpx.Headers) -> int | None:
    raw = headers.get("Retry-After")
    if not raw:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


class GmailClient(_GmailWriteMixin):
    """Async client for Gmail v1 REST endpoints.

    A single instance is intended to be created per dispatch and
    discarded; the underlying httpx.AsyncClient is owned by the
    instance and closed on aclose(). Tests inject a mock by passing
    `client=` explicitly.

    Read endpoints live in this class. Write endpoints
    live in `_GmailWriteMixin`; see gmail_client_write.py.
    """

    def __init__(
        self,
        *,
        access_token: str,
        timeout: float = 15.0,
        client: httpx.AsyncClient | None = None,
    ):
        if not access_token:
            raise ValueError("access_token is required")
        self._token = access_token
        self._timeout = timeout
        self._owned = client is None
        self._client = client or httpx.AsyncClient(timeout=timeout)

    async def aclose(self) -> None:
        if self._owned:
            await self._client.aclose()

    async def __aenter__(self) -> "GmailClient":
        return self

    async def __aexit__(self, *_a: Any) -> None:
        await self.aclose()

    # ---- low-level HTTP -----------------------------------------------------

    def _headers(self, *, json_body: bool = False) -> dict[str, str]:
        h = {"Authorization": f"Bearer {self._token}", "Accept": "application/json"}
        if json_body:
            h["Content-Type"] = "application/json"
        return h

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        url = f"{GMAIL_API_BASE}{path}"
        try:
            resp = await self._client.request(
                method,
                url,
                params=params,
                json=json_body,
                headers=self._headers(json_body=json_body is not None),
            )
        except httpx.HTTPError as exc:
            raise GmailApiError(f"network error: {exc}", status=0) from exc

        if resp.status_code >= 400:
            raise GmailApiError(
                f"gmail returned {resp.status_code}",
                status=resp.status_code,
                body=resp.text,
                retry_after_seconds=_retry_after_from(resp.headers),
            )
        if resp.status_code == 204 or not resp.content:
            return {}
        try:
            payload = resp.json()
        except ValueError as exc:
            raise GmailApiError(
                "gmail returned non-JSON body",
                status=resp.status_code,
                body=resp.text,
            ) from exc
        if not isinstance(payload, dict):
            raise GmailApiError(
                "gmail returned non-object body",
                status=resp.status_code,
                body=resp.text,
            )
        return payload

    async def _get(self, path: str, *, params: dict[str, Any] | None = None) -> dict[str, Any]:
        return await self._request("GET", path, params=params)

    async def _post(self, path: str, *, body: dict[str, Any]) -> dict[str, Any]:
        return await self._request("POST", path, json_body=body)

    async def _put(self, path: str, *, body: dict[str, Any]) -> dict[str, Any]:
        return await self._request("PUT", path, json_body=body)

    async def _delete(self, path: str) -> dict[str, Any]:
        return await self._request("DELETE", path)

    # ---- read: messages -----------------------------------------------------

    async def get_message(
        self,
        *,
        message_id: str,
        format: str = "full",
        metadata_headers: list[str] | None = None,
    ) -> dict[str, Any]:
        # validate ID before path interpolation.
        # optional metadataHeaders repeated query param (httpx
        # serializes lists in `params` as repeated keys). Schema
        # restricts header names to token chars .
        message_id = validate_gmail_id(message_id, field="message_id")
        params: dict[str, Any] = {"format": format}
        if metadata_headers:
            params["metadataHeaders"] = list(metadata_headers)
        return await self._get(
            f"/users/me/messages/{message_id}",
            params=params,
        )

    async def list_messages(
        self,
        *,
        q: str | None = None,
        label_ids: list[str] | None = None,
        page_token: str | None = None,
        max_results: int | None = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if q is not None:
            params["q"] = q
        if label_ids:
            params["labelIds"] = label_ids
        if page_token is not None:
            params["pageToken"] = page_token
        if max_results is not None:
            params["maxResults"] = max_results
        return await self._get("/users/me/messages", params=params)

    async def get_attachment(
        self,
        *,
        message_id: str,
        attachment_id: str,
    ) -> dict[str, Any]:
        # validate both IDs before path interpolation. The
        # tool layer (messages.download_attachment) ALSO validates the
        # attachment_id with the existing Gmail-ID check; double
        # validation is cheap and the second guard sits at the
        # upstream boundary.
        message_id = validate_gmail_id(message_id, field="message_id")
        attachment_id = validate_gmail_id(attachment_id, field="attachment_id")
        return await self._get(f"/users/me/messages/{message_id}/attachments/{attachment_id}")

    # ---- read: threads ------------------------------------------------------

    async def get_thread(
        self,
        *,
        thread_id: str,
        format: str = "full",
    ) -> dict[str, Any]:
        # validate ID before path interpolation.
        thread_id = validate_gmail_id(thread_id, field="thread_id")
        return await self._get(
            f"/users/me/threads/{thread_id}",
            params={"format": format},
        )

    async def list_threads(
        self,
        *,
        q: str | None = None,
        label_ids: list[str] | None = None,
        page_token: str | None = None,
        max_results: int | None = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if q is not None:
            params["q"] = q
        if label_ids:
            params["labelIds"] = label_ids
        if page_token is not None:
            params["pageToken"] = page_token
        if max_results is not None:
            params["maxResults"] = max_results
        return await self._get("/users/me/threads", params=params)

    # ---- read: labels and filters -------------------------------------------

    async def list_labels(self) -> dict[str, Any]:
        return await self._get("/users/me/labels")

    async def list_filters(self) -> dict[str, Any]:
        return await self._get("/users/me/settings/filters")

    async def get_filter(self, *, filter_id: str) -> dict[str, Any]:
        # validate ID before path interpolation.
        filter_id = validate_gmail_id(filter_id, field="filter_id")
        return await self._get(f"/users/me/settings/filters/{filter_id}")
