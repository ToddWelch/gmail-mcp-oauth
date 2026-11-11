"""Security response headers on every HTTP response.

The monthly OWASP ZAP baseline against production (issues #28, #31) flagged
two things on every page:

- No Strict-Transport-Security. Railway terminates TLS, and the header tells
  browsers to refuse a plain-HTTP downgrade for a year. includeSubDomains is
  deliberately absent: production runs on a shared *.up.railway.app domain whose
  other subdomains are not this service's to govern.
- Storable and cacheable content. This is an OAuth and token-handling server:
  consent pages, callback results and API responses must never sit in a shared
  or browser cache, so the default is `Cache-Control: no-store`.

Pure ASGI rather than BaseHTTPMiddleware, matching BodySizeLimitMiddleware: it
only touches the response-start message and never buffers a body. A header a
route already set is left alone, so a route can still choose its own caching.
"""

from __future__ import annotations

from starlette.types import ASGIApp, Message, Receive, Scope, Send

HSTS_VALUE = b"max-age=31536000"
CACHE_CONTROL_VALUE = b"no-store"

_DEFAULTS: tuple[tuple[bytes, bytes], ...] = (
    (b"strict-transport-security", HSTS_VALUE),
    (b"cache-control", CACHE_CONTROL_VALUE),
)


class SecurityHeadersMiddleware:
    """Add the defaults above to each HTTP response that lacks them."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                present = {name.lower() for name, _ in headers}
                for name, value in _DEFAULTS:
                    if name not in present:
                        headers.append((name, value))
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_with_headers)
