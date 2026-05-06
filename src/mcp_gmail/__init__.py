"""mcp-gmail: MCP server wrapping the Google Gmail API.

OAuth-authenticated MCP (Model Context Protocol) server that lets an
LLM agent or any MCP-compatible client read, search, send, draft,
label, and filter mail across one or more Gmail accounts per
authenticated user. Bearer JWT auth on the inbound side (any OIDC
provider); Google OAuth 2.0 on the outbound side; refresh tokens
encrypted at rest with Fernet (MultiFernet for online key rotation).
"""

__version__ = "0.1.0"
