# Security Policy

## Reporting a vulnerability

Please report security vulnerabilities through GitHub's private
vulnerability reporting feature by clicking "Report a vulnerability"
in the Security tab of this repository. See GitHub's documentation at
https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability
for details on the private disclosure flow.

We aim to acknowledge reports within 3 business days.

## In scope

- The mcp-gmail service code (this repository).
- The OAuth flow, JWT validation, allowlist gate, and post-callback
  confirmation page.
- The Gmail tool surface (read, write, cleanup, bootstrap tools).
- The MultiFernet token-encryption pipeline.

## Out of scope

- Vulnerabilities in upstream dependencies (report to the
  dependency).
- Vulnerabilities in Auth0, Google Cloud / Gmail API, or any other
  third-party service this code integrates with (report to the
  service operator).
- Misconfiguration of a self-hosted deployment (e.g. forgetting to
  set `MCP_ALLOWED_AUTH0_SUBS`, reusing the same Fernet key across
  environments). The README and DR runbook document the supported
  configuration.

## What to include in a report

- A clear description of the vulnerability and its potential
  impact.
- Steps to reproduce.
- Affected version (commit SHA preferred).
- Whether you intend to publicly disclose, and your preferred
  disclosure timeline.
