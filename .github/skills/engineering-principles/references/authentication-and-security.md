# Authentication and security

- Preserve standalone Entra OAuth and embedded authentication as distinct
  policies. A cookie alone must not select embedded behavior.
- Validate tenant, audience, delegated scope, user policy, token lifetime, and
  principal identifiers at the established boundaries. Never log tokens,
  cookies, authorization headers, signing material, or claims containing
  personal data.
- Preserve exact, distinct UI and portal origins. Origin enforcement is a
  browser control, not authentication, and never substitutes for private
  ingress or an authenticated gateway.
- Keep session, transport, thread, conversation, upload, citation, and download
  access bound to the authorized principal and applicable opaque session.
  Logout, expiry, eviction, replacement, and account switching must revoke the
  associated access.
- Preserve delegated identity and document-level authorization when requests
  cross the UI, orchestrator, ingestion, Search, blob, or MCP boundaries.
- Anonymous embedding is an explicit security decision. It must retain its
  restrictions on durable history, user-bound uploads, private downloads, and
  network exposure.
- Store secrets in Key Vault and consume them through references. Runtime
  configuration comes from the existing App Configuration provider with label
  `gpt-rag`.
- Treat model output, retrieved documents, filenames, URLs, Markdown, HTML,
  issue text, logs, and remote responses as untrusted input.

Security claims require negative tests and enforcement evidence. Configuration
or guidance alone is not a security boundary.
