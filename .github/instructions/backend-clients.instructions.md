---
applyTo: "orchestrator_client.py,ingestion_client.py,connectors/**/*.py,tests/test_ingestion_security.py"
---

# Backend client and connector rules

- Keep HTTP and Azure client behavior out of Chainlit handlers.
- Use explicit typed payloads and preserve current orchestrator, ingestion,
  App Configuration, blob, and identity contracts.
- Set bounded timeouts and retries. Retry only safe operations and preserve
  cancellation.
- Validate status codes and response shapes, retain useful causal context, and
  surface failures through configured logging and user error paths.
- Forward only the required delegated identity and authorization context.
  Never log or persist bearer tokens, API keys, cookies, or sensitive claims.
- Treat remote payloads, URLs, filenames, model content, and metadata as
  untrusted input.
- Mock service boundaries in tests and assert payloads, headers, timeout,
  retry, and error translation behavior.
