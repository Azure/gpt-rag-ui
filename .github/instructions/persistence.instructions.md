---
applyTo: "datalayer.py,feedback.py,tests/test_datalayer*.py,tests/test_feedback_security.py"
---

# Persistence and feedback rules

- Preserve Chainlit data-layer contracts and Cosmos document compatibility.
- Keep tenant, user, thread, conversation, feedback, and authorization
  identifiers correctly bound. Do not broaden query scope or trust
  client-supplied ownership.
- Treat schema changes as compatibility changes. Prefer additive evolution and
  document migration, coexistence, rollback, and retention impact.
- Do not store access tokens, cookies, secrets, raw authorization headers, or
  unnecessary personal data.
- Surface persistence failures explicitly through existing logging and
  user-visible behavior. Do not return success after a failed write.
- Keep async persistence non-blocking and test success, not-found,
  unauthorized, malformed, and backend-failure paths with mocked boundaries.
