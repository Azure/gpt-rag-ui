# Testing and evidence

Choose validation according to the changed boundary:

- Local policy or transformation: focused `unittest` coverage.
- Authentication, sessions, origins, uploads, citations, or downloads:
  positive and negative security tests.
- Orchestrator, ingestion, Cosmos, blob, or App Configuration adapters:
  contract tests with mocked external boundaries.
- Chainlit event wiring: handler behavior with framework dependencies patched
  at the boundary.
- Themes and frontend assets: light and dark themes, keyboard and focus
  behavior, responsive layout, and affected auth modes.
- PowerShell or shell hooks: syntax plus behavioral parity checks.
- Cross-repository behavior: validate the exact compatible commits or tags and
  document integration and rollback order.

The suite uses `unittest`. Run a focused module first, for example
`python -m unittest tests.test_embed_security -v`, then use
`python -m unittest discover -s tests -v` when risk warrants the full suite.

For every change, capture:

1. Acceptance criterion and observable result.
2. Commands or manual methods and their results.
3. Configuration and component versions relevant to the result.
4. Compatibility, accessibility, migration, and rollback impact.
5. Validation that could not run and the resulting risk.

Tests should observe behavior and contracts, not incidental implementation.
A task is incomplete if the expected outcome cannot be verified.
