---
applyTo: "*.py,connectors/**/*.py,tests/**/*.py,.github/scripts/*.py"
---

# Python implementation rules

- Target Python 3.12 and follow existing module, typing, naming, and
  `unittest` conventions.
- Keep `main.py` and `app.py` focused on composition and Chainlit event wiring.
  Put reusable behavior in the existing focused module.
- Preserve async correctness, cancellation, bounded I/O, and explicit error
  propagation. Do not block the event loop.
- Reuse constants, clients, connectors, security helpers, and data contracts
  before adding abstractions.
- Use configured logging and telemetry; never use `print` for diagnostics or
  log secrets, tokens, personal data, private endpoints, or authorization
  material.
- Test observable behavior with external services and Chainlit patched at
  their boundaries.
