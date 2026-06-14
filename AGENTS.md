## Engineering Standards

### Clean Code and Modularity

All implementations in this repository should follow clean code best practices.
The UI is a Python 3.12 **Chainlit** chat application with Entra ID OAuth and
feedback persistence; keep presentation, auth, and backend-client logic
separated, and avoid letting any single module become a catch-all for
unrelated behavior.

- Keep each module and file focused on a single, clear responsibility.
- Keep the Chainlit entrypoints (`app.py`, `main.py`) focused on
  composition and event wiring; place reusable behavior in dedicated modules
  rather than inflating the entrypoints:
  - `auth_oauth.py` — Entra ID OAuth flow.
  - `feedback.py` / `datalayer.py` — feedback and persistence (Cosmos DB).
  - `orchestrator_client.py` / `ingestion_client.py` — calls to backend
    services (keep all HTTP/client logic here, not in UI handlers).
  - `connectors/` — Azure / external service clients.
  - `telemetry.py` — logging and instrumentation.
- Prefer small, cohesive functions and classes over large handlers. Respect
  async correctness — do not block the event loop with synchronous I/O.
- Reuse the existing client modules, connectors, and constants before adding
  new ones. Avoid duplication and speculative abstractions; extract only when
  code is genuinely repeated or a file is mixing concerns.
- Use clear, intent-revealing names so the code reads without excessive
  comments. Comment only non-obvious decisions.

### Theming and Presentation

Keep visual customization in its dedicated places — `public/theme.json`,
`public/custom.css`, and the Chainlit config (`chainlit.config.yaml` /
`.chainlit/`) — rather than hardcoding styling or layout in Python.

### Configuration, Secrets, and Contracts

- Read runtime settings from **Azure App Configuration** (label `gpt-rag`) via
  the existing config provider; resolve secrets through **Key Vault**
  references. Never hardcode backend URLs (orchestrator base URL, etc.),
  client IDs, or feature flags in code.
- Prefer typed, explicit data contracts (type hints, dataclasses, or Pydantic
  models) for payloads exchanged with the orchestrator and ingestion
  services.
- Surface errors clearly and consistently to the user and the
  telemetry/logging helpers. Do not swallow exceptions or add silent
  fallbacks that hide auth, backend, or persistence failures. Never use
  `print` for diagnostics — use the configured logger.

### Verifying Changes

There is no maintained `tests/` suite here. Verify changes by running the
Chainlit app locally or via `scripts/deploy.*`, then exercising the affected
flow (login, chat round-trip, feedback) against a deployed backend.
