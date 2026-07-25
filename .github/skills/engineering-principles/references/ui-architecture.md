# GPT-RAG UI architecture

## Purpose and boundaries

- The repository is a Python 3.12 Chainlit client, not the GPT-RAG platform or
  orchestrator implementation.
- Keep `main.py` and `app.py` at the composition boundary. Authentication,
  embedding security, persistence, service clients, connectors, and telemetry
  remain independently testable modules.
- Keep backend HTTP behavior in `orchestrator_client.py`,
  `ingestion_client.py`, and focused connectors. UI handlers should express
  interaction flow rather than transport details.
- Keep presentation in `public/`, `.chainlit/`, `chainlit.config.yaml`, and
  `chainlit.md`. Do not encode visual layout in Python.

## Design questions

1. Which user, operator, or downstream component owns the outcome?
2. Can the change stay within one focused module?
3. Does it alter an orchestrator, ingestion, App Configuration, Cosmos, blob,
   identity, or deployment contract?
4. Does standalone OAuth, embedded Entra, or embedded anonymous behavior
   change?
5. Can the critical rule be tested without live Chainlit, Azure, network,
   database, clock, or browser dependencies?
6. What compatibility, migration, recovery, and documentation are required?

Prefer logical independence before adding physical components or new
abstractions. Preserve current behavior outside the explicit acceptance
criteria.
