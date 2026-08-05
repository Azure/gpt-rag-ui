---
name: engineering-principles
description: "GPT-RAG UI architecture and implementation principles. Use for design, review, meaningful refactoring, Python, Chainlit, Azure integration, security, accessibility, testing, or operational changes."
---

# GPT-RAG UI engineering principles

Load only the references needed for the task:

| When the task involves | Read |
| --- | --- |
| Repository purpose, modules, boundaries, or Chainlit composition | [UI architecture](references/ui-architecture.md) |
| Entra, embedding, sessions, origins, secrets, uploads, or downloads | [Authentication and security](references/authentication-and-security.md) |
| Themes, CSS, frontend assets, interaction, or responsive behavior | [Frontend accessibility](references/frontend-accessibility.md) |
| Python clarity, async behavior, contracts, or error handling | [Python quality](references/python-quality.md) |
| Tests, validation, compatibility, or completion evidence | [Testing and evidence](references/testing-and-evidence.md) |
| App Configuration, Azure clients, deployment, telemetry, or recovery | [Cloud and operations](references/cloud-and-operations.md) |

Use these principles as design questions rather than dogma. Task
requirements, executable configuration, backend contracts, security
invariants, and current implementation remain the sources of truth.
