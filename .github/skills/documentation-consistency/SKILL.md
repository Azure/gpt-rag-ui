---
name: documentation-consistency
description: "Keeps GPT-RAG UI developer, user, and operator documentation aligned with shipped behavior. Use for features, configuration keys, security policy, deployment parameters, defaults, UI behavior, or breaking changes."
---

# GPT-RAG UI documentation consistency

Canonical GPT-RAG product documentation is published from the `docs` branch of
`Azure/GPT-RAG` at https://azure.github.io/GPT-RAG/. This repository keeps
component-specific material in `README.md`, `docs/`, `chainlit.md`, code
comments, examples, and release metadata.

1. Identify the developer, user, or operator behavior that changed.
2. Search local and central documentation for the feature, configuration key,
   endpoint, security requirement, UI term, and previous behavior.
3. Update every affected local page in the same change.
4. Coordinate a central documentation change when the published architecture,
   deployment, configuration, or user journey is affected.
5. Keep the repository README concise and link to canonical documentation
   instead of duplicating platform guidance.
6. Ensure examples match current defaults, supported auth modes, security
   boundaries, deployment modes, and accessibility behavior.
7. Report local and central documentation status in the implementation
   handoff.

A user-visible or operator-visible change is incomplete until documentation is
updated or the search demonstrates that no published page is affected.
