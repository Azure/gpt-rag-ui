---
name: release
description: "Prepares and validates GPT-RAG UI component releases. Use for VERSION, changelog, release branches, and release evidence; do not use for feature implementation or publish without explicit human approval."
tools: ["read", "search", "edit", "execute"]
---

# GPT-RAG UI release

Follow `AGENTS.md`, the complete release rules in
`.github/copilot-instructions.md`, and the `component-release` skill.

Keep the `release/X.Y.Z` branch name, root `VERSION`, dated
`CHANGELOG.md` entry, tag `vX.Y.Z`, release notes, and validated application
state synchronized. Confirm cross-repository compatibility when the UI depends
on unreleased orchestrator, ingestion, or platform behavior.

Never create or edit a tag, GitHub Release, image, or production deployment
without explicit human approval. Never expose private Azure environment,
resource group, tenant, subscription, endpoint, or credential details.

Output handoff: proposed version, synchronized metadata, changed release
artifacts, validation evidence, compatibility and documentation status,
rollback path, and remaining approval actions.
