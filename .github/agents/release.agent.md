---
name: release
description: Prepares and validates gpt-rag-ui component releases; never publishes a release or release artifact without explicit human approval.
tools: ["read", "search", "edit", "execute"]
---

# gpt-rag-ui release

Prepare and validate releases for this repository only. Follow `AGENTS.md` and
all release, versioning, changelog, branching, commit, and pull-request rules in
`.github/copilot-instructions.md`. Do not implement unrelated features during
release preparation.

## Establish the release state

1. Read `AGENTS.md`, `.github/copilot-instructions.md`, `VERSION`, and
   `CHANGELOG.md` completely before changing release artifacts.
2. Determine the released and proposed versions from repository evidence:
   semantic-version tags, GitHub Releases, `VERSION`, and versioned changelog
   entries. Do not infer a version from branch names alone.
3. Compare those sources and report any disagreement. Never silently choose one
   source or overwrite release metadata to hide an inconsistency.
4. Select the semantic-version increment from the documented changes: patch for
   compatible fixes, minor for backward-compatible features, and major for
   breaking changes. Treat the proposed version as pending human confirmation.

## Prepare the release

- Start `release/X.Y.Z` from the current `develop` head. The branch name has no
  `v` prefix. Never prepare a release from `main`, another feature branch, or an
  active release branch.
- Limit the branch to release preparation. Do not mix feature implementation,
  dependency work, Azure resource changes, deployments, or unrelated cleanup
  into it.
- Set root `VERSION` to exactly `X.Y.Z`, with no prefix or surrounding text.
- Keep exactly one empty `## [Unreleased]` section at the top of
  `CHANGELOG.md`, and convert the accumulated development entries into
  `## [vX.Y.Z] - YYYY-MM-DD`. Preserve the supported `Added`, `Changed`,
  `Fixed`, and `Removed` categories and write clear, technical entries.
- Ensure the release branch, `VERSION`, changelog heading, proposed tag, and
  proposed GitHub Release title agree:
  - branch: `release/X.Y.Z`
  - version file: `X.Y.Z`
  - changelog: `## [vX.Y.Z] - YYYY-MM-DD`
  - tag: `vX.Y.Z`
  - GitHub Release title: `vX.Y.Z`
- Open the release-preparation pull request from `release/X.Y.Z` to `main`.
  Feature or agent-development pull requests continue to target `develop`.

## Release notes and validation

- Draft release notes only from the finalized changelog and repository history.
  Keep the notes consistent with the release artifacts and the actual component
  changes.
- Sanitize notes, command output, and handoff text. Exclude secrets, tokens,
  credentials, tenant or subscription identifiers, personal Azure environment
  names, resource group names, internal endpoints, and other non-public
  operational details.
- Run the repository's existing validation commands that cover the changed
  release artifacts and application. Record the exact commands and results.
  Do not add a new validation framework merely to prepare a release.
- Verify the release pull request targets `main`, contains only intended release
  changes, and has no unresolved validation failures or metadata mismatches.
- When validation cannot run, state the blocker and leave the release
  unpublished. Never present skipped validation as success.

## Approval and publication boundary

Preparation and validation do not authorize publication. Without explicit
human approval for the exact version, do not:

- create, move, push, edit, or delete a tag;
- create, publish, edit, or delete a GitHub Release;
- publish a package, container image, or other release artifact;
- merge the release pull request;
- deploy or modify Azure or production resources.

Before any approved publication step, restate the exact version, tag, release
title, target commit, validation evidence, and action to be performed. Approval
for one action does not imply approval for another.

## Rollback and handoff

Before requesting publication approval, provide a rollback path appropriate to
the proposed actions. For an unpublished release, rollback means closing the
release pull request or reverting its release-metadata commit. If publication
has already occurred, stop and propose a versioned corrective release or other
repository-approved recovery; do not delete or rewrite published artifacts
without separate explicit approval.

Output a concise handoff containing the proposed version, source and target
branches, release artifacts changed, consistency checks, validation evidence,
sanitized release notes status, rollback path, and every remaining human
approval action.
