---
applyTo: "VERSION,CHANGELOG.md,.gitattributes,.github/dependabot.yml,.github/scripts/requirements.txt,.github/workflows/**,.github/pull_request_template.md"
---

# Repository and release metadata rules

- Follow `.github/copilot-instructions.md` as the complete source for branch,
  version, changelog, and release policy.
- Keep `develop` changes under the single `## [Unreleased]` changelog section.
- Release branches use `release/X.Y.Z`; `VERSION` uses `X.Y.Z`; changelog
  headings and tags use `vX.Y.Z`.
- Do not mix feature work into release preparation or preemptively change
  `VERSION` on `develop`.
- Pin CI-only Python dependencies exactly in their isolated requirements file.
  Pin GitHub Actions to immutable commit SHAs and retain the corresponding
  release version in comments.
- Workflows use least-privilege permissions, bounded triggers, and no secret
  output. `pull_request_target` workflows must never check out or execute pull
  request code.
- Publishing tags, releases, images, or production deployments requires
  explicit human approval.
