# Changelog

All notable changes to this project will be documented in this file.  
This format follows [Keep a Changelog](https://keepachangelog.com/) and adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [v2.2.3] – 2026-03-24

### Added
- **Release Footer**: Added a configurable release footer that displays GPT-RAG and GPT-RAG UI version numbers at the bottom of the chat interface. The footer fetches version data from a new `/version-footer` endpoint and is controlled by the `SHOW_RELEASE_FOOTER` App Configuration setting (default `true`). Missing version values display a descriptive fallback message, and non-prefixed values receive an automatic `v` prefix.
- **Version Footer JavaScript Module**: Introduced `public/footer-version.js`, a self-contained script that creates, positions, and updates the footer element, including layout-aware spacing to prevent overlap with the Chainlit composer input area.
- **Version Footer CSS Styles**: Added footer styling in `public/custom.css` with fixed positioning, responsive font sizing for mobile, and visually subtle divider between the two version labels.

### Changed
- **Application Architecture Refactor**: Restructured `main.py` to use a host `FastAPI` app that mounts both the Chainlit app (`/`) and the blob download sub-app (`/api/download`), enabling top-level routes like `/version-footer` that are independent of the Chainlit middleware stack.
- **VERSION File Reading**: Consolidated duplicated VERSION file reading logic into reusable `_read_local_ui_version()` and `_local_version_file_path()` helpers, eliminating code duplication and improving error handling.

## [v2.2.2] – 2026-03-01
### Added
- Integrated **Low Latency Streaming** compatibility with MAF V2 Orchestrator. The UI now implements native `fetch` with `Transfer-Encoding: chunked`.
- Added reactive buffering UI logic parsing to safely extract 36-char `conversation_id` from the raw byte stream chunk.
### Fixed
- Fixed streaming network fragmentation loss when reading UTF-8 characters via `TextDecoder(stream=True)`.

## [v2.2.1] – 2026-02-04
### Fixed
- Simplified docker image
- Fixed Docker builds on ARM-based machines by explicitly setting the target platform to `linux/amd64`, preventing Azure Container Apps deployment failures.
### Changed
- Pinned the Docker base image to `mcr.microsoft.com/devcontainers/python:3.12-bookworm` to ensure stable package verification behavior across environments.
- Bumped `aiohttp` to `3.13.3`.
- Standardized on the container best practice of using a non-privileged port (`8080`) instead of a privileged port (`80`), reducing the risk of runtime/permission friction and improving stability of long-running ingestion workloads.

## [v2.2.0] – 2026-01-15
### Added
- Added support for Microsoft Entra ID authentication in the UI and forwarding the end-user access token to the orchestrator; this token is used to validate the user and propagate retrieval authorization, enabling document-level security.

## [v2.1.1] – 2025-10-21
### Added
- Added more troubleshooting logs.
### Fixed
- Citations [387](https://github.com/Azure/GPT-RAG/issues/387)

## [v2.1.0] – 2025-08-31
### Added
- User Feedback Loop. [#358](https://github.com/Azure/GPT-RAG/issues/358) 
### Changed
- Standardized resource group variable as `AZURE_RESOURCE_GROUP`. [#365](https://github.com/Azure/GPT-RAG/issues/365)

## [v2.0.2] – 2025-08-18
### Added
- Early Docker validation in the PowerShell deployment script (`deploy.ps1`), including checks for CLI presence, service status, and Docker Desktop availability, with clearer error messages and guidance.

### Fixed
- Orchestrator client (`orchestrator_client.py`) now defaults `ORCHESTRATOR_APP_APIKEY` to an empty string if not set, preventing key errors.
- Dapr API token handling improved: header included only if token is present, with missing token warnings downgraded to debug-level logs.
- Refined error messages for orchestrator invocation failures to clarify the source of errors.
- Improved debug mode toggle handling in the deployment script for clearer output.

## [v2.0.1] – 2025-08-08
### Fixed
- Corrected v2.0.0 deployment issues.

## [v2.0.0] – 2025-07-22
### Changed
- Major architecture refactor to support the vNext architecture.

## [v1.0.0] 
- Original version.
