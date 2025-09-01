# Changelog

All notable changes to this project will be documented in this file.  
This format follows [Keep a Changelog](https://keepachangelog.com/) and adheres to [Semantic Versioning](https://semver.org/).

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
