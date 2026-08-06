---
applyTo: "scripts/**/*.ps1,scripts/**/*.sh,azure.yaml,Dockerfile,infra/**"
---

# Deployment and lifecycle rules

- Keep PowerShell and shell lifecycle hooks behaviorally aligned.
- Preserve explicit `APP_CONFIG_ENDPOINT` precedence, warning behavior,
  managed identity, ACR build, Container Apps image update, and verification
  semantics unless the task requires a documented migration.
- Never echo credentials, tokens, secrets, private endpoints, tenant or
  subscription identifiers, or sensitive configuration.
- Keep commands non-interactive where automation requires it and fail with
  actionable context rather than apparent success.
- Preserve Windows PowerShell 5.1 and Linux/WSL compatibility where the
  existing scripts support them.
- Treat infrastructure, image, runtime dependency, and deployment topology
  changes as operator-visible changes requiring validation and documentation.
