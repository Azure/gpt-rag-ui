# Cloud and operations

- Use the existing Azure App Configuration provider with label `gpt-rag`.
  Resolve secrets through Key Vault references and prefer managed identity
  with least-privilege RBAC.
- Keep App Configuration keys, defaults, environment overrides, infrastructure
  publication, and every consumer synchronized as one cross-repository
  contract.
- Define bounded timeouts, retries, limits, status handling, cancellation, and
  recovery at network and persistence boundaries. Retry only operations that
  are safe to repeat.
- Use structured logging, traces, metrics, correlation identifiers, and
  version signals without sensitive content.
- Keep network-isolated deployment paths viable. Document any requirement for
  a VNet-connected runner, jumpbox, private endpoint, gateway, or ACR Task.
- Keep `scripts/deploy.ps1` and `scripts/deploy.sh`, and the matching
  pre-provision hooks, behaviorally aligned.
- Preserve current image, App Configuration, and Container Apps deployment
  semantics unless the change explicitly requires a migration.
- Define health, failure visibility, rollback or roll-forward, and operator
  evidence for changes that affect deployment or production operation.
