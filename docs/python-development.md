# Python development and package migration

This is the UI implementation checkpoint for
[Azure/GPT-RAG#681](https://github.com/Azure/GPT-RAG/issues/681), coordinated in
[Azure/GPT-RAG#689](https://github.com/Azure/GPT-RAG/pull/689).
The accepted coordination ADR is ADR-0005 in that PR. The component remains
compatible by design with orchestrator v4.1.1 and ingestion v2.7.3; local
mocked-boundary evidence is not live Azure integration evidence.

## Setup and unchanged startup

Use Python 3.12:

```text
python -m pip install -r requirements.txt
python -m pip install -r requirements-quality.txt
python -m pip install --no-deps -e .
python -m unittest discover -s tests -v
uvicorn main:app --host 0.0.0.0 --port 8080
```

`requirements.txt` remains the sole runtime dependency list. The setuptools
distribution installs code and supported legacy modules, with no duplicate
runtime dependency declaration. Editable installation is for contributors;
deployment uses `python -m pip install --no-deps .`. Docker still runs from
`/app` with the same Uvicorn command. No deployment hooks, infrastructure,
backend wire contracts, authentication defaults or frontend assets change.
`VERSION` is deliberately unchanged, including its existing value.

## Ownership and imports

`src/gpt_rag_ui/bootstrap.py` owns ASGI composition and the application instance.
`api/` owns route/callback registration; `services/` owns chat, shared citation
rendering, history, continuity, conversation/download decisions and panel
metadata operations. `auth/` owns identity/session/transport primitives;
`clients/` owns backend/storage transports. `config/` owns the existing
AppConfig provider and cache, settings and resource-root resolution;
`telemetry/` owns instrumentation; `util/` owns constants.

`.quality/migration.json` records all 32 researched runtime modules and original
public exports against `c635bc6696714b543feec24b4a062a8a8f3ff6d0`.
`.quality/policy.json` lists current canonical modules and explicit legacy
adapters. Root `main.py`, `app.py`, the other legacy modules and `connectors/`
contain no business definitions. Public callables/classes share their canonical
objects. Tests patch canonical owners, not arbitrary private adapter globals.

Dependencies flow from bootstrap to API, services, clients, auth, telemetry,
config and util, with no upward edges or cycles. Implementations never import
legacy adapters. Private first-party imports require exact recorded allowances;
the five existing ingestion-to-orchestrator transport helper imports are
explicitly inventoried within `clients/`, not exported as a new shared API.

`api.callbacks.register_callbacks()`, `api.history.register_data_layer()` and
`api.oauth.register_oauth_callback()` own idempotent registration. The OAuth
adapter accepts Chainlit 2.9.4's optional fifth argument and delegates to the
unchanged four-argument OAuth implementation. Classic backend startup does not
import hosted Conversations or panel Cosmos. `hosted_agent` remains the default.

## Installed resources

The supported installed artifact is **code plus staged assets**, not a
self-contained wheel. Keep `.chainlit/`, `public/`, `chainlit.config.yaml`,
`chainlit.md` and `VERSION` together in the writable application root.
Use existing `CHAINLIT_APP_ROOT` for an explicitly staged root, or start from
that directory. A source-checkout `main.py` passes its adjacent asset root.
The root is resolved before importing Chainlit and is shared by VERSION,
config synchronization and Chainlit public/upload paths. Never write to
site-packages or introduce `sys.path`/`sys.modules` compatibility tricks.

Missing VERSION remains optional; missing `.chainlit/config.toml` retains the
existing warning behavior. Disconnected App Configuration remains a 503
not-ready application rather than a successful chat fallback.

```text
python -m pip wheel --no-deps --wheel-dir .artifacts/wheel .
python -m unittest discover -s tests -p test_module_compatibility.py -v
python -m unittest discover -s tests -p test_installed_package.py -v
```

Installed acceptance uses temporary non-repository directories and a
non-editable wheel. It creates a clean venv, installs the unchanged
`requirements.txt`, runs `pip check`, and asserts canonical and legacy UI
imports resolve from that environment. It also copies the existing behavioral
tests, not application sources, and runs them against the installed wheel.
This clean dependency/installed behavior coverage supersedes the earlier
system-site-packages checkpoint; it is not itself Linux image evidence.

## Quality interface and current adoption limits

```text
python .github/scripts/check-quality.py --check all --base-ref <protected-base-sha> --report .artifacts/quality.json
python -m unittest discover -s tests -p test_quality_policy.py -v
```

`--check` accepts `all`, `lint`, `typing`, `architecture`, `exceptions`, `policy`.
Exit 0 means passed, 1 means violations, 2 means invalid inputs or incomplete
tool execution. Reports bind base/head/policy SHAs, installed tool versions,
findings, typing coverage and broad-handler inventory. Checks do not rewrite
source, policy or baselines, import runtime code, or connect to Azure.

### Policy and execution evidence

The four governance records have closed schemas: unknown/missing fields,
duplicate keys/IDs/sites, invalid dates/versions, unsafe paths, inconsistent
scope references and duplicate move destinations fail. Module records include
explicit typing status, public/private ownership and exact adapter forwarding
declarations. An inventoried facade may forward through a declared adapter
chain only if it terminates at an existing, declared canonical export. Extra
imports, mutable state, initialization calls or changed forwarding order fail.

Protected typing identities survive import/path moves; new modules enter
blocking coverage independently of candidate scope. An ordinary move must have
one-to-one identity and unchanged normalized syntax. Changed moves and splits
require protected responsibility/debt allocation; they are not automatically
approved by a candidate map. Individual retained debt is intersected with the
protected baseline, permitting genuine retirement without permitting revival
or duplication.

Annotation policy compares qualified functions, overload occurrences, parameter
kinds, variadic arguments, returns, variables, decorators and local module-level
type aliases. Suppression comments are bound to syntax sites, not just counted;
moving an unchanged ignore to another error is a policy change. String literals
that merely mention `noqa` are not directives. These are static syntax checks,
not a proof about arbitrary Python metaprogramming.

Variable dynamic imports need exact site/context fingerprints, permitted
targets and executed behavior tests. All permitted first-party targets enter
the dependency graph. Literal loader aliases and keyword arguments are resolved
as well. Handler fingerprints cover the protected `try` operation, catch/outcome
and distinct occurrences, so identical handler bodies at separate sites cannot
share one allowance.

`--test-evidence <file>` supplies an optional execution receipt to the quality
CLI. Without valid evidence, no exception or dynamic-import behavior approval
can be consumed. The separate `.github/scripts/run-unittest.py` uses standard
`unittest` discovery and records each exact test method, source fingerprints
and outcome. Referenced skipped/expected-failure tests are not passing evidence;
failed subtests, unexpected successes, stale source or a failed suite cannot
approve a boundary. Exception records must also be active in the protected base,
match the exact source/caught types, have an unexpired `expires_on` date and
not have passed their `review_by_stage` (`bootstrap`, `blocking`, `strict`).
Contractual best-effort outcomes remain representable; logging is not approval.

For a local, same-run receipt in PowerShell:

```powershell
$env:QUALITY_RUN_ID = [guid]::NewGuid().ToString()
python .github\scripts\run-unittest.py --base-ref <protected-base-sha> --report .artifacts\unittest.json
python .github\scripts\check-quality.py --check all --base-ref <protected-base-sha> --test-evidence .artifacts\unittest.json --report .artifacts\quality.json
```

Set `QUALITY_RUN_ID` once per run when using other shells as well. CI instead
binds the GitHub run ID and attempt. Receipts/reports bind repository, base/head,
source digest and run context; quality artifacts also bind protected policy,
toolchain and the exact receipt digest. Integrity hashes detect alteration,
not authenticity: the protected runner/evaluator and actual job conclusions
remain the trust boundary. `--pattern` on the unittest runner supports focused
local work, but the CI aggregate requires full `test_*.py` discovery.

The existing workflow extracts the protected-base runner, checker, aggregator
and tool pins when policy exists. The quality matrix consumes the separate
unittest artifact, and `quality-gate` requires the real matrix, unittest and
`container-tests` results plus every fresh artifact. The container job builds
an ephemeral Ubuntu Docker image and runs `tests/container_smoke.py` with
networking disabled; it does not publish an image or deploy to Azure. Its
result is pending until that CI job executes successfully. A missing local
Docker engine is a local limitation, not proof that Linux CI cannot run.

Tested tool pins are Ruff 0.16.5, mypy 2.3.1, Import Linter 2.14 and Grimp 3.16.
The higher Ruff/Import Linter/Grimp versions proposed during parent research
were unavailable from the configured package index; no runtime pin changed.

The initial blocking typing seeds are the canonical `config.chat_backend`,
`config.panel_config` and `config.hosted_continuity_config`. Newly introduced
modules and legacy adapters also enter blocking coverage. Existing moved
modules retain stable IDs and their prior uncovered status. The explicit
scope, future expansion and one-to-one moves are in `typing-scope.json`.
`typing-baseline.json` is empty: debt cannot be traded by total error count,
duplicated or revived after retirement. Imported legacy diagnostics stay visible
without being described as full-repository typing coverage.

Ruff selects F821, E722, BLE001, PGH003, PGH004 and RUF100. The supplementary
AST handler inventory includes logged and re-raised broad handlers that BLE001
exempts. `.quality/handler-inventory.json` records inherited sites;
`exceptions.json` intentionally contains no approved exceptions. In particular,
configuration-default fallbacks, classic conversation-list empty responses and
legacy SAS fallback need explicit compatibility/error-policy decisions.
Logging alone does not approve them. The initial gate therefore remains red;
do not merge this checkpoint as a completed quality-policy adoption.

Before adoption, complete the handler classification/narrowing and exact
failure-behavior evidence, remaining installed security/resource cases and
Linux container evidence. The quality fixtures now include disposable Git
repositories and real unittest/aggregate subprocesses for protected-policy,
receipt and false-green mutations; they do not substitute for controlled
required-check acceptance PRs. Obtain maintainer review of the concrete policy.
The bootstrap PR cannot approve itself by editing JSON: a base without policy
reports `bootstrap-review`. Ordinary PR checks execute the protected base's
checker and tool config as their minimum, and separately report candidate
policy changes. CI is unprivileged and `quality-gate` requires both the actual
matrix/unit-test/container results and all five fresh bound quality reports
plus the unittest receipt.

An administrator must separately require `quality-gate` and `unit-tests` on
development/release-target branches, require code-owner approval on the latest
head, dismiss stale approvals and restrict bypass. `@placerda` was confirmed
as a repository administrator before adding CODEOWNERS. No settings were
applied. Workflow YAML, approval strings and a green local command cannot prove
required merge enforcement; bootstrap administration and controlled negative
PR evidence remain separate acceptance activities.

## Recovery and coordinated documentation

This UI PR has no dependency on an unmerged peer runtime change. Restore the
previous UI artifact built from `c635bc6696714b543feec24b4a062a8a8f3ff6d0`
(runtime-equivalent to researched v2.6.2) while retaining the existing shipped
orchestrator/ingestion combination. No data, config key or RBAC migration is
needed. Revert the package/code slice through a PR if rolling source back;
do not disable required checks to bypass a checker defect. Production recovery
has not been rehearsed by this change.

Canonical contributor documentation is coordinated in
[Azure/GPT-RAG#688](https://github.com/Azure/GPT-RAG/pull/688). Existing local
embedding and deployment instructions retain their operator/security claims;
this change does not redesign those behaviors or publish planned controls as
already active.
