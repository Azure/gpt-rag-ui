# Python quality

- Python 3.12 and repository tests are the executable baseline. Do not
  introduce a formatter, linter, type checker, or framework when the project
  has not adopted it for the affected work.
- Prefer explicit, readable control flow, intent-revealing names, focused
  functions, and typed boundary contracts.
- Keep asynchronous paths non-blocking. Await network and persistence work,
  preserve cancellation, and bound timeouts and retries.
- Remove duplicated knowledge, not merely similar syntax. Avoid speculative
  flags, parameters, adapters, or abstractions.
- Validate inputs near trust boundaries and keep invariants close to the state
  they protect.
- Fail with useful context at the layer that can decide. Do not catch broad
  exceptions to return apparent success, and preserve original causes when
  translating errors.
- Error messages and telemetry must not disclose secrets, tokens, personal
  data, private endpoints, or exploitable detail.
- Use docstrings for public behavior and non-obvious contracts. Comments
  explain a reason, risk, or constraint rather than narrating code.

Read tests and call sites before changing an interface. Make the smallest
complete change and keep unrelated refactoring separate.
