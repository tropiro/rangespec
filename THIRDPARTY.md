# Third-party dependency ledger

Verified: October 8, 2026

## Runtime

### jsonschema 4.x

- Purpose: Draft 2020-12 structural and format validation.
- Scope used: `Draft202012Validator` and schema self-validation. RangeSpec
  validates its timestamp fields directly so the optional `jsonschema` format
  dependency set is not required.
- Why not local code: reimplementing JSON Schema would create an unreviewed,
  drifting interpretation of the public format.
- Update path: change the bounded version in `pyproject.toml`, run `uv lock`,
  inspect the lock diff, and run `./scripts/check.sh`.

## Optional runtime

### anthropic 1.8.0

- Purpose: optional Claude Messages API structured-output review.
- Scope used: synchronous `Anthropic` client, `messages.create`, and
  `transform_schema`.
- Isolation: imported only when the Anthropic provider is selected. The core
  package and local provider do not require it.
- Credential: `ANTHROPIC_API_KEY` environment variable only.
- Update path: verify the official Python SDK and structured-output migration
  guidance, update the exact pin, inspect the lock diff, run the provider
  contract test and full gate, then perform a separately authorized live smoke
  test.

## Development

- `uv`: environment, lock, sync, and builds.
- `ruff`: formatting and lint.
- `mypy` plus `types-jsonschema`: strict static checking.
- `pytest`: behavior tests.
- `hatchling`: source and wheel build backend.

Exact resolved versions and hashes live in `uv.lock`. Development tools do not
ship in the base wheel.
