# RangeSpec

RangeSpec is an offline-first manifest format and command-line tool for declaring
what an authorized security range may do before a test begins.

It records targets, permitted actions, time limits, rate limits, safe state,
stop conditions, recovery evidence, approvals, and evidence-handling rules in a
versioned JSON document. The CLI validates those declarations, produces stable
fingerprints, redacts sensitive fields, and compares revisions.

RangeSpec is an early Tropiro open-source project. It does not authorize work by
itself, execute tests, scan networks, exploit targets, or replace contracts and
human approval.

## GitHub Action

A repository can make RangeSpec validation a required check before a lab or
security-testing workflow runs:

```yaml
- name: Validate declared scope
  id: rangespec
  uses: tropiro/rangespec@v0.2.1
  with:
    manifest: range/authorized-test.json
    execution-ready: "true"
```

The action returns the canonical manifest fingerprint as
`steps.rangespec.outputs.fingerprint`. The manifest path must stay inside the
checked-out repository. Validation is local and deterministic: the action does
not execute tests against a target, contact Claude, or read an API key.

For time-window checks that must be reproducible, pass an explicit timestamp:

```yaml
with:
  manifest: range/authorized-test.json
  execution-ready: "true"
  at: "2026-10-08T20:00:00Z"
```

See the [complete example workflow](examples/workflows/rangespec.yml).

## Demonstrated workflow

From this directory:

```bash
uv sync --all-extras --dev
uv run rangespec validate examples/gateway-valid.json \
  --execution-ready \
  --at 2026-10-08T20:00:00Z
uv run rangespec fingerprint examples/gateway-valid.json
uv run rangespec review examples/gateway-valid.json --provider local
./scripts/check.sh
```

The valid example describes only documentation-range addresses and a simulated
gateway. The `--at` value makes the demonstration reproducible rather than
depending on the current clock.

## Commands

- `validate`: run schema and semantic checks; optionally require an
  execution-ready approved manifest.
- `normalize`: write stable, human-readable JSON through an atomic verified
  replacement.
- `fingerprint`: calculate a SHA-256 digest over canonical JSON.
- `redact`: create a wrapped export with declared JSON Pointer paths and
  sensitive key names replaced.
- `diff`: compare two manifests after redaction.
- `review`: run an advisory completeness review. The default provider is local
  and deterministic.
- `schema`: print the authoritative bundled JSON Schema.

Every failure is returned with a stable code and JSON Pointer path. CLI exit
codes are documented by `rangespec --help`.

## Optional Claude review

The optional Anthropic provider sends only the redacted manifest and requests a
structured completeness review. It cannot change the manifest or authorize a
test.

```bash
export ANTHROPIC_API_KEY="..."
export ANTHROPIC_MODEL="claude-sonnet-5-5"
uv run --extra anthropic rangespec review examples/gateway-valid.json \
  --provider anthropic
```

No model is selected silently: pass `--model` or set `ANTHROPIC_MODEL`. Never put
an API key in a manifest, command argument, repository file, or captured output.

## Safety boundary

RangeSpec intentionally has no network-execution feature. A later runner may
consume a validated manifest, but it must independently enforce the same target
and action allowlists. Ownership of a manifest is not proof of authorization.

Read [THREAT_MODEL.md](THREAT_MODEL.md) before building an integration.

## Development

`./scripts/check.sh` installs the locked development environment and runs lock
verification, formatting checks, lint, strict type checking, tests, a package
build, and the deterministic example workflow.

The gate also exercises the GitHub Action entrypoint with the documented
execution-ready example and verifies that its output fingerprint is stable.

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).
