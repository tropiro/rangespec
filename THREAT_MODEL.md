# RangeSpec threat model

## Protected decisions

RangeSpec protects the integrity and reviewability of a declared authorization
boundary. The critical outputs are the normalized manifest, its fingerprint,
validation result, and any redacted export.

## Trusted inputs

None. Manifest files, filenames, JSON strings, timestamps, addresses, JSON
Pointers, model responses, and output paths are untrusted until validated.

## Invariants

1. Invalid or ambiguous scope never appears execution-ready.
2. A fingerprint is deterministic for the same JSON value regardless of source
   whitespace or object key order.
3. Redaction never mutates the source document and runs before an advisory
   provider receives data.
4. The core CLI performs no network action against a declared target.
5. An advisory result cannot change approval or validation state.

## Addressed failures

- Duplicate JSON keys are rejected instead of silently choosing one value.
- Input size, nesting depth, and node count are capped before semantic work.
- Schema fields reject undeclared data and malformed identifiers.
- Cross-field validation catches missing target references, incompatible
  protocols, invalid time windows, public targets, and incomplete approval.
- File outputs use same-directory temporary files, flush, `fsync`, atomic
  replacement, directory synchronization, and read-back verification.
- Redaction supports explicit JSON Pointer paths and catches common sensitive key
  names even if a future schema extension permits them.
- Provider imports are lazy, credentials come only from the environment, and
  provider failures are named.

## Out of scope

- Proving the signer or approver has legal authority.
- Enforcing a manifest on a scanner, agent, firewall, or test runner.
- Protecting a machine already controlled by an attacker.
- Cryptographic signing or a public-key trust system in version 0.1.
- Network discovery, exploitation, traffic generation, or device mutation.

Integrators must treat a valid manifest as one input to authorization, not as a
substitute for written agreements, identity verification, and independent
runtime enforcement.
