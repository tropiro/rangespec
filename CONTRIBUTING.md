# Contributing

RangeSpec accepts focused changes that improve manifest clarity, validation,
redaction, deterministic output, or safe interoperability.

Before opening a change:

1. Add or update behavioral tests.
2. Run `./scripts/check.sh`.
3. Update the schema and semantic validator together when changing the format.
4. Document any new stable error code.
5. Keep target execution, scanning, exploitation, and credential collection out
   of this repository.

Use Conventional Commits. Do not commit secrets, customer data, private
vulnerability material, generated virtual environments, or tool caches.
