# Runtime scoped-credential verifier (05c)

This slice promotes the independent Rust conformance consumer into the
`celln_cli::tenancy_credentials` library. The library builds outside `cfg(test)`;
fixture private/public test keys and fixture observations remain test-only.

- `Verifier::from_jwks` requires an explicit issuer and local public Ed25519 JWKS.
- Unknown/private/remote-key fields, duplicate key IDs and malformed/empty keysets
  refuse. No URL or filesystem key resolver is provided.
- `reload_jwks` validates before atomically replacing the public keyset. Invalid
  reload retains the previous keys. Normal rotation must retain overlap through
  outstanding credential lifetime plus skew. Emergency removal affects future
  verification, not already admitted cells.
- `verify` accepts a caller-held bearer and **receiver-owned** `Context`. Errors
  are static reason strings, never signed payloads or bearer contents.
- The pinned JSON Schema 2020-12 decision and credential schemas are compiled
  locally using jsonschema, with HTTP/file resolution features disabled. Full
  required/type/additional-property/broker-limit checks supplement semantic
  audience/operation/identity/deadline validation and strict Ed25519 verification.
- Integer-only canonicalisation remains bounded, duplicate-key rejecting and
  UTF-16 ordered. Widened time arithmetic avoids integer overflow.

The published bundle was corrected upstream in Sympozium `8b69b03`: accepted
model-free/cleanup decisions now contain `tools: []`, not schema-invalid null.
All shared verifier dispositions continue to pass after this correction.

## Receiver integration requirements

This is a runtime **library**, not yet router/dispatcher enforcement. Receivers
must derive expected namespace/run/parent/operation identity from trusted routing
and durable ownership state. Populating Context solely from caller-supplied
claims would authenticate a signature without enforcing tenant ownership.

`seen_admission_jti` only retains the shared fixture recovery observation; a
receiver must independently recover the durable operation. A JTI must never be
used as execution identity, request identity or a fresh budget.

No host publisher, sealed-closure, schema, ABI or resource check is removed.
Nothing in this PR enables mediated mode, dynamic parent creation or #501 host
broker credentials. No compatible installed artifact/KVM proof is claimed.

## Verification

Run `cargo test -p celln-cli --lib --locked`, workspace build/tests, and focused
`cargo clippy -p celln-cli --lib --no-deps -- -D warnings`.
The repository-wide Rust 1.95 baseline Clippy failure remains separately tracked
in Celln #105. Rust 1.75 compatibility is not established by a Rust 1.95 test run;
new time/url/uuid/iso8601 resolutions are locked to older compatible releases
rather than incidentally adopting newer high-MSRV transitive releases.
