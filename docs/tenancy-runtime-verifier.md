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

The verifier is a library, and the dispatcher now consumes it: `celln dispatcher`
serves `POST /v1/scoped/{prepare,start,read,cleanup}`
(`crates/celln-cli/src/dispatch_scoped.rs`). The router does not proxy these
routes. Every request carries the scoped operator bearer in `Authorization`
(a separate credential from `--token-file`, which these routes refuse);
`start`/`read`/`cleanup` carry the signed capability in
`X-Celln-Execution-Permit`, and a `start` on a model route additionally carries
`X-Celln-Model-Permit`. Permits are verified against the prepared decision and
are never written to the state root.

The receiver is off (`404 {"error":"scoped receiver disabled"}`) unless it is
configured, and dispatcher start-up fails on a partial configuration:

| Flag | Rule |
|---|---|
| `--scoped-operator-token-file`, `--scoped-jwks-file`, `--scoped-issuer` | All three or none. Token and JWKS are re-read per request; an unreadable one answers 503. |
| `--scoped-gateway-origin` | Needs the three above. A bare `https://host[:port]` origin. Required for any model route; without it a model-route start is refused `AUTH_CONTEXT_LOST`. |
| `--scoped-gateway-ca` | Needs `--scoped-gateway-origin`. Public CA bundle only. |
| `--scoped-parent-request-file` | Needs `--scoped-gateway-origin`. Required for enduring runs. |

Model calls are mediated: the guest sees only a logical alias, the host relay
sends only to the configured gateway with the model permit as bearer, and no
provider credential file exists on the node. Enduring runs
(`enduring-initial`, then `enduring-turn` per follow-up) additionally require a
model route (`provider: "none"` is refused `AUTH_PROTOCOL_UNSUPPORTED`), a
mediated broker, the operator parent template, and free capacity for the parent
plus one child and one broker slot. A follow-up turn is served only by the owner
epoch that admitted the parent; after a restart, a refused or stopped parent, or
lost in-memory custody it answers `AUTH_CONTEXT_LOST` and never recreates one.

Receivers
must derive expected namespace/run/parent/operation identity from trusted routing
and durable ownership state. Populating Context solely from caller-supplied
claims would authenticate a signature without enforcing tenant ownership.

`seen_admission_jti` only retains the shared fixture recovery observation; a
receiver must independently recover the durable operation. A JTI must never be
used as execution identity, request identity or a fresh budget.

No host publisher, sealed-closure, schema, ABI or resource check is removed.
The verifier slice itself enabled no mediated mode or parent creation; those
arrived with the receiver above. No installed (cluster) acceptance is claimed.

## Receiver evidence

`dispatch_scoped_http_tests.rs` drives the real socket handler without a guest:
disabled/partial configuration, bearer separation, audience/forgery/expiry/
admission-window refusals, the durable prepare/start/read/cleanup record and
replay recovery, the mediated broker against a TLS gateway fixture, enduring
refusals, and `AUTH_CONTEXT_LOST` after owner loss. They need the `openssl` CLI
and `/usr/bin/curl`. `scoped_mediated_lifecycles_on_real_kvm` (in
`make conformance-kvm`) boots a model-route one-shot and an enduring parent with
a follow-up turn through the same routes, with every model call answered by that
gateway fixture. A model-free (`provider: "none"`) scoped one-shot has no KVM
case yet.

## Verification

Run `cargo test -p celln-cli --lib --locked`, workspace build/tests, and focused
`cargo clippy -p celln-cli --lib --no-deps -- -D warnings`.
The repository-wide Rust 1.95 baseline Clippy failure remains separately tracked
in Celln #105. Rust 1.75 compatibility is not established by a Rust 1.95 test run;
new time/url/uuid/iso8601 resolutions are locked to older compatible releases
rather than incidentally adopting newer high-MSRV transitive releases.
