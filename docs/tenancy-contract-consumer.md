# Namespace tenancy: shared encoding consumer

This is the first bounded prerequisite slice for
[sympozium#500](https://github.com/sympozium-ai/sympozium/issues/500) (05/15),
which precedes host credential brokering in
[sympozium#501](https://github.com/sympozium-ai/sympozium/issues/501) (06/15).
It does not close either issue or enable mediated admission.

## Shared input

The unmodified fixture bundle is vendored from Sympozium's #496/#499 stack at
Sympozium source commit `8b69b03` (accepted tool-free decisions corrected to
use the schema-required empty array rather than null). External bundle pin:

`sha256:e5a26a8a31d388072067c9d239ff2908fb962effd08b234f152dc5a0ad3dad34`

Tests check the external pin, normative file checksums, eight decision digests,
exact canonical bytes and their external-request digests. No new protocol or
independently edited expectations are introduced. Included signing files contain
publicly known test-only keys, never production trust defaults.

The independent Rust integer-only encoder rejects duplicate keys (including
escaped aliases), unsafe integers, fractional/exponent numbers, negative zero,
invalid UTF-8, lone surrogate escapes, trailing data, oversized documents and
excessive nesting. Object ordering uses UTF-16 code units, not UTF-8 byte order.

Run `cargo test -p celln-cli tenancy_contract --locked`.

## Explicitly not delivered here

- JWS verification and all semantic positive/negative refusal vectors.
- Router/dispatcher admission wiring and transport-credential separation.
- Dynamic parent instantiation and durable tenant ownership/cleanup.
- Host broker token custody, gateway protocol and cancellation integration.
- Reproducible compatible runtime artifact or installed/KVM isolation proof.

The consumer is test-only; passing it does not authenticate a request or spawn a
cell. The existing host checks and legacy runtime path are unchanged. Subsequent
PRs should stack on this slice rather than call the current runtime tenancy-ready.
