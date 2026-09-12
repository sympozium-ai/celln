# Scoped credential conformance consumer (05b)

Stacks on the encoding consumer (Celln #105) for Sympozium issue #500.
The unchanged shared bundle remains pinned by the encoding consumer test.

`cargo test -p celln-cli tenancy_ --locked` now consumes all **24** shared
`evaluator: verify` vectors with exact accept/refuse/recover dispositions.
It independently verifies compact Ed25519 JWS signatures with ed25519-dalek,
using locally supplied public keys only, and checks endpoint audience/operation,
canonical decision digest, original run/namespace/parent/route/budget bindings,
admission versus model-work deadlines and owner cleanup lifetime.

Additional negatives reject duplicate/remote-key headers, unsupported algorithms,
malformed/oversized compact credentials, removed public keys and model-to-cleanup
audience substitution. Error results contain static reason codes, not bearer
material. Time arithmetic uses widened integers to avoid overflow.

The five resolver vectors are intentionally not evaluated by a receiving
credential verifier: live Kubernetes policy evaluation belongs to the resolver.
Stateful accounting sequences likewise belong to the durable ledger consumer.

## Not an admission implementation

The initial 05b implementation was test-only. The subsequent 05c library adds
runtime schema validation and atomic public-key loading/reload; see
`tenancy-runtime-verifier.md`. It is still not wired into router/dispatcher
admission. Receiver-owned durable context, full HTTP surface enforcement and
dynamic parent ownership/admission remain required before spawning cells. Runtime wiring must
preserve independent host publisher/closure/ABI checks.

The fixture's `seenAdmissionJti` is only a replay *disposition* observation.
Runtime idempotency must use the durable operation identity and never a JTI as
an execution or budget ID. Passing these tests does not implement recovery.

Host-only broker credential delivery (#501 / 06/15), installed artifact pinning
and KVM acceptance remain later dependent slices. No fixture key is added to
runtime configuration.
