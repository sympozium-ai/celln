# Host-only model credential context (06a / Sympozium #501)

This library slice stacks on the scoped verifier (Celln #107). It starts #501's
credential-custody work; it does not complete #500 admission or #501 brokering.

`ModelContext::admit` verifies execution and model credentials against the same
immutable decision and receiver-owned expected context. A swapped model token,
wrong audience, or model-free decision cannot construct a model context. The
execution credential is dropped after verification. Only the model credential
is retained in zeroizing owned memory; the context has no Serialize/Deserialize
implementation and Debug is redacted.

The context's child control is bounded by the earlier of the model credential
expiry, fixed work deadline and original parent/run monotonic control. It
cannot extend its parent's lifetime. Close immediately drops the credential;
parent cancellation refuses subsequent access and drops it on observation.
Dropping a context cancels its cooperative control. None of this confirms
native parent teardown or reverses spending.

`with_bearer` is a narrow host-code hook, not guest authority. Trusted Rust code
can still copy a borrowed string; the memory/type boundary is not a sandbox
against compromised host code. The eventual broker must inject the bearer only
at its configured verified-TLS gateway origin and must never serialize it to a
guest, journal, receipt, log or shared file. Provider credentials are not inputs
to this context.

## Tests

Run `cargo test -p celln-cli --lib --locked` and focused library Clippy. Tests use
the shared signed fixtures to reject token swapping, verify redacted Debug,
show cancellation of one context leaves its sibling usable, propagate parent
cancellation, and ensure expired/closed callbacks are not invoked.

## Remaining integration

- #500's complete durable owner/run admission and HTTP authorization surface.
- Dispatcher/native-turn worker wiring to this context with exactly one context
  per admitted operation and no restoration from standing host credentials.
- Configured gateway origin/HTTP client binding and cancellation of actual
  broker requests, without the legacy credential-file fallback.
- Host-generated durable model-call IDs and lost-response handling.
- Recorder concurrency and real KVM guest-attempt isolation tests.

No mediated runtime configuration is enabled by this PR. Do not close #501 or
advertise an installed compatible Celln artifact based on these library tests.
