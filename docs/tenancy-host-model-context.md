# Host-only model credential context (06a / Sympozium #501)

This library slice stacks on the scoped verifier (Celln #107). It starts #501's
credential-custody work; it does not complete #500 admission or #501 brokering.

`ModelContext::admit` verifies execution and model credentials against the same
immutable decision and receiver-owned expected context. A swapped model token,
wrong audience, or model-free decision cannot construct a model context. The
execution credential is dropped after verification. Only the model credential
is retained in zeroizing owned memory; the context has no Serialize/Deserialize
implementation and Debug is redacted. Canonical verified decision bytes remain
attached to that same context; the relay cannot substitute a separate decision.

The context's child control is bounded by the earlier of the model credential
expiry, fixed work deadline and original parent/run monotonic control. It
cannot extend its parent's lifetime. Close immediately drops the credential;
parent cancellation refuses subsequent access and drops it on observation.
Dropping a context cancels its cooperative control. None of this confirms
native parent teardown or reverses spending.

`with_bearer` is a narrow host-code hook, not guest authority. Trusted Rust code
can still copy a borrowed string; the memory/type boundary is not a sandbox
against compromised host code. The gateway relay injects the bearer only
at its operator-configured verified-TLS gateway origin and must never serialize it to a
guest, journal, receipt, log or shared file. Provider credentials are not inputs
to this context.

## Canonical model request bytes

`canonical_model_request` returns the v1 body bytes and typed SHA-256 digest for
later gateway reservation. The independently implemented encoder agrees with Go
on eleven shared golden vectors in `tests/fixtures/celln-model-requests/v1.json`,
including HTML/U+2028, UTF-16 key ordering, duplicates, malformed Unicode and
invalid numeric forms. Bounds are 262144 bytes and 64 object/array levels. The
profile is integer-only: fractional sampling parameters, exponents and negative
zero refuse rather than being silently converted. No network or reservation is
performed by this function; the broker still needs to call it at actual dispatch.

## Tests

Run `cargo test -p celln-cli --lib --locked` and focused library Clippy. Tests use
the shared signed fixtures to reject token swapping, verify redacted Debug,
show cancellation of one context leaves its sibling usable, propagate parent
cancellation, and ensure expired/closed callbacks are not invoked.

## Host transport implementation

On Linux, `GatewayRelay` implements warden's `ModelRelay`. The separate
`HttpBroker::new_mediated` constructor rejects standing provider credential files,
insecure policy and multiple model routes. The guest still uses the narrow
validated Chat Completions envelope; only the validated provider body reaches
the relay, never guest-selected transport headers or destinations. Legacy broker
construction is unchanged; the mediated branch cannot fall back to it.

The relay uses verified TLS, no redirects, no retries and no ambient proxy or
curl configuration. Its credential-bearing curl configuration travels only over
an anonymous stdin pipe; not argv, environment, temporary files or shared files.
`celln-control` drains bounded input/output while polling cancellation and kills
and reaps the owned process group. Error diagnostics are withheld. Response
bounds, strict duplicate-key checks and decoded-string bearer-echo rejection
apply before returning data. Gateway 429 remains a budget refusal. Host ceilings
are additionally non-refundable; PostgreSQL remains the authoritative ledger.

Per-context request IDs combine the canonical verified decision identity and a
monotonic sequence advanced before transport. There is no context restore API:
production recovery must locate the original owner/context or report ContextLost,
not replay a token into a replacement context and reset the sequence.

The `tenancy-gateway-probe` example is an integration-test driver, NOT an admission
API. A trusted Go fixture supplies its expected receiver context over stdin. It
has exercised the actual Rust broker/relay through TLS to the separate Go gateway
process, live Kubernetes authority and PostgreSQL for both tenants, including
durable budget refusal. This is host transport evidence, not a controller-created
native parent, a VM journey, or tenant RBAC isolation proof.

## Native attachment boundary

The native worker execution helper now moves an owned `HttpBroker` into the VM
rather than rebuilding it from `HttpPolicy`. This preserves a scoped relay and
its counters through VM execution and drops its context with the owned VM.
Repeated owned-broker attachment refuses. Existing legacy worker callers still
construct their legacy broker explicitly; this is not yet mediated admission.

## Remaining integration

- #500's complete durable owner/run admission and HTTP authorization surface.
- Dispatcher/native-turn worker wiring to this context with exactly one context
  per admitted operation and no restoration from standing host credentials.
- Installed operator-owned gateway endpoint/CA distribution and attaching this
  relay to independently admitted native workers.
- Durable owner/request correlation and explicit lost-response lifecycle states;
  per-context sequence generation alone is not restart recovery.
- Recorder concurrency and real KVM guest-attempt isolation tests.

No mediated runtime configuration is enabled by this PR. Do not close #501 or
advertise an installed compatible Celln artifact based on these library tests.
