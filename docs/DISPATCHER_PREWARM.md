# Serving-process artifact verification and prewarming

`POST /v1/artifacts/prewarm` uses the dispatcher's bearer authentication and
accepts a bounded (64 KiB) existing declared `ExecutionRequest`. It must name
an operator-admitted mote and signed closure, with empty invocation arguments,
no Harness/forge payload, no inputs, no workspace and no egress. This endpoint
does not execute the selected Harness or borrowed tools.

The serving process runs the existing challenge-bound sealed guest member
verification and observes its own warm cache afterward. Policy is checked by
that verifier before and after guest verification. A successful response uses
`celln.dev/artifact-prewarm-v1`, includes the exact HTTP request-byte hash,
node identity, an opaque process-incarnation identifier, and the sealed-member
verification report. It says `warmState: present-at-observation` only if the
selected mote/memory configuration is observable in that process's cache.

Preparation reserves one cell and the declared guest RAM under the same
admission lock as executions. Other requests see that reservation in node
capacity; only one prewarm operation is admitted at a time. The reservation
is released on success, refusal or unwinding. The existing retained warm-mote
RAM is separate from active reservations; this is not a whole-process RSS cap.
A control deadline bounds preparation to at most 30 seconds, and the member
check's guest run has its existing maximum 10-second timeout.

This is an **observation, not a lease or an execution authorization**. Cache
eviction, process restart and policy withdrawal can invalidate it immediately.
It is deliberately not persisted or returned as global positive readiness.
Responses retain `artifactReadiness: not_checked`, `conformance: not_checked`
and `executionAuthorized: false`. Runtime/tool functional conformance, model
grants, controller selection resolution, distribution and fresh execution-time
authorization are still required. A CLI verifier running in another process
cannot supply this serving-process observation.

Malformed requests return 400; oversized requests 413; unsupported authority,
missing hardware/artifacts or failed sealed-member verification 422; capacity
shortfall, concurrent preparation or an unobservable/evicted template 503.
The endpoint is not routed through the execution journal and does not create
an execution ID or retry tombstone: it has no lent-tool side effects to replay.

Portable HTTP tests cover authentication, body bounds, executable-argument
refusal, capacity visibility, concurrent-preparation refusal and reservation
release. The explicit `signed_closure_on_real_kvm` hardware test also calls the
authenticated TCP handler twice against a freshly emptied serving-process
cache, checks exactly one preparation and distinct verification challenges,
then revokes a signed input source and checks refusal and released capacity.
The [recorded run](evidence/dispatcher-prewarm-2026-09-07.json) passed on
2026-09-07 alongside the dynamic-closure guest attack/revocation suite, portable
`make ci`, and all-target/all-feature Clippy. No model calls were made.

This proves the dispatcher handler and real guest verification, not deployed
router/controller integration or the complete selection-specific readiness
path. The hardware proof can be reproduced with a built `celln` binary and
static pilot binaries:

```sh
CELLN_TEST_BINARY=/absolute/path/to/celln \
CELLN_PILOT_DIR=/absolute/path/to/static/pilot/binaries \
cargo test -p celln-cli signed_closure_on_real_kvm -- --ignored --nocapture
```

Check for the explicit `PASS real-KVM prewarm endpoint` line; a hardware/toolchain
skip is not evidence of verification. Each run writes observations beneath
`target/prewarm-proof-<pid>/evidence.json`.
