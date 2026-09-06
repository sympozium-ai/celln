# Dispatcher cancellation and deadlines

`POST /v1/executions/{id}/cancel` uses the same bearer authentication as submit
and status. Unknown IDs return 404. Active executions return 202 and remain in
`Cancelling` while cleanup runs. Repeating the request is safe. A terminal
execution returns 200 with its existing terminal result; cancellation never
rewrites completed work.

The registry retains capacity while cancellation is pending. Only the worker,
after unwinding its VM and owned subprocesses, publishes `Cancelled` and
releases the reservation. Terminal receipts are marked Cancelled when a cell
was created; cancellation before a cell exists has a status record but no
invented cell ID or receipt. Active records are not evicted by the history TTL.

## One deadline

After parsing and validating a submission, `timeoutMs` creates one monotonic
deadline. The same control object spans worker scheduling, provider discovery
and model invocation, both reproducibility builds, image preparation, cache
waiting, cold mote preparation, guest execution, DNS/HTTPS requests and final
result publication. Starting a new phase does not renew the budget. The
terminal registry update checks the control under the same lock as cancel.
Deadline expiry is Failed with `execution deadline exceeded`; cancellation is
Cancelled. The first observed stop cause is sticky.

Cancellation is cooperative and OS-mediated, not a hard real-time guarantee.
Process and cache loops poll at 10 ms; KVM's watchdog polls at 20 ms and wakes
blocked KVM_RUN. Synchronous local filesystem/kernel operations must return
before their owner can unwind. Reservations stay held during that cleanup,
rather than claiming resources have been released prematurely.

## Subprocess ownership

The shared `celln-control` crate scopes control to one worker thread and restores
the previous context on exit or unwind. Helpers inherit that context, not a new
timer. Provider, compiler/linker, image-build and fetch commands run in owned
Linux process groups. Nonblocking bounded pipe reads avoid leaked reader threads
or a background child holding output pipes open indefinitely. Cleanup signals
the group before reaping the leader, retaining its PID until the signal is sent;
the leader is also killed directly if it changed groups. Capture is capped at
8 MiB per stream. This is process supervision for trusted host tools, not a
sandbox against a malicious host tool deliberately escaping into another group.

Controlled DNS uses `getent ahostsv4` under the same deadline before curl receives
the pinned public address. Install `getent` with the node runtime; its absence
refuses fetches, with no unbounded resolver-thread fallback. Temporary response
headers are unique per fetch and removed on success, failure or cancellation.

## Evidence

- `make ci`: sticky stop reasons, scope restoration, process-group cleanup,
  pipe-holding background processes, authenticated/idempotent cancel, terminal
  success races, TTL retention and cancellation while waiting for preparation.
- `cargo test -p celln-cli on_real_kvm -- --ignored --nocapture`: actual guest
  output before cancellation/deadline, cold-preparation expiry and no live cell
  after teardown, alongside the existing outcome and substrate proofs.

This completes the first lifecycle implementation, not the epic. Aggregate
resource accounting, granted/executed provenance, input/closure delivery and
external Sympozium conformance still need their own implementation and proofs.
