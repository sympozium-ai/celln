# Router ownership and ambiguous submissions (M0)

Tracks [Sympozium epic #426](https://github.com/sympozium-ai/sympozium/issues/426).
This increment builds on inbound authentication/cancellation in Celln PR #70.
It is not the full deployed-path acceptance gate.

## Contract

`celln route` now requires `--ownership-dir`. All replicas must mount the same
durable operator-controlled POSIX filesystem, with coherent `flock`, atomic
publication and directory/file `fsync` across those replicas. Per-pod emptyDir
or independent per-node hostPath directories do **not** meet this requirement.
This storage contract must be verified on the selected deployment backend;
local tests do not certify a Kubernetes storage driver or multi-host filesystem.

The router uses an exclusive nonblocking filesystem lock while creating a new
owner record. It writes and syncs the selected backend and request-body hash,
publishes the record atomically, and syncs its directory **before** forwarding
the first POST. Concurrent lock contention returns 503 rather than waiting
indefinitely. IDs are bounded to 512 safe ASCII path-component bytes; filenames
are content hashes, not request-provided paths. Records contain neither bearer
tokens nor task bodies. Only operators may write the ledger.

| Event | Behavior |
|---|---|
| First request ID | Choose a healthy backend, durably claim, send POST once |
| Same ID and exact request bytes | Poll the recorded backend; never send another execution POST |
| Same ID, changed bytes | 409 before contacting any backend |
| Lost acceptance response | 503; owner retained; retry recovers by polling |
| Fresh router replica/restart | Read owner from shared ledger for retry, poll, audit and cancellation |
| Owner unavailable or dispatcher lost its record | 503; no reroute/replay |
| Owner removed from configured backends | 503; do not forward credentials to the removed endpoint |
| Corrupt/unreadable ledger or unsupported locking/sync | Refuse, never manufacture a fresh owner |

Health-based fallback is allowed only **before** ownership exists. Backend
order or routing-mode changes do not move an existing execution. All replicas
must retain the same authorized backend set while old executions need access.
Backend URLs must identify stable dispatcher endpoints; changing DNS/IP reuse,
TLS/proxy identity and deployment topology remain operator/deployment concerns.

The dispatcher remains responsible for actual cell admission, immutable
artifact checks, execution, cancellation, and receipts. Retrying a cancellation
request is allowed; replaying an execution POST is not. This avoids duplicate
model/tool side effects at the cost of conservative refusal when a crash occurs
between durable claim and dispatch. It does not claim exactly-once external
effects or automatic recovery of an ambiguous provider transaction.

## Retention and operations

The ledger has a hard limit of 100,000 owner/tombstone records. Existing IDs
remain routable at capacity; new IDs receive 503. It is not an unbounded memory
map. No automatic expiry deletes replay protection. **Do not purge the ledger
as routine cleanup or during an upgrade.** Preserve/back up the mounted state
with the dispatcher state and keep replicas on compatible schemas.

Administrative reclamation needs a confirmed request-ID retirement boundary:
no client may retry retired IDs, and external effects must be reconciled first.
That lifecycle/GC protocol is not implemented here. Capacity exhaustion requires
operator reconciliation; blindly deleting old records permits duplicate work.
Storage-driver qualification, a chart/PVC topology, verifiable rollout/rollback,
terminal retention and distributed node-loss tests remain M0 work. This CLI
change requires coordinated chart arguments/volumes before deployment.

## Evidence (2026-09-07)

Actual TCP protocol tests deliberately accept an execution at a backend and
drop its response. A fresh router state using the same disk ledger and reordered
backends retries by GET, polls, fetches audit and forwards cancellation. The
backend's expected transcript permits exactly one execution POST. After that
backend stops, the router refuses rather than submitting to the spare. Changed
request bytes return 409.

Additional tests cover reload across fresh ledger instances, bounded capacity,
nonblocking lock contention and corrupt records. Existing inbound missing/wrong/
rotated credential, cancellation and parser-bound tests remain green.
Run `cargo test -p celln-cli router::` and `make ci`.

These are local TCP/filesystem correctness tests, not a KVM, shared-volume,
multi-node failover or deployed Sympozium proof. Keep the epic open until the
actual controller → Service/router → dispatcher → KVM release gates pass.
