# Dispatcher durability and interrupted execution

Part of Sympozium epic #426. The router's shared owner ledger and the
dispatcher's journal serve different purposes: the router records **where** an
ID belongs; each dispatcher records that it admitted that ID and its eventual
result/audit. Keep both on persistent operator-controlled storage.

## Behavior

The dispatcher owns its state root exclusively using the existing process
lock. Before starting a worker or returning acceptance it publishes a durable
claim under `ROOT/execution-journal/`. The filename hashes the request ID; the
claim binds the exact submitted request bytes by hash. It contains no bearer
credential or request task/argument payload. Terminal snapshots also contain
the bounded output and audit and therefore may contain sensitive workload data;
files are private mode-0600 temporary files published atomically.

Terminal records are written and synced before serving them as completion.
Their receipt shape is unchanged. Terminal output/audit retrieval and idempotent
cancellation work after memory-cache expiry or dispatcher restart. A completed
ID never starts another execution. Changed request bytes return 409.

| State after restart | Response |
|---|---|
| Durable terminal snapshot | Return original result, receipt/audit; never execute again |
| Admission claim without durable terminal snapshot | 503: interrupted execution requires reconciliation; never replay |
| Corrupt/unreadable journal | 503; never treat it as a missing execution |
| No journal record | 404 on lookup; a new POST still requires normal admission |

An interrupted claim is **not** evidence that a cell or provider transaction
finished or was cleaned up. Cancellation of that claim does not fabricate a
cancelled receipt or let a controller falsely finalize teardown. A crash
between claim persistence and worker start can consequently leave work that
never ran requiring reconciliation. Automatic in-flight crash recovery and
operator acknowledgement/fencing are not implemented by this increment.

## Bounds and failure handling

- At most 100,000 admission/terminal records per root. New admission refuses
  when full; existing records remain readable. No automatic tombstone deletion.
- At most 16 MiB per serialized journal record. A terminal snapshot exceeding
  this bound or failing storage I/O is not advertised as durably completed;
  reads/cancellation return 503 until persistence succeeds. The memory entry
  is retained past the one-hour cache TTL while persistence is unproven.
- Output storage failure, interruption and successful execution are distinct
  facts. Journal failure never authorizes replay of possible side effects.
- Publication uses private files, file fsync, atomic no-clobber creation for
  claims, atomic replacement for terminal snapshots, and directory fsync.
  Existing identical snapshots still require directory sync before a durable
  acknowledgement. Directory-fsync failure is unsupported, not success.
- Terminal snapshots are immutable. Cleanup/compaction requires an explicit
  request-ID retirement protocol and coordinated router retention; not simple
  age-based deletion. Storage capacity planning remains operator work.

The journal is process-local to the owning dispatcher state root. It does not
turn multiple independent dispatchers behind a load balancer into one owner,
certify a distributed filesystem, or promise exactly-once provider effects.

## Upgrade limits

The old dispatcher kept records/audits only in memory and expired them after
an hour. This version cannot recover those records retroactively. Quiesce old
submissions and export/reconcile outstanding results before upgrading; preserve
the router ledger and do not replay its old IDs to recreate missing results.
Do not roll back to a dispatcher that ignores the journal while IDs can still
be retried. An old execution with no new journal record is not protected by a
new claim invented after the fact.

## Verification scope

Tests exercise durable claim/terminal publication, immutability, capacity,
corruption refusal, unavailable-persistence refusal and cache retention. Real
TCP HTTP handler tests use an empty registry to check authenticated poll,
audit, cancellation and POST retry: terminal state survives, interrupted claims
refuse, changed bytes conflict, and no worker is registered. These do not by
themselves prove deployed KVM node-loss recovery. The deployed image still needs
updating and testing with fresh executions before that gate is claimed.
