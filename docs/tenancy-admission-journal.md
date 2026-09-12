# Namespace admission ownership journal (Sympozium #500)

`celln_cli::tenancy_admission` is a Linux, private-POSIX-storage ownership
boundary. It does not yet expose an HTTP admission endpoint or replace the
independent native publisher/closure/schema/ABI/resource checks. No compatible
installed mediated runtime is advertised by this library.

## Ordering and recovery

- Verify the scoped execution credential against receiver-owned context and
  independently canonicalize/hash the submitted external request **before** any
  duplicate lookup. Model/read/cleanup credentials cannot claim execution.
- Bind a run by cluster, namespace UID and run UID. Neither token JTI, a new
  decision digest nor a changed parent incarnation creates a new run slot.
- Publish and fsync a credential-free ownership record before returning the
  non-cloneable `Fresh` handle. A duplicate only returns `Recovery`, never a new
  launch handle. The caller must find the original live operation or explicitly
  report uncertainty/ContextLost; it must not execute a recovery response.
- Each opened owner instance gets a fresh random identity. Restarting/reopening
  the journal does not restore a lost native parent or model credential context.
- Follow-up turns retain original run/runtime/agent/route/incarnation and aggregate
  limits. Initial work counts toward maxTurns. Only one unfinished operation per
  parent is admitted; completion does not refund a turn.
- Fence the parent slot durably before publishing its new child. An interrupted
  publication leaves a fail-closed uncertainty fence, not retry authority.
- Completion stores only an immutable receipt digest or refusal. An identical
  completion retry is idempotent; a substituted outcome conflicts.

`execution.read` and `execution.cleanup` credentials can address the original
immutable authority after the execution deadline. Their decision may change its
operation/windows, not its executable, route, budget, request or subject binding.
A child cleanup fences only that child; a parent fence refuses further turns.
**A journal fence does not confirm VM teardown.** The owning runtime must cancel
its actual controls, destroy descendants and retain cleanup-pending/ContextLost
when it cannot confirm that work.

## Storage and trust

The configured directory must be private and owned by the daemon UID. It is
pinned by an open directory fd so replacing its pathname cannot redirect writes.
Record and lock opens refuse symlinks/nonregular files and are nonblocking.
Records are bounded, strictly decoded and contain no tokens, tasks, request bodies
or output. Fresh publication uses no-clobber atomic rename plus file/directory
fsync. flock unlock is explicit and owner-PID-bound so a concurrent fork cannot
extend a completed critical section or unlock its parent from a child.

The directory is durable authority, not a disposable cache. Do not delete,
restore older copies or externally rewrite records while credentials/owners can
remain live. There is no automatic tombstone collection or authority reset.
Storage errors and capacity refusal are not permission to choose another owner.

## Evidence limits

Ten library tests cover concurrent duplicate delivery, independent reopened owner
instances, changed ceilings, request/namespace mismatch before duplicate lookup,
missing replay state, turn serialization/limits, expiry-safe read and narrowed
cleanup, inode pinning and private storage. The interrupted-publication test
constructs the exact persisted gap; it is not an OS-crash or native execution
claim. Run `cargo test -p celln-cli --lib tenancy_admission --locked`.

Remaining: authenticated transport/receiver-context construction, native artifact
preparation and dispatch, original-owner result/cancel routing, durable controller
prepared operations, and actual installed native lifecycle/failure testing.
