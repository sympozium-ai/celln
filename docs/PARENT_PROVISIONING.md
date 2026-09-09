# Local persistent-parent provisioning

`celln --root /absolute/operator/state parent-provision /absolute/plan.json
--principal authenticated-operator-principal` publishes a run-specific permit
and launch profile. It does **not** launch a VM, warm a mote, read a model key,
grant catalogue tools or approve a Kubernetes run. This command is an
operator-local authority boundary; do not expose it as a tenant upload API.

The caller must independently authorize the complete run intent and resolved
Agent/runtime/tool/grant snapshot before preparing the plan. Its `intentSHA256`
must identify that complete authorized intent, not just a task or runtime name.
The CLI validates its format, not the upstream Kubernetes authorization.

## Plan contract

Input is strict JSON, at most 64 KiB, with these fields:

| Field | Meaning |
| --- | --- |
| `apiVersion` | `celln.parent-provision-plan/v1` |
| `scope` | Stable operator-controlled cluster/issuer identity |
| `runUid` | Immutable run UID; never a reusable object name |
| `intentSHA256` | `sha256:` plus 64 lowercase hexadecimal digits |
| `admissionWindowMs` | 1–300000; time to admit, not the parent lease |
| `parent`, `worker` | Complete independently selected `ExecutionRequest` objects |
| `template` | Native JSON-harness configuration, including persona and required-tool policy |
| `modelProfile` | Hash of an independently published host model profile |
| `reservedMemoryBytes` | Logical host reservation including retained motes, both cells and overhead; not measured RSS |
| `maxTurns` | Parent's total turn ceiling |
| `turnModelRequests`, `turnOutputTokens` | Per-child model ceilings |
| `totalModelRequests`, `totalOutputTokens` | Aggregate parent model ceilings |

Both requests' callers must equal `--principal`. Parent/child memory and time
limits come from their respective requests. Configuration fingerprints and the
worker's template/model binding are calculated locally, not accepted as caller
assertions. Startup still performs artifact admission, replay prevention,
capacity reservation and warm preparation before execution.

The operator must provision and protect these directories under the root:
`parent-issuance`, `trusted-parent-permits`, `trusted-parent-launches`, and the
existing `trusted-parent-models` policy store. All issuers for one scope must
share and retain the issuance directory across process restarts. The command
does not create authority directories or replace conflicting records.

## Recovery and output

The incarnation depends only on scope and immutable run UID. The issuance
record pins a domain-separated BLAKE3 hash of the entire typed plan, including
the upstream SHA256 intent identity. This avoids requiring Go and Rust to
produce identical JSON bytes. Plan formatting and field order do not matter;
changed semantic values, including the logical memory reservation, do.

Success prints one JSON object with `apiVersion: celln.parent-provisioned/v1`,
`launchProfile` and `incarnation` hashes. Repeating an identical plan recovers
the original unexpired permit and exact launch hash. Expiry, a new host boot,
changed intent or a corrupt record refuse; retry never renews authority.
Failures after issuance retain its record. Never delete the journal, change
scope or invent a replacement UID to make a failed run retry.

The command is a local provisioning primitive. Automatic Sympozium plan
construction, trusted host invocation and per-run registration remain separate
integration work. It does not establish production TLS/RBAC or a running demo.

## Optional private worker audit

By default, production does not retain raw native worker output at the turn
boundary. An operator may explicitly create a real `parent-audit` directory
under the state root, with no group/other permissions (normally mode 0700).
Symlinks and non-private directories are refused. The path is fixed by the host,
not accepted from an AgentRun, turn or HTTP request.

When enabled, each completed worker produces a bounded, synced, non-replacing
mode-0600 `worker-proof-<child-hash>.json` file containing actual guest events,
execution identity and host broker counts. These files can contain sensitive
conversation/tool data. They are evidence only, never authorization to replay.
The operator owns retention, storage sizing and deletion policy; there is no
automatic expiry. Do not publish the directory or mount it into guest workloads.
An audit failure refuses result commitment after the child is destroyed; it
does not refund the turn or make it retryable. Disable retention by removing the
opt-in directory only when stopped, after handling any retained files explicitly.
# Owner-process loss and cleanup

New native parent claims persist the host process identity before launching a
VM: Linux boot ID, PID namespace, UID, PID and process start ticks. After an
owner-process restart, the authenticated stop route can confirm teardown only
when that original process has exited in the same boot/namespace/user context.
The native parent and its child KVM file descriptors are owned inside that
process. A missing registry entry is not evidence of teardown; procfs errors,
identity mismatches and legacy journals without the record fail closed.

This acknowledges resource cleanup, **not context recovery**. Historical reads
still report `ContextLost`, no turn is replayed, and the incarnation tombstone
remains occupied. The stop response retains its existing wire format. This
proof must not be reused for a backend which delegates VMM ownership to another
process. Cross-reboot/migrated journals require separate operator reconciliation;
never backfill process identities or delete journals to make cleanup succeed.
