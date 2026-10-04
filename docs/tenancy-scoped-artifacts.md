# Scoped enduring brokered artifacts v1

Review contract for the paired Sympozium integration (epic #495 / contract #496).
This is an additive implementation of the **existing signed** v1 `limits.artifacts`
fields, not a new credential audience or a filesystem grant. No changes to the
frozen authorisation-decision schema or credential canonicalisation are needed.
The additive cross-repository vectors are `tests/fixtures/scoped-artifacts/v1.json`.
They must be copied unchanged and consumed by the paired Go tests before merge.
This document proposes the shared contract for review; it does not claim external
review or installed acceptance has already happened.

## Exact negotiation and wire fields

`GET /v1/capabilities` adds `scopedArtifactContracts: ["celln.scoped-artifacts/v1"]`.
Missing field or missing value means **Unsupported**, never a legacy fallback.
The capability remains preflight-only: scoped receiver/gateway/parent-template
configuration, KVM, publishers, signed closure, tool schemas, resource admission,
and fresh execution/model permits are independently required.

The prepare/start/read/cleanup routes, prepared operation version
`sympozium.ai/celln-prepared-operation-v1`, decision version
`celln.sympozium.ai/authorisation-decision-v1`, and existing separate
`celln-execution` / `sympozium-model-gateway` audiences are unchanged.
Only `enduring-initial` and `enduring-turn` with a mediated model route support
this feature. One-shot artifacts, a model-free enduring parent, direct guest
workspace mounts, tool HTTPS, and arbitrary host paths remain unsupported.

For each **explicitly selected**, independently reviewed/signed tool, use:

```json
{
  "workspace": "none",
  "effects": "external-side-effects",
  "artifacts": {
    "operation": "write",
    "maxOperations": 4,
    "maxFiles": 8,
    "maxFileBytes": 4096,
    "maxTotalBytes": 16384
  },
  "https": null
}
```

These are fields of both `resolution.execution.tools[i].spec.limits` and the
signed `decision.tools[i].limits`; existing timeout/memory/argument/output limits
are still required. `read` uses `effects: "none"`; `write` requires
`effects: "external-side-effects"` (matching the starter catalogue). There is no
implicit write authority from a read tool. Artifact objects are strict: all five
fields are required; additional fields and other operations refuse.

| Field | Supported range / meaning |
| --- | --- |
| `operation` | Exactly `read` or `write` |
| `maxOperations` | Integer 1..64, aggregate attempts per disposable turn |
| `maxFiles` | Integer 1..256, retained parent-wide file ceiling |
| `maxFileBytes` | Integer 1..4096, UTF-8 data bytes per artifact |
| `maxTotalBytes` | Integer maxFileBytes..1048576, parent-wide retained data bytes |

Each signed ceiling must be no greater than its tool material ceiling, with the
same operation. The host intersects **all selected artifact-tool ceilings by
minimum**, not sum. The aggregate operation counter covers read and write
combined; a smaller cap on either tool constrains the entire turn. Malformed or
denied operations reaching the workspace broker spend this counter too.
The tools collectively authorize a set of read/write operations for the sealed
worker cell. This is a cell-wide capability, not a claim of per-process tool
isolation within that cell. Tool identity still binds exact name/revision/hash,
signed source closure, publisher, schema and ABI; changing just a tool name does
not mint authority.

`resolution.execution.runtimeLimits.workspace`, the runtime profile workspace,
and every native `ExecutionRequest.capabilities.workspace` remain **`none`**.
No new runtime workspace enum, native mount, guest network stack, executable
write permission, or provider/issuer private key is involved. Select the minimal
`runtime` `/worker` starter bundle and compose exactly the selected
`workspace-read` / `workspace-write` tool source closures, not the monolithic
legacy `worker` bundle. Each source can contain the identical `/pilot-fetch`.

## Guest broker ABI

Existing `pilot-fetch` PIO transport and `celln.workspace/v1` envelopes:

```json
{"apiVersion":"celln.workspace/v1","body":{"operation":"write","name":"notes/sentinel.txt","revision":0,"content":"artifact-violet"}}
{"apiVersion":"celln.workspace/v1","body":{"operation":"read","name":"notes/sentinel.txt"}}
```

Responses are `{"revision":1}` and
`{"revision":1,"content":"artifact-violet"}` respectively. Writes replace/create
atomically only at the exact current parent-wide revision. A lost write reply
must be reconciled by read, never automatically replayed. Failed/stale/quota
writes do not mutate data or advance the revision. Request wire cap stays 8192
bytes; actual accepted data is also bounded by the signed byte caps. Logical
names are 1..256 ASCII bytes in 1..64-byte slash-separated components containing
only alphanumerics, `-`, `_`, `.`; empty, `.` and `..` components refuse. Absolute
paths, backslashes and traversal refuse. There is no symlink operation, mount,
host path resolution, executable artifact, or archive expansion. `list`,
`search`, `append` and `delete` are **not** implied by scoped read/write. Legacy
workspace grants retain their prior explicitly configured semantics.

## Ownership, persistence and cancellation

The existing incarnation is independently checked on every turn:
`run_incarnation(JSON(["celln.scoped-parent/v1", clusterId, namespaceUid]), runUid)`.
The exact scope encoding and incarnation hashing are unchanged. Namespace
name/UID and run UID are also checked by the existing admitted decision and
receiver context. Namespace/name reuse and another run cannot attach to this
owner. The retained worker factory owns the in-memory artifact store; the
metadata registry never owns a reusable artifact grant.

After independent signed admission and durable child reservation, the owner
mints a host-only lease for the exact parent and derived child ID. There is one
active lease, no replay, and at most 1024 claimed children. Fresh child processes
share data only through this original parent-owned store. The derived policy
must equal the original parent's policy on every continuation; policy changes
(including contraction) require a new run in v1. No turn enlarges or resets
storage ceilings, parent lease, model budgets or original admission windows.

The worker validates the model-only relay before separately attaching the
artifact grant. Artifact calls do not consume model requests and do not create
GET/POST/HTTPS authority. The workspace lease is kept until the child VM has
been joined/destroyed; all copies revoke on lease drop. Every artifact operation
checks both the parent-bound child control and original operation control.
Cancel fences subsequent operations; completed writes are not rolled back.
Child cancellation preserves prior committed parent data. Root cancellation,
deletion, lease expiry or owner drop revokes data access and drops the store.
Cleanup confirmation still requires real native teardown. Owner/process loss
means `ContextLost`, not disk recovery or silent recreation. Persistence means
**across turns of one live parent**, not restart durability.

## Enforcement and proof

- `dispatch_scoped_artifacts.rs`: typed signed/material derivation at prepare
  and start, range/operation/effect restrictions and minimum aggregate policy.
- `dispatch_scoped.rs`: run/incarnation isolation on every turn, pinned policy,
  retained owner custody and reservation-bound lease supply.
- `dispatch_parent_worker.rs`: model-only gate, separate artifact attachment,
  lease lifetime through actual VM destruction.
- `workspace_broker.rs`: exact scoped read/write, foreign/replayed child refusal,
  active-child fence, cancellation and revocation. `celln-store::workspace`
  remains the bounded in-memory data implementation with no filesystem I/O.
- Hermetic tests cover three children, parent deletion, foreign ownership,
  read/write capability refusal, traversal, symlink/extra-operation rejection,
  strict fields, stale revision, quotas, cancellation and unchanged model count.
- `scoped_brokered_artifacts_three_turns_on_real_kvm` rebuilds/adopts a signed
  starter package under a disposable state root, composes the two real tools,
  and drives the actual scoped HTTP receiver and disposable guest cells. It
  verifies actual tool replies (not assistant claims), one stable parent,
  three distinct children and cells, six local TLS gateway requests, native
  execution/substrate receipts and confirmed root cleanup. It uses no paid
  provider and never discovers credentials.

Commands (bound builds with `CARGO_BUILD_JOBS=2`):

```sh
cargo fmt --all --check
cargo test --locked -p celln-cli --bin celln scoped
cargo test --locked -p celln-warden workspace_broker
cargo build --release --locked --target x86_64-unknown-linux-musl -p celln-pilot --bins
cargo test --locked -p celln-cli --bin celln scoped_brokered_artifacts_three_turns_on_real_kvm -- --ignored --nocapture --test-threads=1
```

Run hardware tests only with KVM access and explicit private scratch `TMPDIR`;
`CELLN_PILOT_DIR` selects the rebuilt static binaries. Optional test-only
`CELLN_RETAIN_SCOPED_PROOF=1` retains that scratch root for diagnostics. Never run
all ignored tests: some unrelated legacy tests are explicitly billable.
Installed Sympozium/Kubernetes, cross-tenant installed evidence and release
acceptance remain the dependent PR's work, not implied by this native proof.
