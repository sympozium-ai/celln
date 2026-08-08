# Sympozium ensemble execution plane

## Current seam

Sympozium already coordinates an Ensemble through `AgentRun` objects. A sequential edge stores the predecessor result in `AgentRun.status.result`, builds a bounded handoff card for the successor, carries the trace context, and injects shared workflow-memory access. A delegation edge records child lifecycle/result in `AgentRun.status.delegates` and delivers a completion through its IPC/NATS path.

Celln must not turn either mutable status text or a ConfigMap name into execution authority. The boundary is a versioned `celln.dev/v1alpha1` request. It names an immutable mote, immutable tool hashes, and (now) immutable `inputs[]` handoff data. `inputs[]` are data only: assay resolves them from the immutable artifact store and warden makes them workspace data. They never grant tool-lane authority.

See `examples/execution/ensemble-handoff.json` for the wire request.

## Redesigned integration shape: hermetic actions first

Celln is not the initial backend for a full `AgentRun` or Ensemble. Sympozium
keeps its existing Job/Agent Sandbox execution path for agents, pipelines,
delegation, shared memory, NATS/IPC, model credentials, and token lifecycle.
Celln becomes a first-class *hermetic action* choice for one bounded immutable
program and data inputs. It is appropriate for sensitive or risky work that
must return a content-addressed output and a Celln receipt.

The future Sympozium UI must present Celln alongside gVisor/Agent Sandbox as an
execution choice, but it must disable/reject the option until a live Celln
dispatcher reports availability. Refusal must never fall back to a Job or
Agent Sandbox while preserving a Celln label.

An optional `celln-action` relationship may later let a normal AgentRun spawn
one subordinate hermetic action. The parent waits for a validated receipt and
uses only its immutable output artifact as data. Celln does not thereby become
an agent-to-agent, delegation, or shared-memory participant.

## Full-AgentRun integration shape (not the first delivery)

1. The Sympozium controller keeps ownership of `AgentRun`, parent/delegate edges, cancellation, retries, token budgets, shared memory, and status conditions.
2. A Celln backend must render the existing agent-runner, ipc-bridge, shared `/ipc` volume, labels, session key, and NATS metadata before it submits work. This pod-equivalent topology is non-negotiable: without it, `delegate_to_persona`, `spawn_subagents`, and the parent `AwaitingDelegate` recovery path break.
3. The rendered workload needs a Celln Kubernetes shim/runner. The current `ExecutionRequest` names authority and limits only; it cannot represent OCI containers, sidecars, volumes, IPC, NATS, or an agent result/log stream. Directly converting an `AgentRun` to this request is therefore insufficient for whole-agent execution.
4. The shim writes the canonical Celln request from immutable policy-selected hashes. It must not derive an executable tool/mote hash from prompt text, pod image tags, mutable ConfigMaps, or a shared-memory record.
5. The Celln node agent validates the request then checks KVM, a bootable guest kernel, and resolved signed substrate/tool artifacts. It returns `accepted`, `invalid_request`, `unsupported`, or `no_eligible_node`.
6. Only an accepted request may reach a per-cell warden. One accepted request maps to one warden, one microVM, and one sealed cell. `warden` emits an execution receipt containing the Celln request ID, lifecycle timestamps, and content-addressed output/artifact hashes.
7. The Sympozium controller writes that receipt to `AgentRun.status.conditions`; it retains the existing human result/status behavior and uses the output hashes to create the next edge's `inputs[]`.

## Information-flow rules

- Text in `AgentRun.status.result` remains a bounded orchestration handoff for native Sympozium runners. It is not a Celln artifact reference.
- Persistent shared workflow memory remains accessed through Sympozium's memory service under the configured membrane/access rules. It is not mounted into a Celln tool lane.
- A Celln handoff is an immutable, declared, size-bounded object. Its BLAKE3 hash is the reference passed to a successor, with its media type and byte length. A missing artifact must refuse admission rather than fall back to a mutable copy.
- A source cell's output is harvested only after it has dissolved. The output reference has no path, tag, or arbitrary URL that the guest can reinterpret as code.
- Egress remains the Celln pilot ABI: named HTTPS destinations only, brokered by the host. Ensemble shared memory does not add ambient network access.

## What's proven today

- The Celln contract rejects a mutable ensemble handoff (`inputs[0].hash: latest`) and accepts the immutable `ensemble-handoff` example, in contract validation.
- A running Celln dispatcher admits a `celln.dev/v1alpha1` `ExecutionRequest` against a node's real, live-probed capacity, resolves the declared mote/tool by content hash from an integrity-checked store, seals the exact resolved bytes into a real KVM cell, and returns a genuine `ExecutionReceipt` — verified end to end on real hardware, including through a deployed Kubernetes Service, not just `kind`.
- Sympozium's controller dispatches `AgentRun.spec.backend: celln` directly (`internal/controller/agentrun_celln.go`), with the mutual-exclusivity and deadline-safety rules this document's "information-flow rules" require already enforced in code, not just described here.

## The honest gap

Sympozium's controller today submits through Celln's older `/v1/actions` — a free-form `{id, task, timeout}` that an LLM turns into fresh code on every call — not the hash-pinned `celln.dev/v1alpha1` contract described above. Migrating the controller onto that contract is real, scoped follow-up work: it needs the `AgentRun` side to express *which declared, hash-pinned program* to run rather than a free-text task, which is a genuine design question, not a wiring exercise. Until that lands, "hermetic" for a Sympozium-dispatched Celln action means "isolated compute," not yet "attested program."

The run-creation UX also doesn't yet gate the `celln` backend option on live dispatcher/provider availability — it's always offered, and a misconfigured or disabled Celln surfaces as a failed run rather than an unavailable option. Both gaps are tracked, not hidden, and neither blocks using Celln for what it's for today: one bounded, sensitive, or high-risk computation, selected explicitly, per run.
