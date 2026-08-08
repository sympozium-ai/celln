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

## What this branch proves today

- The Celln contract rejects a mutable ensemble handoff (`inputs[0].hash: latest`).
- It accepts the immutable ensemble-handoff example during contract validation.
- The deployed Kind node agent evaluates the same contract and truthfully refuses it while the node lacks a guest kernel and immutable mote/tool stores.

## What is deliberately not claimed yet

No Celln executor/controller has been installed in Kind. The existing node agent is an admission seam, not a replacement for Kubernetes CRI and not a warden dispatcher. Its current store non-emptiness test is a readiness placeholder, not evidence that a requested mote/tool hash can be resolved or run. The current Kind node has `/dev/kvm`, but no bootable guest kernel or provisioned stores, so an actual Celln-backed `AgentRun` cannot be accepted there. Building a fake fallback would violate the authority model.

The next implementation must add a third Sympozium `AgentRun` backend (alongside its Job and Agent Sandbox backends), plus a Celln Kubernetes shim/runner. It must render the same agent/IPC topology, create a warden only after admission, persist receipts/artifacts, and extend the Sympozium `AgentRun` API with a typed Celln policy plus receipt status. That controller can then be deployed and proven against a node prepared with a kernel, resolved signed motes, and resolved signed tool store.
