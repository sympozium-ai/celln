# Sympozium ensemble execution plane

## Current seam

Sympozium already coordinates an Ensemble through `AgentRun` objects. A sequential edge stores the predecessor result in `AgentRun.status.result`, builds a bounded handoff card for the successor, carries the trace context, and injects shared workflow-memory access. A delegation edge records child lifecycle/result in `AgentRun.status.delegates` and delivers a completion through its IPC/NATS path.

Celln must not turn either mutable status text or a ConfigMap name into execution authority. The boundary is a versioned `celln.dev/v1alpha1` request. It names an immutable mote, immutable tool hashes, and (now) immutable `inputs[]` handoff data. `inputs[]` are data only: assay resolves them from the immutable artifact store and warden makes them workspace data. They never grant tool-lane authority.

See `examples/execution/ensemble-handoff.json` for the wire request.

The dispatcher transport and host-owned egress policy are documented in
[`DISPATCHER_SECURITY.md`](DISPATCHER_SECURITY.md). In particular, the
dispatcher has no native TLS: non-loopback deployments require an explicit
unsafe bind opt-in and a TLS-terminating reverse proxy. Request egress is
deny-all unless the host operator configures exact allowed hostnames.

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
7. The Sympozium controller retains the validated receipt in `AgentRun.status.cellnReceipt`; it keeps human-readable result/status separate and uses output hashes, not mutable result text, to create a future edge's `inputs[]`.

## Information-flow rules

- Text in `AgentRun.status.result` remains a bounded orchestration handoff for native Sympozium runners. It is not a Celln artifact reference.
- Persistent shared workflow memory remains accessed through Sympozium's memory service under the configured membrane/access rules. It is not mounted into a Celln tool lane.
- A Celln handoff is an immutable, declared, size-bounded object. Its BLAKE3 hash is the reference passed to a successor, with its media type and byte length. A missing artifact must refuse admission rather than fall back to a mutable copy.
- A source cell's output is harvested only after it has dissolved. The output reference has no path, tag, or arbitrary URL that the guest can reinterpret as code.
- Egress remains the Celln pilot ABI: named HTTPS destinations only, brokered by the host. Ensemble shared memory does not add ambient network access.

## Verified one-node integration

The fresh production-controller proof passed on merged Celln
`c4a2c9670a088a00d7d7353dd0a669403fd26b29` and Sympozium
`aabe054989aec9db5ae29b3b76da8bfbdc8a0509`, both clean. See
[the acceptance record](SYMPOZIUM_ACCEPTANCE.md) for all requirements, commands,
environment, binary identities and committed evidence.

The production Sympozium controller ran against actual Kubernetes CRDs and
AgentRuns in a disposable Kind cluster, speaking the authenticated versioned
contract to an isolated host Celln dispatcher. Celln executed real KVM cells from
the approved declared substrate. Eleven external cases covered silent success,
nonzero failure, marker spoofing, immutable inputs, workspace restrictions,
unsupported authority, timeout and deletion cancellation. No fallback Jobs were
created, and terminal paths released their reservations.

The controller gaps previously identified at Sympozium
`fa1bc53a828fae3ec644bdafdc9ed061135c6eb1` were repaired in
[PRs #421](https://github.com/sympozium-ai/sympozium/pull/421),
[#422](https://github.com/sympozium-ai/sympozium/pull/422),
[#423](https://github.com/sympozium-ai/sympozium/pull/423) and
[#424](https://github.com/sympozium-ai/sympozium/pull/424):

- Operator-mounted bearer authentication, rotation, redirect refusal and explicit
  transport configuration; no credential is derived from task text.
- Explicit immutable `spec.celln` requests, independent of a model task, frozen
  in `status.cellnRequest` before first dispatch.
- Complete receipt validation and correlation against the frozen request, with
  canonical null/empty fields retained in `status.cellnReceipt`.
- Authenticated remote cancellation and finalizers that wait for terminal
  teardown on deletion or controller deadline.

The Kind node did not provide nested KVM: the real controller and dispatcher
ran on the host, and Kind supplied the Kubernetes API. A separate unprivileged
Kind Job proved the no-KVM unsupported refusal. Neither proof deployed into the
existing cluster or upgraded legacy installer images.

## Boundaries and next work

The static reference does not require dependency closures. The subsequent
[trusted-closure acceptance](TRUSTED_CLOSURES_ACCEPTANCE.md) adds signed,
precomposed closure AgentRuns; unsupported combinations still refuse.
Secret-provider live withdrawal, distributed revocation, persistent
execution, multi-node scheduling and broader tracing remain outside this
one-node milestone. See the acceptance record for the issue ownership.

Full agent/ensemble/sidecar integration and live UI availability policy remain
separate from the verified hermetic-action seam. Historical demonstrations are
not evidence for those broader features.
