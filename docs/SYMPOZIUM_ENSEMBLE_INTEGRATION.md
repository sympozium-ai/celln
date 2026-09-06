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
7. The Sympozium controller writes that receipt to `AgentRun.status.conditions`; it retains the existing human result/status behavior and uses the output hashes to create the next edge's `inputs[]`.

## Information-flow rules

- Text in `AgentRun.status.result` remains a bounded orchestration handoff for native Sympozium runners. It is not a Celln artifact reference.
- Persistent shared workflow memory remains accessed through Sympozium's memory service under the configured membrane/access rules. It is not mounted into a Celln tool lane.
- A Celln handoff is an immutable, declared, size-bounded object. Its BLAKE3 hash is the reference passed to a successor, with its media type and byte length. A missing artifact must refuse admission rather than fall back to a mutable copy.
- A source cell's output is harvested only after it has dissolved. The output reference has no path, tag, or arbitrary URL that the guest can reinterpret as code.
- Egress remains the Celln pilot ABI: named HTTPS destinations only, brokered by the host. Ensemble shared memory does not add ambient network access.

## Current Celln evidence (2026-09-06)

The implementation stack through [PR #64](https://github.com/sympozium-ai/celln/pull/64),
revision `ae5562c9804430a4280dee1666f927a55b0ed782`, passed `make ci` and both
real-KVM dispatcher suites from a clean worktree. These are branch results,
not a claim that the stack has merged or that an external controller ran it.

- The production dispatcher was exercised over authenticated HTTP, executing
  the operator-approved declared kernel/initrd/tool bytes from warm mote forks.
  The earlier limitation of ignoring the declared kernel is fixed in this stack.
- Silent success, nonzero failure, forged output markers, guest workspace
  restrictions, immutable inputs and unsupported authority were tested.
- Cancellation and end-to-end deadlines stopped execution and released cell,
  aggregate guest-memory and egress-broker reservations. Guest-memory accounting
  is not a total host-RSS bound.
- Receipt/audit correlation records executed substrate identities, actual grants
  and broker counters. Local tool revocation refuses a warm-cache execution.
- An isolated Kind Job without KVM returned exit 5 and a structured unsupported
  refusal. This is refusal evidence, not a successful Kubernetes-to-KVM proof.

The commands, coverage and evidence format are in
[`DISPATCH_CONFORMANCE.md`](DISPATCH_CONFORMANCE.md). Clean-revision local
summaries are under `target/dispatch-conformance/1788692248178884672-1073720/`
and `target/kubernetes-proof/run.xXZHr6/`; these paths are not hosted artifacts.
Earlier reported Kubernetes/AgentRun demonstrations are historical only and
do not establish compatibility with the current authenticated dispatcher.

## External controller gap

Read-only inspection of Sympozium main at
`fa1bc53a828fae3ec644bdafdc9ed061135c6eb1` found the following in
[`internal/controller/agentrun_celln.go`](https://github.com/sympozium-ai/sympozium/blob/fa1bc53a828fae3ec644bdafdc9ed061135c6eb1/internal/controller/agentrun_celln.go):

- POST and polling requests carry no bearer token. Direct calls to the current
  authenticated dispatcher therefore refuse; disabling authentication is not
  an acceptable integration fix.
- The request type supports forge only, not a predeclared immutable mote/tool/
  input request. It cannot express the static pinned reference proof yet.
- A `Succeeded` record is accepted without validating a complete receipt or
  correlating its request identity. Only bounded output is persisted as the
  result; selected receipt fields are logged, not retained as provenance.
- Its backstop deadline fails the AgentRun locally without calling Celln's
  cancellation endpoint. That path does not prove remote teardown.

These findings are source inspection, not a fresh external runtime test. The
controller integration must be repaired and tested before the epic's full-path
acceptance can pass. No changes to Sympozium or an existing cluster are implied
by this document.

## Next acceptance run

Use an isolated test environment and record both repository revisions, dirty
flags, node prerequisites and binary/image identities. Provision the dispatcher
token through operator configuration, never through task text. Submit one
operator-pinned static program and bounded immutable input through the actual
Sympozium controller using the versioned contract; retain the original request,
AgentRun status, terminal receipt and authenticated audit.

Check silent success and nonzero failure, unsupported authority refusal,
cancellation and timeout teardown, guest denial attempts, exact identities and
released reservations. A missing/invalid/mismatched receipt must not become
success, and refusal must not fall back to a different backend. Repeat on the
merged stack before closing [epic #2](https://github.com/sympozium-ai/celln/issues/2).
Live availability gating for the UI and broader agent/ensemble integration
remain separate from this first hermetic-action proof.
