# Agent Harness execution in Celln — requirements and proof contract

Status: implementation requirements, not a declaration of delivered capability.
Recorded 2026-09-07. Product tracking: [Sympozium epic #426](https://github.com/sympozium-ai/sympozium/issues/426).

## User outcome

A user chooses an approved Agent Harness, opts into Celln execution and lends
an explicit set of approved tools, including tools they have brought for
admission. The Harness runs a real model-driven agent loop, invokes those
tools, and returns useful results with attributable execution evidence.

The user must not need to understand mote packaging, PIO or the VMM to use the
feature. Administrators must still be able to inspect what code and authority
were admitted and revoke access. A **mote** is the substrate at rest; a **cell**
is a live, sealed, tool-loaned mote. Every cell is a sealed mote.

## Two distinct capabilities

| Mode | Where the agent loop runs | What Celln isolates | Completion claim |
|---|---|---|---|
| Celln tool execution | Existing Job/HarnessSession adapter | Individual borrowed-tool invocations | Intermediate integration proof only |
| Harness in Celln | Approved sealed runtime inside a cell | The Harness runtime and its explicitly lent execution authority | Required target experience |

Do not describe a host-side model loop calling cells as an in-cell Harness.
Do not relabel built-in functions compiled into a reference program as user-
borrowed tools. Do not remove the current Harness/backend refusal until the
requested runtime and authority are actually delivered.

## Current baseline and gaps

Prototype progress: the [borrowed-tools reference proof](HARNESS_BORROWED_TOOLS_PROOF.md)
now demonstrates a real model/tool/result loop inside a warm-forked cell with
two separately hashed executables. This does not remove the baseline production
gaps below or complete the deployed Harness acceptance gates.

The prototype now also has [host-enforced model/parameter and output-reservation
limits](HARNESS_MODEL_POLICY.md), with real guest escalation attempts. These
are not yet bound to Sympozium runtime/model selection or tenant accounting.

Baseline inspected: Celln `4b95a1c`, Sympozium `88a432c`, plus draft M0 router
changes in [Celln #70](https://github.com/sympozium-ai/celln/pull/70) and ingress
policy in [Sympozium #427](https://github.com/sympozium-ai/sympozium/pull/427).

- Direct typed AgentRun execution and a signed dynamic closure have committed
  hardware evidence: [trusted closure acceptance](TRUSTED_CLOSURES_ACCEPTANCE.md).
- The real DeepSeek acceptance run exercised native forge/build/execute, not a
  Harness agent loop or a Sympozium model-routed run.
- The existing guest HTTPS broker accepts GET URLs only. Model completion APIs
  require a bounded request body and POST. A host allowlist alone must not
  implicitly grant POST or provider credential use.
- The dispatcher delivers one invoked tool / one signed precomposed closure.
  Multiple requested tools refuse. Closure requests with forge, immutable
  inputs or egress also refuse. These guards need delivery proofs before removal.
- AgentRuntime is presently an approved OCI primary-container profile;
  HarnessSession uses a Deployment/Service. Neither is a sealed Celln runtime
  contract. An OCI digest is not automatically a trusted closure or proof that
  its runtime can function without ordinary networking/filesystem authority.
- The local Pi adapter at version 0.84.4 explicitly disables tools and does not
  implement MCP. Selecting it does not establish borrowed-tool support.
- A three-node Kind cluster with two workers has demonstrated cross-worker
  enforcement of the chart ingress policy and KVM VM creation from privileged
  pods. This is environment qualification, not guest execution, independent
  physical-host failure tolerance or the deployed Harness proof.

## Required execution contracts

### R1 — Runtime identity and placement

Runtime identity, execution placement and tool selection must be separate
concepts in the API and UX. Bind an administrator-approved, immutable runtime
artifact to a versioned adapter contract. Resolve and freeze identities before
dispatch; a runtime change must not silently change a retry.

For full Celln mode, package all executable dependencies and necessary runtime
data into an authenticated closure. Define how task/persona/configuration and
results cross the boundary. Do not assume the container adapter's writable
HOME, PVC, loopback MCP server, sockets or environment exist in the guest.

Persistent conversation support needs an explicit design: state outside
disposable cells, or a bounded persistent execution model. Define reconnect,
turn cancellation, resume and teardown. An indefinitely extended one-shot run
is not a persistence implementation. Coordinate with [Celln #9](https://github.com/sympozium-ai/celln/issues/9).

### R2 — Model and remote-service mediation

- The in-cell Harness must request model work through a bounded, host-enforced
  broker. It must not receive an ordinary network stack or unrestricted socket
  authority merely to make an SDK work.
- Preserve the existing GET ABI. Version extensions explicitly; reject unknown
  methods, fields and versions. Keep request/response bytes, call count, model
  output, execution time and cancellation bounded.
- A POST grant must identify an exact allowed endpoint separately from a GET
  host grant. The host selects a credential bound to that endpoint. The guest
  cannot supply arbitrary headers, credential files, proxy configuration or
  alternate destinations that broaden authority.
- Provider, model and permitted model parameters must reflect the selected
  Sympozium configuration. Endpoint restriction alone does not enforce model
  choice or token/cost budget: validate those independently before product use.
- DNS pinning, public-address/SSRF checks and TLS verification remain mandatory.
  Do not expose private-cluster MCP by weakening the public HTTPS checks;
  platform services need a separately defined authenticated mediation path.
- No implicit redirect or retry for credential-bearing POSTs. Define ambiguous
  response handling so a transport error cannot cause duplicated side effects
  or unbounded billing.
- Provider keys stay outside the guest, invocation, immutable artifact, argv,
  logs and evidence. Rotation must be defined, failures must refuse, and
  revocation semantics must distinguish future calls from already in-flight
  work. Local file reload is not fleet-wide live withdrawal.

Related: [secret providers #7](https://github.com/sympozium-ai/celln/issues/7),
[fleet revocation #8](https://github.com/sympozium-ai/celln/issues/8).

### R3 — Borrowed tools

Each tool binding requires an immutable artifact/closure identity, publisher,
entry point, argument/result schema, supported lane and bounded resources,
inputs, workspace and egress. Keep packaging, publisher approval, admission,
distribution, prewarming and lending distinct lifecycle steps.

Users may submit a tool for approval; they may not self-approve its publisher
or elevate its authority. Effective authority is the intersection of operator
policy, approved runtime/tool capability, Agent grants and per-run selections.
Tool discovery and invocation must both enforce that intersection; an invented
tool name or model-supplied capability claim must refuse.

Lending is not installation into a writable guest filesystem. Code remains
sealed; executable authority is content-hash based. Interpreters and agent-
authored code must preserve lane classification. A signature authenticates an
artifact's origin; it does not make arbitrary behavior safe.

Distinguish executable tools, remote MCP services and privileged SkillPacks.
Do not move Kubernetes service-account credentials or the entire sidecar/IPC
surface into a cell as a compatibility shortcut.

### R4 — Lifecycle, provenance and operations

Correlate AgentRun/HarnessSession, model turn, tool call, resolved runtime and
tool identities, policy decision, node, Celln execution and terminal receipt.
Closure publisher/member provenance currently belongs to the correlated audit,
not receipt v1alpha1; do not claim otherwise.

Cancellation must reach the owning execution and wait for teardown. Submission
retries, router restarts/replicas and node loss need stable ownership and
explicit ambiguous-outcome handling. Health-based redistribution is not safe
retry semantics. Bound registry retention without losing live ownership.

Integrate applicable lifecycle gates, metering, events, memory and delegation
through mediated control-plane services; explicitly reject unsupported options
rather than ignoring them. Reuse common completion accounting where possible.

Capability reporting must distinguish reachability, authentication, runtime
compatibility, hardware eligibility, admitted artifacts and current capacity.
A TCP connection or `/dev/kvm` file alone is not execution readiness.

### R5 — UX

Expose approved Harness selection, placement and a reviewable borrowed-tool
list. Show effective permissions and unsupported combinations before launch;
show resolved runtime/tool identities, refusals, results and receipts afterward.
Use the two distinct mode labels above. Keep full Celln opt-in unavailable for
an adapter until it passes its supported-contract conformance gate.

## Acceptance evidence — no substitutes

1. **Model-in-cell proof:** guest code actually initiates a bounded request via
   the broker, receives a real model response and uses it. Observe host-side
   request counters and guest execution evidence. A canned response or a model
   called only by the host does not pass. This alone is not a borrowed-tool proof.
2. **Tool-lending proof:** one real model task uses at least two independently
   identified, selected tools, including an admitted user-supplied artifact.
   Record model tool-call IDs, executed arguments, receipts and results used in
   the next model turn. Verify an unselected tool is rejected.
3. **Full placement proof:** the supported Harness agent loop itself executes
   inside a cell with the approved runtime identity. Observe actual guest
   attempts at forbidden code mutation/network/authority expansion; host-side
   assertions alone do not prove the boundary.
4. **Product proof:** submit through Sympozium using the supported API and
   deployed controller/router/dispatcher path; show results, receipts, model
   routing and failure/refusal reasons. Direct-launch probes supplement, not
   replace, this evidence. Include the chosen conversational lifecycle.
5. **Failure proof:** cancellation, deadlines, malformed/flooded output,
   missing credentials, tampered closures, revoked tools, exhausted budgets,
   replica restarts and node loss. No retry may silently duplicate tool work.
6. **Regression/measurement:** retain existing GET/PIO, hardware sealing,
   closure, Job and HarnessSession suites; publish cold/warm latency, concurrent
   memory and cleanup with exact revisions and topology. Two Kind workers on
   one host are not independent physical failure domains. A skipped hardware
   test is not a pass.

## Delivery sequence

Finish M0's authenticated deployed path and ownership semantics. In parallel,
develop the versioned model broker needed for in-cell inference, then approved
runtime delivery and tool lending. An intermediate external Harness calling
Celln tools may validate the UX and tool-call contract, but must remain labelled
as such. Full opt-in and epic completion require the full-placement and product
proofs above. Record each increment's actual evidence and remaining limits in
the epic rather than promoting a prerequisite test into an end-to-end claim.
