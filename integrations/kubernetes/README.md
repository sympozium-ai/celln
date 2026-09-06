# Celln node-plane spike for Sympozium

This prototype addresses the first execution-plane issues: contract (#1), one-node
Sympozium path (#2), node-agent seam (#4), and eligibility/capacity (#5).

## Decision

Use a node agent plus the transport-neutral `celln.dev/v1alpha1` execution request.
Do not implement Celln as a `RuntimeClass`/CRI handler. CRI owns a pod filesystem
and process lifecycle; Celln must instead receive explicit content hashes and
capabilities, then let `warden` make a sealed cell from a warm mote. The node agent
is the narrow Kubernetes seam: it reports eligibility and admits or refuses a
request. The Sympozium controller adapter must translate `AgentRun` policy
into this request. It freezes the request in `AgentRun.status.cellnRequest` and
persists the validated terminal receipt in `AgentRun.status.cellnReceipt`.

The included DaemonSet has only the privileged access required to inspect `/dev/kvm`
and read the Celln mote/tool stores. It does not mount the container runtime socket,
the host root filesystem, or an ambient network capability into a cell.

## Run against kind

```sh
./integrations/kubernetes/prove.sh
```

The script builds and loads the local image into a new disposable Kind cluster,
runs an unprivileged Job without `/dev/kvm`, and requires exit 5 plus a structured
`unsupported` refusal. It never deploys into your current Kubernetes context:
kubeconfig is isolated and an existing cluster name is refused. Evidence is kept
in a unique `target/kubernetes-proof/run.*` directory; the owned cluster is removed
on exit unless `KEEP_CLUSTER=1` is explicitly set. This refreshes the useful
unsupported-hardware harness originally contributed in PR #25.

Docker or Podman can provide the containers. `KIND_EXPERIMENTAL_PROVIDER=podman`
selects Podman; see the [Kind rootless requirements](https://kind.sigs.k8s.io/docs/user/rootless/).
`CELLN_KIND_BIN` selects a project-local Kind executable. Missing tools/runtime
fail explicitly; this proof never modifies host cgroup or kernel settings.

The `celln node admit` command emits JSON only. `verdict: accepted` means the node admitted the intent;
it does not claim the request's workload was run. An accepted node now also requires
a readable loader-compatible guest kernel with matching modules. This remains
preflight, not a proof that a particular guest boots. The versioned terminal result contract is
[`examples/execution/succeeded-receipt.json`](../../examples/execution/succeeded-receipt.json);
it binds a request, node, cell, resolved authority, and optional output to immutable
BLAKE3 references. `celln dispatcher` now executes requests and returns terminal
results through its authenticated execution endpoints. Declared requests fork an
operator-pinned warm mote; forge requests build their program before preparing and
forking a mote. External controller acceptance uses the separate full-path proof below.

For live scheduling, use authenticated `GET /v1/node`, not a standalone node-probe
process that cannot see the service's pre-cell reservations. The dispatcher now
reserves aggregate guest memory and broker slots atomically; zero egress slots
refuses network-enabled requests. Public `/v1/health` uses configured stores and
reports preflight readiness without exposing cache identities. See
[capacity and readiness](../../docs/NODE_CAPACITY.md),
[declared substrates](../../docs/DECLARED_SUBSTRATES.md), and
[input/workspace authority](../../docs/DISPATCH_INPUTS.md) for configuration,
trust boundaries and compatibility requirements.

For actual granted authority, selected lane, loaded substrate hashes and broker
activity, opt into authenticated `GET /v1/executions/<id>/audit`. Its separately
versioned [audit envelope](../../docs/DISPATCH_AUDIT.md) includes the unchanged
terminal receipt, preserving existing strict receipt consumers.

## Exercise actual Celln cells on the KVM host

The Kind proof is intentionally an unsupported-hardware preflight. For actual
production dispatcher HTTP → worker → KVM → receipt/audit conformance, run:

```sh
make conformance-kvm
```

The real-KVM fixture starts a separate loopback dispatcher process and submits
silent success, nonzero exit, output spoofing, broker refusal, all workspace modes,
immutable input delivery, denied input/closure authority, cancellation, deadline,
capacity pressure and locally revoked-tool cases through the public HTTP API.
It validates receipts/audits and reservation release and retains requests/results,
audit records, binary identity and revision/dirty/environment metadata under
`target/dispatch-conformance/`. These fixtures do not call a model or mutate
operator state. Hardware prerequisites may skip; a skipped run is not evidence
that isolation passed. The broader kernel sealing/hostile-guest proofs remain
in `celln verify` and the warden suite.

For the actual Sympozium controller → Kubernetes AgentRun → Celln execution path:

```sh
CELLN_KIND_BIN=/absolute/path/to/kind \
CELLN_SYMPOZIUM_PROOF=/absolute/path/to/sympozium/test/integration/test-celln-real-controller.sh \
make conformance-kvm
```

This opt-in starts a fresh Kind/Podman API server and the production Sympozium
controller on the host, connected to the isolated host KVM dispatcher. It does
not deploy to an existing cluster or claim nested KVM isolation inside Kind.
Requests, status, receipts and audits are retained under the conformance run's
`sympozium/` directory. See [conformance](../../docs/DISPATCH_CONFORMANCE.md)
for prerequisites, permissions and evidence semantics.

The companion benchmark harness exercises model-authored tasks: code is forged
twice, sealed and run in a real cell; bounded web tasks use `/pilot-fetch`.

```sh
./scripts/benchmark-kubernetes-agents.sh --runs 10 --parallel 2
./scripts/benchmark-kubernetes-agents.sh --runs 20 --parallel 3
```

It records one CSV line and one complete log per agent under
`target/kubernetes-agent-bench/`. Its duration is end-to-end user latency (model +
build + seal + guest work), not the mote-fork latency. Use `make bench-kvm` for the
latter; it stores raw hardware measurements in `target/celln-bench/`.

Open `docs/kubernetes.html` locally for the full-stack SVG and two animated
walkthroughs, including the recorded 10- and 20-run measurements.

Both proof scripts clean up their owned clusters automatically. If you separately
deploy `node-probe.yaml`, remove it only from the explicitly selected test context;
the proof scripts never require deleting resources from your current context.
