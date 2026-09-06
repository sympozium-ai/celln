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
into this request and persist the returned verdict in `AgentRun.status.conditions`.

The included DaemonSet has only the privileged access required to inspect `/dev/kvm`
and read the Celln mote/tool stores. It does not mount the container runtime socket,
the host root filesystem, or an ambient network capability into a cell.

## Run against kind

```sh
./integrations/kubernetes/prove.sh
```

The script builds and loads the local image, deploys the DaemonSet, and writes the
real node report and admission verdict below `target/kubernetes-proof/`. Results
depend on that cluster's KVM, kernel and configured stores. An unavailable KVM
boundary is `unsupported`, never silently downgraded. Prepare and authorize the
requested artifacts before dispatching declared workloads; do not create
placeholder files to imitate object availability.

The command emits JSON only. `verdict: accepted` means the node admitted the intent;
it does not claim the request's workload was run. An accepted node now also requires
a readable loader-compatible guest kernel with matching modules. This remains
preflight, not a proof that a particular guest boots. The versioned terminal result contract is
[`examples/execution/succeeded-receipt.json`](../../examples/execution/succeeded-receipt.json);
it binds a request, node, cell, resolved authority, and optional output to immutable
BLAKE3 references. `celln dispatch serve` now executes requests and returns terminal
results through its authenticated execution endpoints. Declared requests fork an
operator-pinned warm mote; forge requests build their program before preparing and
forking a mote. Fresh external Sympozium integration acceptance remains tracked in #2.

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

The Kind proof is intentionally a preflight because its node lacks real Celln
stores. The companion harness exercises the execution path the node will dispatch
once provisioned: model-authored code is forged twice, sealed, and run in a real
cell; bounded web tasks use the guest-only `/pilot-fetch` ABI.

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

Clean up with:

```sh
kubectl delete -f integrations/kubernetes/node-probe.yaml
```
