# Celln node-plane spike for Sympozium

This prototype addresses the first execution-plane issues: contract (#1), one-node
Sympozium path (#2), node-agent seam (#4), and eligibility/capacity (#5).

## Decision

Use a node agent plus the transport-neutral `celln.dev/v1alpha1` execution request.
Do not implement Celln as a `RuntimeClass`/CRI handler. CRI owns a pod filesystem
and process lifecycle; Celln must instead receive explicit content hashes and
capabilities, then let `warden` make a sealed cell from a warm mote. The node agent
is the narrow Kubernetes seam: it reports eligibility and admits or refuses a
request. A future Sympozium controller adapter should translate `AgentRun` policy
into this request and persist the returned verdict in `AgentRun.status.conditions`.

The included DaemonSet has only the privileged access required to inspect `/dev/kvm`
and read the Celln mote/tool stores. It does not mount the container runtime socket,
the host root filesystem, or an ambient network capability into a cell.

## Run against kind

```sh
./integrations/kubernetes/prove.sh
```

The script builds and loads the local image, deploys the DaemonSet, and writes the
real node report and admission verdict below `target/kubernetes-proof/`. The current
kind node exposes `/dev/kvm`, so an unavailable KVM boundary would be reported as
`unsupported`, never silently downgraded. It does not contain a prepared Celln mote
or tool store, so this fresh cluster truthfully returns `no_eligible_node`. Populate
signed mote and tool stores on the node before a node is eligible; do not create
placeholder files just to make the report pass.

The command emits JSON only. `verdict: accepted` means the node admitted the intent;
it does not claim the request's workload was run. An accepted node now also requires
a bootable guest kernel: KVM visibility and non-empty directories are not a truthful
execution capability. The versioned terminal result contract is
[`examples/execution/succeeded-receipt.json`](../../examples/execution/succeeded-receipt.json);
it binds a request, node, cell, resolved authority, and optional output to immutable
BLAKE3 references. It is a contract for the dispatcher, not evidence that a dispatcher
exists yet. Executing a workload through the node agent and writing that receipt back
to Sympozium remains the next slice.

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
