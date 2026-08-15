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

The preflight requires Cargo, Docker, Kind, kubectl, and jq on an x86-64 host.
The script builds the static Celln CLI, packages it as `celln-node:dev`, loads it
into an ephemeral Kind cluster, and writes evidence below
`target/kubernetes-proof/`. Its first conformance case deliberately gives the pod
no `/dev/kvm`: an execution request requiring hardware isolation must exit `5`
and return `verdict: refused` with `reason: unsupported`, never silently
downgrade or pretend the request ran.

This is an admission preflight, not an isolation proof. It does not accept or run
the workload, and it makes no claim about guest enforcement. The cluster is
deleted after the run; set `KEEP_CLUSTER=1` to retain it for inspection.

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
