# One-node execution conformance

`make conformance-kvm` builds the production dispatcher and static pilot, then
runs both ignored real-KVM dispatcher suites. The declared-substrate fixture
also starts a separate `celln dispatcher` process on loopback with its own state
root, host policy and token. Requests go through the public HTTP endpoints,
not a replacement worker or fake VMM. No model account is required.

## Cases and evidence

- Silent success, output followed by nonzero exit, and output-marker spoofing.
- Declared mote/tool identities, actual lane/grants and strict receipt/audit correlation.
- Host-broker denial, with host counters, without depending on public HTTPS availability.
- All workspace modes; guest read/write/exec/socket/namespace denial attempts.
- Verified immutable input delivery, unapproved input refusal and unsupported closure refusal.
- Cancellation after the guest ran, end-to-end deadline, and no residual live cell.
- Atomic memory/broker reservation observations, duplicate-ID idempotence and capacity refusal.
- Local tool revocation observed on a warm-cache hit, without executing the revoked tool.
- Authentication on node/audit/cancellation paths.

Evidence goes to unique `target/dispatch-conformance/<timestamp>-<pid>/`
directories: requests, results, audits, dispatcher log, configured/busy capacity
and a summary with revision, dirty-worktree flag, binary digest and host identity.
Never present a dirty-worktree run as proof of its parent commit. CI uploads
these artifacts when a KVM runner executes the suite. Missing hardware/kernel/
toolchain prerequisites can skip; absence of a passing evidence summary is not
an isolation pass. Invalid code, failed assertions and service errors fail.

The ordinary-host production seccomp test also tries x32-tagged getpid and all
three io_uring entrypoints. It requires EPERM from the real installed filter,
not a substitute policy. Existing warden tests remain the hardware proof of
stage-2 sealing and live unmapping; `make fetch-proof` separately exercises an
actual public HTTPS request.

## Kubernetes preflight

`integrations/kubernetes/prove.sh` refreshes the unsupported-hardware fixture
from contributor PR #25 on the current execution stack. It creates its own Kind
cluster and isolated kubeconfig, loads the actual static CLI, and runs a Job
without `/dev/kvm`, host mounts, elevated capabilities or service-account token.
The proof requires both exit 5 and a JSON `unsupported` refusal with `node.kvm`
false. Evidence is retained under a unique `target/kubernetes-proof/run.*` path.
Docker and Podman providers are supported; the script never reuses an existing
cluster or edits the user's Kubernetes context or host kernel/cgroup settings.

## External Sympozium controller proof

An explicit `CELLN_SYMPOZIUM_PROOF` executable extends the real-KVM fixture
before local revocation. The fixture passes its isolated loopback URL, test
credential file, pinned request and evidence directory. It does not pass a
production credential or existing cluster context. The external process has a
600-second bound and a 10-second termination grace period.

Sympozium's `test/integration/test-celln-real-controller.sh` creates its own
Kind/Podman cluster and kubeconfig, installs the real CRDs, builds and runs the
production controller, and submits actual AgentRuns. It verifies immutable
execution, outcomes, guest restrictions, refusal, timeout and deletion-driven
cancellation, retaining statuses, dispatcher records, audits and binary/revision
metadata. No model account is needed for this static reference program.

```sh
CELLN_KIND_BIN=/absolute/path/to/kind \
CELLN_SYMPOZIUM_PROOF=/absolute/path/to/sympozium/test/integration/test-celln-real-controller.sh \
make conformance-kvm
```

Opting in runs the specified local script with the user's permissions; inspect
it first. Ordinary `make ci` and `make conformance-kvm` do not create this cluster.
External evidence lives in the conformance run's `sympozium/` subdirectory.

## Remaining scope

The optional external proof covers the actual Sympozium controller, not just an
HTTP client substitute. A complete acceptance run requires passing summaries
for both repositories on the intended clean revisions. Secret leases/live provider
withdrawal, distributed revocation and multi-node scheduling are not claimed.
Unsupported closures still refuse; their eventual implementation needs its own
conformance extension. Contributor PR #25 was superseded by merged #64, with
its attribution retained.
