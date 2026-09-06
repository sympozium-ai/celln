# One-node Sympozium acceptance — 2026-09-06

The one-node milestone in [epic #2](https://github.com/sympozium-ai/celln/issues/2)
passed on merged Celln `c4a2c9670a088a00d7d7353dd0a669403fd26b29` and merged
Sympozium `aabe054989aec9db5ae29b3b76da8bfbdc8a0509`. Both worktrees were clean.
The final real-KVM suites passed (2 tests, 165.82 seconds), including all 11
external-controller cases. This is a tested one-node execution seam, not a claim
that arbitrary agents, closures or a production cluster deployment are supported.

## Environment and retained evidence

- Linux `7.1.12-200.fc44.x86_64`, actual `/dev/kvm`, readable kernel and static musl pilot/tool fixtures.
- Kind v0.33.0 with Podman 5.8.4. Kind supplied a real Kubernetes API and CRDs;
  the production Sympozium controller and Celln dispatcher ran on the host.
- The controller used its configured bearer credential over isolated loopback.
  It created no fallback Jobs. Both temporary clusters were removed and the
  original `kubernetes-admin@kubernetes` context was unchanged.
- [Committed evidence](evidence/2026-09-06-one-node.json) retains revisions,
  binary digests, requests, validated persisted receipts, actual grants and
  loaded substrate identities, audits, refusals and final capacity.

Full local artifacts (including controller/dispatcher logs and Kubernetes status):
`target/dispatch-conformance/1788703099494392717-1182367/`, with external cases in
`sympozium/`. The separate unsupported-hardware proof is under
`target/kubernetes-proof/run.rtuTap/`. Local paths are not hosted artifacts; the
committed evidence is the portable acceptance record. The cancellation status
snapshot precedes deletion; its audit proves the resulting terminal state.

## Requirement-by-requirement result

| Requirement | Evidence |
| --- | --- |
| Versioned control-plane contract | Production controller submits `celln.dev/v1alpha1`; original request is frozen before dispatch, then correlated with the receipt. |
| Truthful outcomes (#13) | Silent exit 0 succeeds; output + exit 7 fails; spoofed success markers + exit 9 fail. Separate real-KVM forge-mode runtime cases cover signals, output bounds and pilot refusal. |
| Pinned substrate and warm spawn (#13) | Declared kernel/initrd/toolfs are actually loaded; altered/invalid substrates cannot substitute the host default. Repeated warm forks preserve private scratch and do not increment preparation count. |
| Input/workspace authority (#3/#7) | Actual guest reads the declared immutable input, attempts mutation/rename/link/exec, and checks all three workspace modes. Guest socket/namespace/root-read/scratch-exec attempts are denied. |
| Explicit refusal | Unsupported closure and unapproved input produce failed/refused control-plane results without guest receipts; no alternate backend Job is created. A no-KVM Kubernetes Job returns exit 5 with structured `unsupported`. |
| Capacity/readiness (#5) | HTTP conformance observes atomic cell/guest-RAM/broker reservations and capacity refusal; terminal paths restore 256MiB guest RAM and one broker slot. Cache hints remain advisory. |
| Actual provenance (#10) | Controller persists the validated full receipt, including null/empty fields. Authenticated audit records the executed tool/lane/input hashes, loaded substrate hashes, grants and broker counts, correlated to AgentRun UID/caller and cell. |
| Cancellation/deadline (#13/#12) | Deleting an AgentRun cancels the exact observed live cell; its nonempty output proves guest execution. Finalizers wait for teardown. Deadline watchdog stops the guest; all reservations return. |
| Hardware/conformance (#12) | Both real-KVM suites pass; `celln verify` passes hostile ring-0 sealing and live revocation attempts; x32/io_uring production seccomp regressions pass in `make ci`. |

Also passed: `make ci`, `make fetch-proof` (actual brokered HTTPS), and
`scripts/acceptance-agent-cell.sh` (deterministic model-response fixture with real
build/reproduce/seal/execute/history, not an external model-service test).
Sympozium PR checks passed formatting, vet, build, tests and generated-code/CRD sync;
local controller/API tests passed with the race detector.

## Reproduce

Follow [conformance setup and commands](DISPATCH_CONFORMANCE.md). The external
proof needs Sympozium's `test/integration/test-celln-real-controller.sh`, Kind and
Podman in addition to the normal KVM prerequisites. No model account is needed.
Missing prerequisites are not an isolation pass. Hosted Celln CI lacked KVM and
skipped hardware proofs; the acceptance evidence above comes from real local KVM.

## Deliberate boundaries

The reference program is static: #6's closure implementation is not needed for
this milestone and closures still refuse. Operator-pinned content is the trust
root here; no asymmetric publisher-signature guarantee is claimed. Secret leases
and live provider withdrawal (#7), OpenTelemetry/durable audit transport (#10),
extended distributed conformance (#12), fleet revocation (#8), persistence (#9)
and broad comparative benchmarks (#11) remain separate work. Guest-RAM accounting
is not total host RSS; this is not CRI replacement, whole-AgentRun sidecar parity,
multi-node scheduling, or an upgrade of legacy deployed installer images.
