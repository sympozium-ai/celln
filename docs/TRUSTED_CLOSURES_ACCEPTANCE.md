# Trusted closure milestone — merged acceptance

Issue [#6](https://github.com/sympozium-ai/celln/issues/6) is complete for the
explicitly authenticated, precomposed closure format. Implementation:
[Celln #68](https://github.com/sympozium-ai/celln/pull/68); controller proof:
[Sympozium #425](https://github.com/sympozium-ai/sympozium/pull/425).
See [format, trust policy, operation and limits](TRUSTED_CLOSURES.md).

On 2026-09-06 the full regression suite passed on clean merged revisions:

- Celln `b43133f8550e581b37c6caf6679a0e89c96483dc`.
- Sympozium `88a432cad3c976978b4d62f01244ea8b66b6471e`.
- Linux `7.1.12-200.fc44.x86_64`, real host KVM, Kind v0.33.0, Podman 5.8.4.

[Portable evidence](evidence/2026-09-06-closures.json) contains signed closure
identities, actual controller request/status/audit, binary identities, capacity
cleanup, static and closure measurements, and both controller suite summaries.
It contains no API credential or private publisher key. This documentation-only
follow-up does not change the tested runtime.

## Acceptance

| Requirement | Observed result |
|---|---|
| Publisher authentication | Strict Ed25519 signatures checked against separate operator policy. Invalid signature and withdrawn publisher refuse, including warm-cache reuse. |
| Resolved dynamic closure | Native dynamically linked Rust program runs with its declared ELF loader, libc and libgcc from the exact signed sealed image. All guest member hashes are checked. |
| Guest immutability | Guest attempts to overwrite, remove, rename and hard-link libraries fail. Copied scratch code cannot execute or map executable. A mismatched member and a symlink member refuse before execution. |
| Actual sealed-page execution | Removing the closure memslot after the workload emits output kills that running guest program. It is not executing a detached page-cache copy. |
| Provenance | Production HTTP audit and actual Sympozium AgentRun correlate the authenticated closure hash/publisher/member graph with the pilot verdict and persisted receipt. |
| Warm reuse and collection | Every launch forks a parked mote. Eight simultaneous forks add no sealed-tool allocation. A live fork retains its pages after cache eviction; unused pages are collected after the last owner releases them. |
| Regression coverage | All three native KVM suites passed in 231.85 seconds; both actual-controller modes passed (11 static cases plus signed closure). |

The controller tests used private kubeconfigs and disposable Kind clusters, with
the real controller and Celln dispatcher on the host. Kind supplied the real
Kubernetes API, not nested KVM. Both clusters were deleted; no Podman containers
remained running. The existing `kubernetes-admin@kubernetes` context and original
user worktrees were preserved. No production-cluster deployment is claimed.

## Measured comparison

Single-host reference samples, not statistical performance promises. Both
fixtures deliberately use 32 MiB sealed filesystems; these values do not measure
whole-process RSS or minimum closure size. Packaging includes compilation,
filesystem construction, initrd construction and storing artifacts.

| Measurement | Static reference | Signed dynamic closure |
|---|---:|---:|
| Cold materialisation | 868.0 ms | 1,003.5 ms |
| First execution, including cold mote preparation | 3,143.4 ms | 3,034.1 ms |
| Two subsequent warm executions | 181.8 / 127.3 ms | 138.6 / 166.7 ms |
| Shared sealed allocation for eight simultaneous forks | 32 MiB | 32 MiB |
| Additional sealed allocations for those forks | 0 | 0 |

## Full regression run

Passed on the merged code:

- `make ci`: formatting, lint, build and tests.
- `make conformance-kvm` with the optional real-controller hook: actual HTTP,
  native KVM, exit/signal/flood/spoof outcomes, inputs, all workspace modes,
  egress refusal, cancellation/deadlines, capacity, local revocation and audit.
- `integrations/kubernetes/prove.sh`: no-KVM Job exits 5 with explicit
  `unsupported`; this is refusal evidence, not an isolation pass.
- `celln --json verify`: hostile ring-0 writes refused; live revocation proven.
- `make fetch-proof`: actual HTTPS via the pilot broker ports.
- `scripts/acceptance-agent-cell.sh`: public setup → agent → output → dissolved
  history flow, using the deterministic model fixture.
- `go test -race ./internal/controller ./api/v1alpha1`: counterpart regression.
- Offline `closure sign` → operator-policy `closure admit` command smoke test.
- Real authorized DeepSeek API test: generated program built reproducibly,
  sealed, executed in the agent lane, and dissolved (4.33 seconds). This tested
  the native forge/launch pipeline; the controller tests used deterministic
  declared workloads, not a paid model. Credential passed only in the provider
  subprocess environment/stdin header, never in curl arguments or evidence.

Reproduce the cross-repository proof with:

```sh
CELLN_SYMPOZIUM_PROOF=/path/to/sympozium/test/integration/test-celln-real-controller.sh \
CELLN_KIND_BIN=/path/to/kind make conformance-kvm
```

The explicitly billed test is opt-in:

```sh
PATH="$PWD/scripts:$PATH" CELLN_TEST_FORGE_BACKEND=deepseek \
  cargo test -p celln-cli forge_actually_writes_builds_and_runs_a_program \
  -- --ignored --nocapture
```

Supply `DEEPSEEK_API_KEY` through your secret environment; do not put it on the
command line or commit it. Missing hardware prerequisites skip, never constitute
a successful isolation proof.

## Remaining boundaries

One invoked tool, one explicitly signed precomposed closure. Closure requests
with forge, immutable inputs or egress still refuse. Runtime data files must be
enumerated; arbitrary distro images do not receive a root-wide grant. Receipt
v1alpha1 is unchanged; closure provenance lives in the correlated execution
audit. There is no automatic OCI/cosign publisher discovery, layer composition,
online disk sweep, or fleet-wide live publisher withdrawal. Disk retention and
offline collection are defined in the format document; live page collection is
implemented and tested. Secret providers, distributed revocation, persistence,
durable tracing and broader benchmarks remain separate tracked work.
