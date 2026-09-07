# Sealed closure member identity verification

For Sympozium epic [#426](https://github.com/sympozium-ai/sympozium/issues/426),
operator review must progress beyond hashing a signed filesystem blob. The
read-only `celln closure check-members REQUEST.json` command verifies declared
member paths and hashes **inside a sealed cell**, using the same pinned
substrate and guest checks as declared execution. No tool is invoked.

## Inputs and trust

`REQUEST.json` is an existing valid declared `celln.dev/v1alpha1` execution
request selecting one approved mote, executable and signed closure. Its
invocation arguments must be empty; workspace must be `none`; inputs, egress,
forge and Harness binding must be absent. This check never interprets a task
as a command or forwards execution arguments. All ordinary request validation
and host mote/publisher/revocation policies remain authoritative.

```sh
celln --root /absolute/operator/node-state closure check-members REQUEST.json
```

The operator root contains `motes/`, `tools/`, `closures/`, `trusted-motes.json`
and `trusted-closures.json`, as for declared dispatch. Kernel/initrd must be
independently operator-approved; a submitted filesystem cannot supply its own
verification pilot. This does not import a submitted publisher or bypass local
withdrawal. Stores are read by exact content identity and verified bytes are
held for loading, not reopened by mutable path. Missing KVM/compatible pilot
cannot produce a successful verification report.

## How it works

Cold preparation boots the pinned substrate into its existing authority-free
park point. The check, including the first one, forks that warm mote. The host
delivers a separate `verify_closure` envelope containing bounded signed member
metadata and an unpredictable challenge; it has **no executable path/alias**.
Older pilots interpret it as zero invocations and cannot silently execute the
tool. New pilots refuse mixed verification/execution envelopes without falling
through to an execution path. No model or network broker is enabled.

Pilot traverses canonical paths under the sealed `/tools` mount, refusing
symlinks, nonregular/oversized files and absent members, then hashes actual
member bytes. It emits a versioned report bound to the challenge, exact request
bytes and member count. The host requires exactly one matching successful
report, clean shutdown and no execution markers. Each check cell is dropped;
the bounded warm template may remain cached. The cell run has a watchdog of at
most ten seconds; cold preparation retains its existing separate watchdog.
Policies are rechecked after the potentially slow operation.

The warm cache is process-local. A standalone CLI exits and releases its
template; checking members in that process does **not** prewarm a separate
dispatcher or make a node selection ready. Distribution/prewarm must be proven
in the actual serving process before advertising readiness.

Success reports `scope=sealed-member-identities-only`,
`memberIntegrity=verified-in-sealed-cell`, `toolExecution=false`, exact
mote/kernel/initrd/toolfs/closure identities and `cellDissolved=true`.
**`conformance` and `artifactReadiness` remain `not_checked`.** This establishes
member identity, not ELF/loader/ABI correctness, application behavior, tool schema
semantics, permission suitability, node distribution/prewarm leases or full
Harness conformance. The report is not a signed attestation or a grant. A
future trusted verifier must bind the current catalogue/runtime/policy identities
and complete those remaining gates before exposing runnable readiness.

## Reproduction and evidence

The existing ignored signed-closure suite now exercises positive sealed-member
verification and the real CLI, alongside altered-library and symlink-member
refusals and the existing dynamic execution/revocation/hostile-guest cases:

```sh
CARGO_TARGET_DIR=target/validation cargo build --release \
  --target x86_64-unknown-linux-musl -p celln-pilot \
  --bin celln-pilot --bin pilot-fetch
CARGO_TARGET_DIR=target/validation cargo build -p celln-cli
CELLN_TEST_BINARY="$PWD/target/validation/debug/celln" \
CELLN_PILOT_DIR="$PWD/target/validation/x86_64-unknown-linux-musl/release" \
CARGO_TARGET_DIR=target/validation cargo test -p celln-cli \
  signed_closure_on_real_kvm -- --ignored --nocapture
```

Unavailable prerequisites are explicitly skipped, not counted as hardware
passes. Reports are saved in `target/closure-proof/`. The revised evidence
separates member-check preparation time from subsequent execution samples:
those executions are now prewarmed by the member check and must **not** be
described as cold-start measurements. Protocol tests cover mixed envelopes and
the absence of a legacy executable fallback. Normal `make ci` remains required.

On 2026-09-07, `make ci` passed and the explicit KVM/CLI suite passed in
10.20 seconds with no prerequisite skips. The
[committed report](evidence/sealed-members-2026-09-07.json) includes both
four-member verification reports, binary fingerprints and working-tree
provenance. Initial member checking including preparation took 2,746,416 µs.
These are single-host fixture measurements, not fleet or full-Harness claims.
No cluster deployment or provider credentials were changed or used.
