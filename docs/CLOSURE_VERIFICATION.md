# Read-only closure authenticity reports

For Sympozium's approved-tool catalogue integration (epic
[sympozium#426](https://github.com/sympozium-ai/sympozium/issues/426)), an operator
can verify a signed descriptor against the current local publisher/revocation
policy without admitting it to a store:

```sh
celln --root /var/lib/celln closure verify signed-closure.json \
  --expected-hash blake3:<exact-descriptor-hash> \
  --publisher <expected-lowercase-ed25519-public-key> \
  --entry-point /tools/example \
  --executable blake3:<expected-executable-hash>
```

Replace placeholders with exact catalogue identities. The root must already
contain operator-controlled `trusted-closures.json` in the existing
`celln.dev/closure-policy-v1` format. A tenant submission must never supply that
policy or add itself to the publisher list. No private signing key is needed.

Success emits one `celln.dev/closure-verification-v1` JSON report on stdout.
Failure returns nonzero without a success report. The report binds the exact
descriptor bytes, expected publisher, selected member path/hash and current
policy bytes' BLAKE3 hash. It also reports the signed filesystem hash, closure
entry point, interpreter flag and dependency graph. A selected member need not
be the closure's primary entry point: membership is not permission to invoke it.
Reformatting a signed JSON descriptor preserves signature semantics but changes
its content identity; the expected descriptor hash must still match exact bytes.

The same verification function now serves offline admission and dispatcher
resolution. All three re-read the current policy and reject revoked descriptor,
filesystem or member hashes. Policy and descriptor reads are bounded at 256 KiB;
an oversized policy fails closed rather than being partially loaded. An existing
larger dispatcher policy must be reduced within that documented bound before
upgrading. No wire-format or signature-domain change is introduced.

## Deliberately limited evidence

### Optional local filesystem-byte verification

Add `--toolfs /absolute/operator-staged/toolfs.ext2` to hash the exact local
artifact against the signed filesystem identity. Inputs must be nonempty regular
files of at most 512 MiB; Unix symlinks/special files refuse. Reads remain bounded
if files grow. No mount, filesystem parser, guest or store write is involved.
Policy is rechecked after reading; policy changes during verification refuse.

This emits `scope=descriptor-and-local-toolfs-bytes`, `localToolfsVerified=true`
and `localToolfsBytes`. Without the option the previous report is unchanged.
**Both forms retain `artifactReadiness=not_checked` and
`conformance=not_checked`.** Hashing bytes does not prove filesystem/member
semantics, dependency ABI, execution behavior, distribution or prewarm. A
publisher can sign broken bytes; guest/conformance gates must still refuse
those. Reports are byte snapshots, not leases on files or publisher policy.

`cargo run -p celln-cli --example prepare_review_fixture -- NEW_DIRECTORY`
creates a public deterministic fixture for Sympozium review tests. Its
filesystem is deliberately **non-executable**, with valid signed identities
and restricted schemas. The generator validates the schemas itself. Never
install its publisher as production trust or use this as a Ready fixture.

Without `--toolfs`, `scope=descriptor-authenticity-only`, `artifactReadiness=not_checked` and
`conformance=not_checked` are explicit. By default the command does not fetch or inspect
filesystem/member bytes, verify schema documents, approve behavior or lending
limits, distribute/prewarm artifacts, run a guest, grant invocation authority,
or write an admission store. The policy hash is a snapshot identifier, not a
lease or exemption from later revocation checks. A report is not signed and
must be obtained directly by a trusted verifier, not accepted from a tenant.

Catalogue readiness still requires independently trusted approval, exact
artifact and schema verification, adapter conformance, node eligibility and
prewarming. Guest isolation must still be proven by guest attempts. Existing
dispatch performs its own current-policy and filesystem/executable binding
checks; a successful offline report never bypasses them.

Tests use real Ed25519 signatures from a public deterministic test seed. They
cover tampering, identity/publisher/member mismatch, exact-byte identity,
revocation of every target type, missing/invalid/oversized policy, oversized
descriptor, read-only behavior and the real CLI exit/stdout contract. They do
not constitute KVM or full Harness/BYO-tool E2E evidence.

## Regression evidence — 2026-09-07

`CARGO_TARGET_DIR=target/deployed make ci` passed (format, all-target/all-feature
Clippy with warnings denied, build and workspace tests), including the actual
CLI verification test. The separate ignored `signed_closure_on_real_kvm` suite
then passed in 7.14 seconds with explicit build paths:

```sh
CARGO_TARGET_DIR=target/deployed cargo build --release \
  --target x86_64-unknown-linux-musl -p celln-pilot \
  --bin celln-pilot --bin pilot-fetch
CARGO_TARGET_DIR=target/deployed cargo build -p celln-cli
CELLN_TEST_BINARY="$PWD/target/deployed/debug/celln" \
CELLN_PILOT_DIR="$PWD/target/deployed/x86_64-unknown-linux-musl/release" \
CARGO_TARGET_DIR=target/deployed cargo test -p celln-cli \
  signed_closure_on_real_kvm -- --ignored --nocapture
```

The test helpers now accept those explicit paths instead of requiring the
default target directory. Initial attempts skipped on the hard-coded guest path
and then failed on the hard-coded dispatcher path; neither was counted as a
pass. The final run exercised the dynamic guest, replacement attempts, signed
member mismatch, publisher withdrawal, dependency revocation, live DAX
withdrawal, executable-scratch refusal, warm reuse and backing reclamation,
including production dispatcher HTTP receipt/audit checks. Local raw evidence:
`target/closure-proof/240005.json` and `target/closure-proof/240005/`.

Measured fixture executions: 2,779,841 µs initial preparation/execution,
133,335 and 141,610 µs warm executions. Eight simultaneous forks shared
33,554,432 sealed-tool bytes with zero additional tool allocations. These are
single-host fixture measurements, not full-Harness latency or fleet guarantees.

Tested dispatcher binary SHA256:
`e24a0cc3fd2efbcbb77149728de16d887b4338653ec90d2a0d1b6a5b97346cf9`.
The deployed Kubernetes cluster was not changed and no model credentials or
model calls were used. This rerun checks existing signed-closure behavior, not
the still-unimplemented catalogue approval/distribution user journey.
