# Local tenancy prerequisite conformance

`make conformance-kvm` now builds the static native parent and JSON Harness in
addition to Pilot/fetch, creates its own JSON Harness package without model
calls, and executes five required real-KVM proofs in separate serial processes.
It requires readable/writable `/dev/kvm`; printed prerequisite skips and missing
case counts fail. It does not use model credentials or invoke external controller
hooks. Logs/results are retained beneath a new private `target/conformance-kvm.*`
directory. This is prerequisite substrate/legacy-admission proof, **not** the
new mediated multi-namespace admission/browser release gate.

The local run exposed two concrete problems:

- HTTP capacity reservation appeared before guest execution. The cancellation
  test's 300 ms delay was too short on this host. It now permits five seconds
  within the original 15-second bound, retaining the assertion that the actual
  terminal receipt contains guest output. Capacity visibility is not that proof.
- With umask 077, composed image directories inherited mode 0700 and confined
  guest execution failed with EACCES. The composer now sets image directories to
  0755 explicitly; the enclosing host output directory remains 0700 and lent
  executable files remain 0555. The closure fixture likewise specifies guest
  image modes rather than depending on host umask. No host isolation is relaxed.

Pilot failure frames now include only the bounded numeric OS errno, not guest
paths/arguments/content. This made the EACCES failure diagnosable. A failed proof
no longer poisons the global lock and obscures all subsequent proofs, because
they run in independent test processes. Failures still fail the complete target.

Executed evidence: `target/conformance-kvm.AwlqT6Qo/results.tsv` reports all five
required cases passed, with no skips: signed closures/guest replacement attacks,
native parent/retained context/revocation, declared substrate/HTTP cancellation,
dispatch outcomes, and native JSON Harness grant issuance. No real provider was
called. Follow-up Rust 1.95 `make ci` passed after semantics-preserving lint fixes
in schema validation, MMIO accounting and fetch-grant comparison. The earlier
parallel admission-test flake is not claimed fixed merely because this run passed.
