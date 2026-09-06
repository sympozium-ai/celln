# Dispatcher execution results

The dispatcher determines success from pilot's observed exit status and the
host's run termination. An exit of zero with a complete report succeeds even
when the program is silent. Nonzero exits, signals, setup failures, pilot
refusals, watchdog timeouts and missing or ambiguous reports fail.

Output is collected independently. Failure output is retained up to the
request's byte limit. A successful silent execution has no output reference.
If nonempty output cannot be persisted, the execution is Failed with an
output-persistence reason; a storage error must not masquerade as a guest
exit error.

## Reporting and compatibility

Dispatcher-generated run requests opt into `report_output_limit`. Pilot
connects the workload's stdout and stderr to a pipe, substitutes read-only
`/dev/null` for stdin, and emits JSON frames prefixed `CELLN:dispatch=`.
Output frames contain byte arrays, so arbitrary bytes and marker-like text
cannot become pilot control messages by being printed. Pilot drains output
beyond the byte limit without forwarding it, allowing the process to exit.
Exactly one terminal frame reports exit code, signal, or pilot failure.

The dispatcher requires a protocol announcement immediately after the first
pilot startup marker, these frames, and a clean guest shutdown. A workload
cannot impersonate an updated pilot by printing an announcement later. Older pilot
assets without this protocol fail closed with a missing-report reason.
Install matching host and pilot assets together. Requests without the opt-in
retain the legacy console format used by the CLI. The public
`celln.dev/v1alpha1` receipt shape is unchanged: phase and the existing status
reason carry the corrected outcome; structured receipt provenance additions
remain tracked in #10.

This separates workload output from supervisor reports; it is not independent
attestation of a malicious privileged guest kernel or a trusted tool that
deliberately takes over its guest. Agent-lane requests explicitly narrow the
manifest lane, and existing artifact authorship/proofs survive dispatch.

## Proof

Build the static pilot binaries, then run:

```sh
cargo test -p celln-cli dispatch_outcomes_on_real_kvm -- --ignored --nocapture
```

The real guest probes cover silent success, output then nonzero exit, a signal,
forged markers, output beyond the limit, timeout, exec failure, preservation of
agent authorship and revoked-tool refusal. Ordinary host tests cover malformed,
duplicate and missing frames and output persistence failures. The hardware CI
job runs the guest proof when KVM is available.

## Supported request authority

The transport schema describes more authority than the runtime currently
delivers. Node admission, HTTP submission, direct bundle resolution and launch
refuse tool closures, multiple tools and input requests outside the bounded
provider described in [Dispatcher inputs](DISPATCH_INPUTS.md).
HTTP returns 422 with `reason: "unsupported"` and a diagnostic
before reserving capacity or starting model, store or VM work. The worker
also checks before forging, for callers that bypass HTTP. These are temporary
runtime restrictions, not removals from the versioned schema.

Receipts record input hashes only after host resolution and matching pilot
acknowledgement of staged bytes. Dispatcher workspace modes are now enforced
by Landlock, including truncation and execution denial; `none` grants no
filesystem workspace. This does not change the legacy CLI/closure policy.
Secret providers and live withdrawal remain in #7; closure loading remains in #6.

This completes the outcome and unsupported-input/closure refusal slices of #13.
Declared execution now forks an operator-pinned warm substrate with a separate
one-shot invocation channel; see [Declared substrates](DECLARED_SUBSTRATES.md)
for the trust root, compatibility requirements and exact artifact semantics.
Cancellation and end-to-end deadlines are described in
[Dispatcher lifecycle](DISPATCH_LIFECYCLE.md).
