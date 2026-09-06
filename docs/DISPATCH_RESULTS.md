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

This completes the outcome slice of #13. Declared substrate consumption,
unsupported input/closure authority, warm spawning and end-to-end cancellation
remain separate work in that issue.
