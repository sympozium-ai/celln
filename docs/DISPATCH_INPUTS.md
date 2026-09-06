# Bounded dispatcher inputs and workspace authority

The static dispatcher supports up to 16 immutable named inputs, at most 65,536
bytes in total. It does not mount a caller's host path or accept a URL as a
provider. Input names are single lowercase ASCII components of 1–64 bytes,
using letters, digits, `.`, `_`, or `-`, excluding `.` and `..`.

## Host provisioning

The operator places input bytes in the content-addressed store under
`<state-root>/inputs` (the ordinary `objects/<prefix>/<digest>` layout) and
approves hashes in `<state-root>/trusted-inputs.json`:

```json
{
  "apiVersion": "celln.dev/v1alpha1",
  "hashes": ["blake3:<64-lowercase-hex-digits>"]
}
```

This is host-owned policy, not request-controlled configuration. A stored hash
is not permission. Missing/invalid policy, unapproved or missing objects,
corruption, mismatched byte counts and oversized requests refuse explicitly.
Reads are bounded before allocation. The policy is re-read for each execution,
including warm-cache hits; removing an approval prevents future deliveries but
does not withdraw bytes already lent to a running cell. Inputs are ordinary
data, not a secret-delivery mechanism. Secret leases and live withdrawal remain
unimplemented (#7).

An execution declares each input's `name`, `hash`, `mediaType`, and exact `bytes`,
and requests `read-only` or `read-write` workspace access. Inputs combined with
`workspace: "none"` are refused. Pilot receives verified bytes over the bounded
post-fork invocation stream, rehashes them, and creates fresh
`/celln/inputs/<name>` files. A pre-existing input directory fails closed rather
than mixing template data with requested data. No input bytes enter the warm
mote snapshot. Pilot reports the staged hashes before workload output; receipts
only retain hashes that exactly match the resolved request.

## Guest authority

Every dispatcher lane uses the same filesystem confinement. The lane still
records tool provenance; choosing the tool lane does not expand filesystem
authority. Only the verified executable and an explicitly lent `pilot-fetch`
helper receive executable access. Tool closures and multiple tools remain
unsupported.
The exact `/dev/null` node remains readable/writable for child-process standard
streams; this does not grant access to the console or other device nodes.

| Workspace mode | `/celln/work` | `/celln/inputs` |
| --- | --- | --- |
| `none` | No read/write grant; cwd `/` | Inputs refused |
| `read-only` | Read/list; no creation, write or truncate | Requested inputs read-only |
| `read-write` | Private scratch read/write/create/truncate | Requested inputs still read-only |

No mode grants execution from workspace or input paths. Root-wide reads,
device creation, and socket creation are not granted. Landlock ABI 3 is required
so truncation is mediated; a kernel unable to install confinement refuses
execution. These are guest-kernel-enforced workload restrictions, not a claim
that data in writable guest RAM has stage-2 sealing. Tool code retains the
separate stage-2 guarantee. Legacy non-dispatch CLI/image behavior is unchanged.

## Compatibility and evidence

Dispatcher host and pilot must use protocol 5 together. Repin/rebuild declared
bundles when upgrading from protocol 3/4; older reports cannot establish success.
Protocol 5 adds an acknowledged execution grant; see [audit](DISPATCH_AUDIT.md).
The invocation transport cap grows from 64 KiB to 1 MiB to accommodate JSON
encoding of bounded input bytes; the raw input budget remains 64 KiB.

Run `cargo test -p celln-cli declared_substrate_on_real_kvm -- --ignored --nocapture`
after building the static pilot binaries. The guest actually tries forbidden
reads, writes, truncation, rename/hard-link and execution; it also checks two
different inputs across forks of one warm mote. On 2026-09-06 this passed on
the development KVM host (Linux 7.1.12-200.fc44.x86_64, Rust 1.98.0) alongside existing substrate, isolation, cancellation,
deadline and mismatch probes. Host tests cover authorization, exact sizes,
missing/corrupt objects, path names and malformed input acknowledgements.
The strict helper probe also executes `pilot-fetch`, reaches the host broker,
and observes its refusal of plaintext HTTP without making an external request.
This is one part of #3/#7, not completion of the external integration epic.
