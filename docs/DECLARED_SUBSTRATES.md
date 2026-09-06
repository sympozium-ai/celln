# Declared static substrates

Declared dispatch consumes the exact hash-verified kernel, base initrd and tool
filesystem referenced by a bundle. It never chooses a host kernel or rebuilds
those artifacts. Forge dispatch remains a separate host-prepared path and does
not claim a declared mote identity.

## Trust root

The node operator provisions `trusted-motes.json` under the dispatcher's state
root, outside the content store and request body:

```json
{
  "apiVersion": "celln.dev/v1alpha1",
  "bundles": ["blake3:<64 hexadecimal characters>"]
}
```

No policy, malformed policy, or an unlisted bundle refuses. Provision this file
and its parent directory with write access restricted to the trusted operator
and daemon account. Obtain approved bundle hashes through the operator's
authenticated release channel; do not approve a hash merely because a caller
submitted it or the object store contains it. Removing a pin prevents future
launches; it is not fleet or in-flight revocation.

This is explicit local digest-pinned admission. It authenticates the entire
bundle transitively through the operator's trusted configuration, not through
publisher signatures. `sign_standin` is a recomputable consistency checksum,
not a signature. An embedded manifest inherits this bundle approval; it must
not be promoted to independent publisher authentication. The same policy model
must govern future closure admission; closure loading remains unsupported.

## Bundle format

```json
{
  "apiVersion": "celln.dev/v1alpha1",
  "format": "celln.warm-static-v1",
  "kernel": "blake3:<kernel hash>",
  "initrd": "blake3:<base initrd hash>",
  "toolfs": "blake3:<tool filesystem hash>",
  "invocation": {
    "alias": "/tools/program",
    "toolHash": "blake3:<static executable hash>"
  }
}
```

The descriptor and its three substrate objects live in the mote store; the
static executable also lives in the tool store. Hashes are of the exact bytes.
The tool filesystem exposes the executable at `/tools/program` in the guest,
regardless of the reporting alias. Pilot verifies the opened file against the
request's expected hash before execution, then applies the embedded manifest
and lane rules. Local revocations and agent/interpreter constraints can only
narrow the embedded grant.

The approved base initrd is an uncompressed newc archive containing init,
pilot, pilot-fetch, the reviewed manifest, and all modules needed by the pinned
kernel. It must provide a normal `/celln` directory and no symlink/hardlink
trickery involving `/celln/dispatch-warm`. The operator must review these properties
when approving the bundle, just as they review privileged init and pilot code.
This is trusted boot code, not an untrusted filesystem ingestion format.

Preparation appends a fixed `/celln/dispatch-warm` mode flag to the base initrd,
boots once with sealed tools and no egress grant, and parks at init's
`CELLN:mote=parked` boundary before pilot executes. Every execution forks this
template, including the first. Per-request JSON arrives after the fork through
PIO port `0x510`: four little-endian length bytes followed by at most 1 MiB of
data. The stream is host-owned and one-shot. Pilot revokes the I/O bitmap grant
before parsing or executing. No arguments, requested egress authority or output
from one cell are snapshotted for another. No executable, module or manifest is
overlaid. Future receipts should record the invocation digest too.

Use pilot dispatch protocol 4, which enforces `expected_hash`, implements the
warm invocation channel and acknowledges staged immutable inputs. Protocol 4
also applies explicit workspace confinement to every dispatcher lane. Pinning a bundle
asserts its pilot implements that protocol and its boot code preserves the
invocation seam. Host and pilot must be upgraded together. Legacy bundle
descriptors can still be inspected by `resolve-file`, but cannot launch without
this format and explicit approval. Output framing is not attestation against a
compromised approved kernel or deliberately malicious privileged tool.

## Evidence and remaining work

`cargo test -p celln-cli declared_substrate_on_real_kvm -- --ignored --nocapture`
proves a marker unique to the declared initrd, a guest refusal of a mismatched
tool, and invalid declared kernel refusal without host fallback. Ordinary tests
prove separate trust admission and preservation of local authority.

The process retains one warm template keyed by approved bundle hash and guest
RAM size. Different arguments share it; a different identity evicts it. Trust
policy, artifact integrity and local authority are rechecked even on cache hits.
Requests still pay for hash-verified store reads, and a cache miss pays for
preparation. Forge dispatch also prepares then forks, but its freshly generated
substrate may miss the cache; deterministic forge substrate reuse is not claimed.
The cache is not an aggregate memory scheduler (#5).

Cancellation/deadlines use the shared [execution control](DISPATCH_LIFECYCLE.md).
This does not complete the epic: full provenance, input providers and external
integration remain outstanding.
See [warm dispatch measurements](WARM_DISPATCH_MEASUREMENTS.md) for the current
end-to-end numbers and guest isolation proof.
