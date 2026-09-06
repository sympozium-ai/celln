# Trusted precomposed closures

Issue #6 adds `celln.warm-closure-v1` alongside the unchanged
`celln.warm-static-v1` bundle format. A closure is an immutable ext2 image plus
an Ed25519-signed inventory/dependency graph. It is not an ambient host library
search path, an OCI tag, or a replacement for the operator's mote trust policy.

## Admission and composition

The publisher builds a self-contained filesystem offline, including the ELF
loader at its required absolute path and a real `/tmp` directory. Every runtime
file that the workload needs to read must be a member. Paths are canonical
absolute names; member paths and their parent components must not be symlinks.
This prevents pre-chroot verification and post-chroot loading resolving an
absolute symlink against different roots. Package real files at loader paths.
Dependencies refer to member paths, all are resolved, and every member must be
reachable from the entrypoint. Cycles are permitted. Limit: 256 members and a
256 KiB signed descriptor; the serialized invocation must additionally fit the
existing bounded PIO delivery channel.

Unsigned descriptor shape (replace the illustrative hashes):

```json
{
  "apiVersion": "celln.dev/closure-v1",
  "toolfs": "blake3:<64 lowercase hex digits>",
  "entrypoint": "/bin/program",
  "interpreter": false,
  "members": {
    "/bin/program": {
      "hash": "blake3:<program hash>",
      "dependencies": ["/lib64/ld-linux-x86-64.so.2", "/lib64/libc.so.6"]
    },
    "/lib64/ld-linux-x86-64.so.2": {"hash": "blake3:<loader hash>", "dependencies": []},
    "/lib64/libc.so.6": {"hash": "blake3:<libc hash>", "dependencies": []}
  }
}
```

Sign offline using a private, random 32-byte Ed25519 seed:

```sh
celln closure sign closure.json --key-file publisher.seed > signed-closure.json
celln --root /var/lib/celln closure admit signed-closure.json
```

Do not reuse the deterministic test keys. Signing emits only the descriptor,
public key and signature. The dispatcher never receives the private seed.
Signatures cover a domain-separated, deterministic serialization of every
descriptor field; strict Ed25519 verification rejects invalid/weak signatures.
Implementation: [ed25519-dalek 2.1.1](https://docs.rs/crate/ed25519-dalek/2.1.1).

The operator separately installs `trusted-closures.json` under the state root:

```json
{
  "apiVersion": "celln.dev/closure-policy-v1",
  "publishers": ["<64 lowercase hex public-key digits>"],
  "revoked": []
}
```

`closure admit` verifies that policy and stores the exact descriptor bytes in
`<root>/closures`. Its returned BLAKE3 hash becomes `tools[0].closure.hash`.
It does not install a trust root or claim the filesystem is already available.
The normal content stores must contain the program and bundle artifacts. Pin
the bundle in `trusted-motes.json` as before, changing only its `format` to
`celln.warm-closure-v1`; its toolfs and program hashes must match the signed
closure. The pinned initrd must contain the current pilot and an entry for the
program in its manifest. The guest manifest's legacy checksum is **not** the
publisher signature: publisher authentication happens on the host before fork.

Every launch rechecks publisher policy, descriptor integrity, signature,
filesystem identity, entrypoint identity and dependency revocation, including
warm-cache hits. A publisher can be withdrawn by removing its key. `revoked`
accepts closure-descriptor, filesystem or member hashes. Local manifest
revocation also wins. A locally agent-authored/interpreter dependency narrows
the whole invocation to the agent lane; a publisher-marked interpreter is always
narrowed. Policy changes govern new launches, not live fleet withdrawal (#8).

## What the cell receives

Preparation seals the exact composed filesystem and parks the mote. Every
execution forks that mote, including the first. Request arguments and the
authenticated member inventory arrive only after the fork. Pilot re-hashes
every actual member before executing the entrypoint by its verified descriptor.
The child's root is the single sealed filesystem. Landlock grants read/execute
only for the enumerated files; no root-wide read/execute grant is added.

Strict closure scratch is private tmpfs with `noexec,nodev,nosuid`, including
when workspace access is `none` or `read-only`. This matters because Landlock's
EXECUTE restriction alone does not stop `mmap(PROT_EXEC)` of a copied library.
Workspace access remains independently enforced by Landlock. Mount failure
refuses execution. Guest socket creation and capabilities remain restricted.

This version supports one precomposed closure for one invoked tool. Closure
requests with forge, inputs or egress refuse explicitly. Arbitrary distribution
images are not automatically admitted or granted root-wide access. Layer-level
deduplication, registry/cosign identity discovery, and automatic dependency
discovery are not claimed. Offline packaging may use OCI; dispatch never needs
a container runtime or a host library directory.

## Provenance, retention and collection

The execution audit's `execution.substrate.closure` records descriptor hash,
authenticated publisher, sealed filesystem hash, and member graph next to the
actual pilot verdict and receipt. The immutable `celln.dev/v1alpha1` receipt
schema is unchanged; its mote/tool hashes and cell ID correlate with that audit.
Neither the receipt nor the legacy guest manifest is advertised as a signed
publisher attestation. Preserve the audit when exporting execution evidence.

Live cells and parked motes hold strong handles to their shared sealed pages.
Warm-cache replacement collects page sets with no remaining live/template
owner; an active fork cannot lose its backing memory. Cold store objects are
retained, not automatically deleted. Offline disk collection must stop dispatch,
retain the operator-pinned bundles and their kernel/initrd/toolfs/program
objects, admitted descriptors plus audit-retained identities, and only remove
unreachable objects. Do not infer deletability from a publisher withdrawal:
historical audit retention may still need the bytes. There is intentionally no
online disk sweep racing active resolution.

## Proofs

`make conformance-kvm` includes a native dynamically linked Rust workload, its
loader/libc/libgcc closure, every workspace mode, guest code/library replacement
and executable-mapping attempts, member mismatch, invalid signature, publisher
withdrawal, dependency revocation, HTTP receipt/audit correlation, warm reuse,
shared allocation measurements for eight simultaneous forks, and collection
after eviction. It also reruns the existing static dispatcher suite.

Set `CELLN_SYMPOZIUM_PROOF` to the counterpart real-controller script to test
both static and signed-closure AgentRuns through isolated Kind, the production
controller, HTTP dispatch and real host KVM. No user Kubernetes context is used.
Measurements under `target/closure-proof` compare cold packaging/preparation,
warm execution, and shared sealed allocation sizes. These are reference-fixture
measurements, not a claim of whole-process RSS or general workload latency.
