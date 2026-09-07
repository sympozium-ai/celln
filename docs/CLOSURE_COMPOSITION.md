# Signed-source filesystem composition

`celln closure compose` is operator-side packaging for the Harness/tool
catalogue integration. It does not admit, distribute, prewarm or certify a
selection, and is not yet connected to the high-level Sympozium picker.

A bounded JSON plan names exact descriptor-byte identities, runtime first:

```json
{
  "apiVersion": "celln.dev/composition-plan-v1",
  "sources": ["blake3:<runtime descriptor>", "blake3:<tool descriptor>"],
  "imageBytes": 33554432
}
```

Run with a trusted Linux filesystem builder and an independently authorized
composer key (exactly 32 raw private seed bytes):

```sh
celln --root /var/lib/celln closure compose plan.json \
  --key-file /secure/composer.seed --output-dir /var/tmp/new-composition
```

The destination must not exist. Sources are original signed closure-v1
descriptors in the root's `closures` store. Every member must be present by
content hash in its `tools` store. All source publishers and the composer must
be allowed by the current `trusted-closures.json`; revoked inputs refuse.
No source executable runs, input filesystem is mounted, or host library is
implicitly imported. Shared paths must agree in both bytes and dependency
edges; selected entrypoint collisions and file/directory collisions refuse.
`/tmp` and `/lost+found` are reserved. The combined interpreter flag cannot be
downgraded.

The resulting `toolfs.ext2` contains the union of those exact members, and
`signed-closure.json` authenticates a closure-v2 graph retaining the exact
signed source descriptors. Verification independently checks source publishers
and source descriptor/filesystem revocations, as well as final image, member
and descriptor revocations. A composer signature cannot replace source trust.
Original v1 signature encoding remains unchanged. Nested composition is not
accepted: source count is bounded to one runtime plus at most 16 tools, the
combined graph to 256 members, and the signed descriptor to 256 KiB.

Image size is 32–512 MiB, aligned to 2 MiB. The builder has a 45-second deadline
and bounded output. Source bytes have an aggregate image-size-minus-8-MiB cap;
filesystem overhead can still cause an explicit build failure. Graph
composition is deterministic; ext2 byte reproducibility is **not claimed**.
Policy is rechecked before publishing the descriptor, with policy changes
refused. Failed builds may leave an explicitly named output directory for
diagnosis, but no artifact is automatically admitted. Temporary member staging
is removed on normal return or error.

The report explicitly says `artifactReadiness: not_checked` and
`conformance: not_checked`. Source filesystem provenance is retained, but this
command does not prove that original source filesystems matched their member
graphs. Sealed guest member verification, runtime/tool functional conformance,
distribution, serving-process prewarm and request-specific grants remain
separate mandatory checks before execution. Neither a successful build nor
an approved catalogue record is permission to execute a composition.

## Dispatch and validation

The JSON Harness contract accepts v2 only when the ordered source roots match
the runtime and every explicitly selected tool. The runtime source must include
`/pilot-fetch`. Shared signed dependencies do not become entries in the model's
callable tool list. The reference contract retains its static member restriction;
interpreter closures remain unsupported by Harness dispatch. Exact host grants
and the existing sealed execution gate still apply.

Portable tests cover conflicting members/graphs, source order, omitted tools,
publisher/source/filesystem/member withdrawal, v1 encoding compatibility, and
an actual ext2 build. The explicit `signed_closure_on_real_kvm` test additionally
feeds a signed dynamic closure through the compositor CLI, checks its generated
image's members inside a sealed cell, executes the dynamic program with guest
mutation attempts, and refuses a subsequent run after source revocation. This
is a compositor/dynamic-execution proof, not a catalogue-backed model journey.

```sh
CELLN_TEST_BINARY=/absolute/path/to/built/celln \
CELLN_PILOT_DIR=/absolute/path/to/static/pilot/binaries \
  cargo test -p celln-cli signed_closure_on_real_kvm -- --ignored --nocapture
```
