# Scoped framework native package

`scripts/package-framework-native.sh` builds and packages the native artifacts
used by the scoped receiver. It is an operator-only cold path: it does not read
provider or cluster credentials, contact a model, install authority, start a
cell, or create a run permit.

```sh
umask 077
CARGO_TARGET_DIR=/absolute/build-target \
  scripts/package-framework-native.sh /boot/OPERATOR_SELECTED_KERNEL \
  /absolute/new-package-directory
```

The command builds static `linux/amd64` Pilot, JSON one-shot adapter, enduring
turn worker, retained parent, and Unicode-aware uppercase JSON tool binaries.
It generates fresh Ed25519 seeds from `/dev/urandom` in memory and zeroizes
them; only public publisher keys and signatures are exported. Fresh signing
material intentionally gives each build new signed identities. Pinned source,
complete source-tree SHA-256, Cargo lock, executable, schema, closure,
filesystem, initrd, mote, and package hashes make every output byte reviewable;
`MANIFEST.blake3` covers every file except itself. The tree hash includes tracked
and untracked non-ignored source files, so a package built from an uncommitted
operator checkout does not pretend the base commit alone describes its source.

`sources/` contains the actual independently signed v1 source images and
descriptors. `artifacts/one-shot` and `artifacts/enduring-worker` contain real
v2 composed images whose embedded source graph is runtime-first and then the
independent uppercase tool. `artifacts/parent` is the actual independently
signed parent substrate. Every `mote.json` names the exact final image next to
it. The copied `authority/` tree contains content-addressed tools, closures,
motes and schema blobs plus the generated public publisher and mote policies.
Copying or merging that tree into a receiver is a separate reviewed privileged
operation; this command never touches an existing authority root.

`resources.yaml` contains two immutable `CellnRuntimeProfile` resources and one
`ClusterCellnTool`: `celln-json-one-shot`, `celln-json-enduring`, and
`uppercase`. The first profile supports both explicit model-free
`celln.json-direct/v1` and broker-backed `celln.json-tools/v1` construction;
the second supplies the same one-tool closure to enduring turns. The runtime
profile publisher is the runtime source publisher, the tool publisher and
closure are its independent source, and both profile motes name the actual
composed image.

`parent-request.json` is credential-free operator metadata for the native
scoped parent constructor. It carries fixed artifact identity and conservative
limits only. It deliberately contains no scope, run UID, incarnation, deadline,
permit, model route, token path, or request-specific authority.

Before any manual installation, compare `package.json`, verify
`MANIFEST.blake3`, verify every signed closure against
`authority/trusted-closures.json`, and verify every mote/closure/toolfs hash.
The package records `hardwareConformance=not_checked` and
`readiness=not_established`; only a later guest-executed KVM admission/smoke can
change those operational facts.
