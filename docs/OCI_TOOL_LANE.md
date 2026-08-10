# Any tool in a cell: OCI images as the tool lane

**Status:** proposal, with a working spike. Measured on real KVM hardware, 2026-08-10.

## The question

Celln can seal and attest any file. It can only *run* one shape of thing: a
statically linked musl binary that celln itself built. `celln agent` compiles
model-written Rust to static musl and runs that; `dispatch::launch` runs a
static binary resolved by hash from a mote bundle. Both seal exactly one file
to `/tools/program` and exec it once.

A real tool is not that shape. `python`, `curl`, and `node` are a binary plus a
loader plus a tree of shared objects. So the question this document answers is:

> Can a cell run a tool that is a *dependency closure* rather than a single
> static binary — without giving up the hardware seal?

The answer is yes, and the spike below does it: **Python 3.12.13, with its own
OpenSSL and glibc, running inside a real sealed KVM cell.**

## Why the obvious approaches fail

Three approaches were considered and rejected before landing on OCI. Each is
recorded because the reasons are not obvious and would otherwise be
rediscovered.

### 1. Borrow binaries from the host

The intuition is that a host already has the tools; lend them in. Measured on a
working developer machine:

```
ELF binaries in /usr/bin: 2064
statically linked:        3       (containerd-shim-runc-v2, tailscale, tailscaled)
```

All three are Go binaries. Of the tools anyone actually wants — `python3`,
`node`, `curl`, `wget`, `rustc` — every one is dynamically linked or a symlink.
The cell has no loader and no libc, so `execve` fails at the missing
`/lib64/ld-linux-x86-64.so.2` before the tool's own code runs.

**Detection was never the bottleneck.** Harvesting the host catalogue yields
essentially nothing usable, no matter how well the bytes are attested.

### 2. Let the cell reach host libraries for linking

If the binary is lent in but its `.so` files resolve on the host — via virtiofs
or 9p passthrough of `/usr/lib` — the linking problem disappears. So does the
security model:

- `curl` is ~1 MB of code against a **21 MB, 28-object closure**, so roughly
  95% of the code actually executing would sit outside the sealed memslot. The
  C1 claim ("a ring-0 guest with its own page tables cannot write lent tool
  code") would cover the smaller part.
- Hash-attestation collapses — a live filesystem view cannot be hashed the way
  sealed bytes can, and TOCTOU applies if the host tree changes.
- Revocation breaks: a memslot can be unmapped; an already-open fd cannot be
  un-read.
- The cell gains a full inventory of the host's library tree.

This is "give the agent a machine", which is the thing Celln exists not to do.

### 3. Broker the host binary

Have the cell ask the host to run the tool. This one is subtle, because **it is
already how Celln does egress, and it is correct there**: `pilot-fetch` sends a
URL over four I/O ports and `warden` runs `curl` on the host
(`egress.rs:100`).

What makes that safe is not the brokering — it is the *interface*. The cell
supplies a **URL**, not a command line, and the host applies:

- `--proto =https` (no `file://`, `scp://`, `smb://`)
- `--max-redirs 0` plus manual per-hop re-authorisation, because
  "`curl --location` would bypass the allowlist on hop two"
- `--resolve host:443:ip` — DNS pinned before connect, closing rebinding SSRF
- `is_public_v4` — private addresses never reachable
- bounded time, size, and a per-cell request budget

Six hardening measures for **one verb of one binary**. If the cell supplied its
own argv instead, every one becomes opt-out: `-o` writes host files, `-K` reads
them, `file://` exfiltrates, `--unix-socket` reaches host daemons, `--resolve`
overrides the pinning. The host becomes a confused deputy acting with host
authority for confined code.

**Rule: broker capabilities, never binaries.** `fetch(url)`, not `curl(argv)`.
Brokering is a good pattern that does not generalise to "run arbitrary tools".

## The approach: OCI images as a packaging format

An OCI image *is* a dependency closure — the exact artifact needed, produced by
an ecosystem that already solved building it, content-addressed by digest, with
an existing story for signing and provenance.

The critical constraint:

> **Docker is a build-time packaging format, never a runtime dependency.**

The image is resolved on the host at cell-construction time, exported to a
rootfs, built into a deterministic ext2 image, hashed, and sealed as read-only
pages. Nothing talks to a container runtime, and no container is ever started.
The guest does not know Docker exists. If instead the cell (or the host on its
behalf) talked to `docker.sock`, that is the confused-deputy problem again plus
a root-equivalent socket on every node — and namespace isolation is precisely
what this project defines itself against.

Use `skopeo`/`crane`, not the Docker daemon. Pulls need no daemon and no root.

### Pipeline

```
skopeo copy docker://img@sha256:…   →  layers
        └─ extract in manifest order →  rootfs
        └─ mke2fs -d (deterministic) →  ext2 image
        └─ blake3 + admit            →  manifest entry
        └─ seal as pmem window       →  KVM_MEM_READONLY memslot
guest:  mount DAX at /tools → pilot chroot()s in → execve
```

The existing `mktoolfs.sh` already builds the image with `mke2fs -d` from a
directory, so pointing it at an extracted rootfs changes its *input*, not the
pipeline.

## What the spike proved

All of the following was measured, not reasoned about.

**The closure is genuinely self-contained.** Chrooting into an extracted
`python:3.12-slim` rootfs on the host:

| | host (Fedora) | image (Debian) |
|---|---|---|
| python | 3.14.6 | **3.12.13** |
| openssl | 3.6.3 | **3.5.6** |
| glibc | 2.43 | **2.41** |

Three different stacks, through a loader inside the image's own tree. Nothing
resolved against the host.

**The image build is deterministic.** With a fixed UUID, fixed `hash_seed`,
`root_owner=0:0` and `SOURCE_DATE_EPOCH=0`, two builds of the same rootfs are
byte-identical. This is what the content-hash sharing story depends on: same
image → same blake3 → one physical copy across every cell that leases it, per
`one_physical_copy_serves_many_cells` (64 cells, one host allocation).

**A dynamically linked binary runs in a real sealed cell.** Alpine's busybox
(dynamically linked against musl), sealed as an OCI-derived ext2 image, mounted
DAX, chroot'ed into by pilot:

```
CELLN:pilot_run_/image/bin/busybox=permitted:tool
CELLN:out-begin
SEALED-OCI-OK
loader=/lib/ld-musl-x86_64.so.1
id=0
CELLN:out-end
CELLN:pilot_run_/image/bin/busybox_exit=0
```

**Python runs in a real sealed cell.** The headline result — a 138 MiB
`python:3.12-slim` image, sealed and executed on real KVM:

```
CELLN:out-begin
python   3.12.13
openssl  OpenSSL 3.5.6 7 Apr 2026
libc     ('glibc', '2.41')
sqlite   3.46.1
blake2b  75e7dc4be704b06ff906315f
json     {"sealed": true}
CELLN:out-end
```

**Per-cell scratch works and the seal holds.** A tmpfs mounted over the image's
`/tmp` is writable per cell; the sealed image itself is not, and the sealed
bytes stay intact under a write attempt.

**The VFS↔memslot join is closed for a real image — proven by revocation.**
This is the claim everything else depends on, and execution working does *not*
establish it: if the guest were reading a page-cache copy rather than the sealed
memslot, every test above would still pass, but each cell would hold its own
copy (destroying the one-physical-copy sharing story) and revocation could never
reach a running cell.

Tested behaviourally — read a file, print a marker, have the host delete the
memslot at exactly that point:

```
BEFORE=3.20.10            ← sealed file read fine
CELLN-REVOKE-NOW          ← host deletes the memslot here
traps: busybox[141] trap invalid opcode in ld-musl-x86_64.so.1
exit=-1                   ← killed mid-execution
```

The process was *executing* out of the sealed pages — its own dynamic loader's
text lived there — so deleting the memslot killed it mid-run. A page-cache copy
would have carried on. The kill wire reaches a running, dynamically linked
program, which is `init.c`'s stated claim now holding for real tools rather than
only for the probe fixture.

### Two pre-existing defects found in the proofs themselves

Both DAX proofs were **red on `main`** before this work, which meant the join
this feature rests on was unverified:

- `PROBE_MAGIC` went from `NOUSTOOL` (8 bytes) to `CELLNTOOL` (9) in the Celln
  rename, *and* its type was relaxed from `&[u8; 8]` to `&[u8]`. That single
  change turned two compile-checked lengths into runtime bugs: `probe_tool()`
  panicked copying 9 bytes into `t[..8]`, and the toolfs assertion scanned
  8-byte windows for a 9-byte needle so it could never match. Restoring the
  fixed-size type makes a future rename fail to *build* instead of on hardware.
- The prebuilt initramfs carried modules for an older kernel than the host now
  runs, so `nd_pmem` failed its vermagic check and no `/dev/pmem0` appeared.
  `make guest` fixes it, but the test silently breaks on **every host kernel
  update** — worth hardening with a staleness check.

## What the spike found broken

Four real defects, each of which would have been hit by any implementation.

### F1 — the tool window caps images at 32 MiB, and cannot simply be widened

`TOOL_WINDOW_SIZE` is 32 MiB, and `boot.rs` explicitly refuses a larger pmem
image. The window is a *hole punched in low RAM* at 96 MiB, with RAM mapped as
two memslots either side of it — so a bigger window pushes the window end above
`mem_size` and every cell must grow to match. Measured, with a 192 MiB window:

```
Backend("mem_size 268435456 must exceed the tool window end 0x12000000;
         RAM has to continue above the hole for the kernel to register it")
```

The stock 256 MiB cell fails to boot outright. **Fix:** relocate the tool window
*above* RAM so its size stops constraining guest memory. Only
`probe_sealed_tool`'s `/dev/mem` path depends on the hardcoded `TOOL_GPA`; the
real DAX path discovers the device from e820 and does not.

### F2 — sealed images mount read-write, so writes silently vanish — FIXED

`init.c` performs its read-only remount only *after* successfully opening
`/tools/probe` — a test fixture no real image contains. With a genuine image
`dax_open` fails, the function returns early, and the mount stays read-write
(`mounted filesystem … r/w without journal`).

The hardware seal still refuses the writes, so security holds. The *semantics*
are dangerous:

```
write exit code:        rc=0            ← reported success
does it appear to exist? -rw-r--r-- 1 root root 6 /bin/newfile
can we read back?        (empty)        ← data never landed
original file:           3.20.10        ← sealed bytes intact
```

The guest's in-memory inode cache fakes success. A tool that writes and reads
back gets **silent corruption with no error**. Worse, `init.c`'s own comment
records that a read-write DAX mount over a read-only memslot eventually makes
the writeback thread flush dirty pages into memory it cannot write and die with
an invalid opcode in `arch_wb_cache_pmem` — so a long-running tool does not just
corrupt, it can kill the guest.

**Fixed.** The unmount-and-remount-read-only step was extracted from the tail of
the probe into `remount_tools_ro()`, and the probe now returns whether it
mounted, so the remount runs on *every* path that got far enough to mount rather
than only the one where the fixture was found. Verified with a real image:

```
CELLN:dax_ro_mount=ok
sh: can't create /bin/newfile: Read-only file system        rc=1
sh: can't create /etc/alpine-release: Read-only file system rc=1
sealed file: 3.20.10     ← intact
tmpfs scratch: ok        ← per-cell writes still work
```

### F3 — image size must be 2 MiB-aligned

`nd_pmem` refuses a misaligned namespace:

```
nd_pmem namespace0.0: [mem 0x06000000-0x0e8b7fff] misaligned, unable to map
nd_pmem namespace0.0: probe with driver nd_pmem failed with error -95
```

`mktoolfs.sh` takes its size in MiB so it is aligned by construction; an
OCI-derived image is whatever size the rootfs needs and must be rounded up. In
ext2 terms with 4 KiB blocks, the block count must be a multiple of 512.

### F4 — file ownership is wrong

`mke2fs -E root_owner=0:0` sets only the *root inode*; every other file keeps
the uid of whoever extracted the tarball. Harmless while pilot runs as root and
files are `0755`, but wrong for setuid binaries and any ownership-sensitive
tool. **Fix:** extract inside a user namespace (or with `fakeroot`) so the
recorded ownership is correct.

## Design

### Surface

```toml
[[tool]]
image = "docker://python@sha256:229a2c5bfa27…"   # digest, never a tag
exec  = "/usr/local/bin/python3.12"
```

Adding a tool becomes naming an image. That is the whole user-facing change.

### Security model

- **Digest-pinned only; tags refused.** A tag is a mutable reference to
  third-party code that would carry tool-lane authority. `celln-spec` already
  enforces immutable references and has a test named
  `execution_request_rejects_a_mutable_ensemble_handoff` — this applies the
  existing rule rather than inventing one.
- **Tier ceiling is `Verified`.** A pulled image is bytes held, not built. Only
  a locally, reproducibly built image could earn `Forged`. The tier must not
  quietly overstate what happened.
- **Exec-by-hash still governs.** The spike admits the hash of the specific
  binary pilot is asked to exec, and pilot re-hashes it in-cell before running.
  A fuller design should additionally attest the image digest and layer digests.
- **Landlock scoping survives.** The existing rule — never grant the `/tools`
  directory, or the child could enumerate every host-lent tool — is *satisfied
  by construction* inside a chroot: the root is exactly the one image being
  lent, and a second image is a second mount the child never sees.
- **Third-party code is a real trust change.** "A binary the operator vouched
  for" and "whatever `python:3.12-slim` contains" are different claims. Digest
  pinning plus optional signature verification (cosign) at pull time is the
  mitigation, and the default should be deny-unpinned.

### Scaling: seal layers, not images

Many cells on the *same* image is already free — read-only pages are shared, and
DAX ensures the guest maps them directly rather than caching its own copy.

Many *different* images is the real cost. OCI already solves it: images are
layered and content-addressed, and derived images share base layers. Make each
**layer** its own sealed page-set keyed by its digest and base layers dedup
across every image that derives from them, composed in-guest with overlayfs
(read-only lowerdirs plus one tmpfs upper). The measured memslot budget is
32,762, so hundreds of layers is nothing.

`CONFIG_OVERLAY_FS` is a module on the host kernel the guest boots, so this
costs a `finit_module` (precedented — init.c already loads the nvdimm stack that
way) and inherits the vermagic coupling to the host kernel. Whole-image sealing
plus a tmpfs needs none of that, which is why it is step one.

### Least authority vs. hermeticity

Sealing a whole distro image to obtain one interpreter is hermetic but not
minimal. It remains categorically safer than host passthrough — every page is
sealed, hashed, and revocable — but "hermetic" is not "least authority", and
per-tool Landlock scoping stops being optional at this size.

## Sequencing

1. ~~**Decouple the read-only remount from the probe** (F2).~~ **Done.**
2. **Relocate the tool window above RAM** (F1). Nothing larger than 32 MiB
   ships without it.
3. **Image → sealed ext2 builder**: skopeo pull by digest, ordered extraction,
   2 MiB-aligned deterministic `mke2fs`, correct ownership (F3, F4).
4. **Spec/CLI surface**: `image =` + `exec =`, digest-only validation.
5. **Layer-level sealing and overlayfs composition**, once image count justifies
   the vermagic dependency.

## Reproducing the spike

```bash
cargo build --release --target x86_64-unknown-linux-musl \
  -p celln-pilot --bin celln-pilot --bin pilot-fetch

skopeo copy docker://docker.io/library/python@sha256:<digest> dir:./img
# extract layers in manifest order into ./rootfs, then:
SOURCE_DATE_EPOCH=0 mke2fs -q -t ext2 -b 4096 -d rootfs -F \
  -U <fixed-uuid> -E root_owner=0:0,hash_seed=<fixed-uuid> py.ext2 35328

CELLN_SPIKE_IMAGE=py.ext2 CELLN_SPIKE_ROOTFS=rootfs \
CELLN_SPIKE_EXEC=/usr/local/bin/python3.12 CELLN_SPIKE_MEM_MB=512 \
CELLN_SPIKE_ARGS=$'-u\n-c\nprint("hello")' \
cargo test -p celln-cli --bin celln -- --ignored --nocapture \
  a_dynamically_linked_tool_runs_from_a_sealed_oci_image
```

Note the python case needs `TOOL_WINDOW_SIZE` temporarily widened (F1) and
`CELLN_SPIKE_MEM_MB=512`; the alpine case fits the stock 32 MiB window
unmodified. The spike test lives in `crates/celln-cli/src/oci_spike.rs`.
