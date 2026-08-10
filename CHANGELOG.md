# Changelog

## 0.5.0

Celln could seal and attest any file, but only ever *run* one shape of thing: a
static musl binary it built itself. Real tools are not that shape — a `python`
is a binary plus a loader plus a tree of shared objects resolved by absolute
path, and on a working developer machine 3 of 2064 binaries in `/usr/bin` are
static. This release lends a tool's whole dependency closure instead, as a
sealed filesystem built from a digest-pinned OCI image.

### Breaking

- **`celln ask` is removed.** It sent a question to the configured model CLI on
  the host — no cell, no tools, no attestation. Use that CLI directly.
- **`Tool.path` is now optional.** A tool comes from exactly one of `path`
  (a static binary on this host), `image` + `exec` (a dependency closure), or
  `builtin = "fetch"`. Specs setting none, or more than one, are refused.

### Added

- **Images as tools.** `[[tool]] image = "python"` with `exec`, pinned by
  digest; tags are refused, because a moved tag would change what a cell is
  lent without the spec changing.
- **A tool catalogue**, compiled into the binary and refreshed by CI.
  `celln image add <image:tag>` resolves the digest, materialises the image,
  inspects it without mounting, and exposes what it finds. Hosts extend it at
  `<root>/tools.toml` without rebuilding; a local entry shadows a shipped one.
  Also `celln image pull|list|catalogue|spec|remove`.
- **`celln run` executes.** It previously sealed tools and dissolved without
  running anything.
- **Several images per cell.** Each becomes its own pmem namespace mounted at
  `/tools`, `/tools1`, …; tools naming the same image share its mount and its
  single physical copy.
- **Several invocations per cell** via `[[run]]`. `[run]` still takes one.
- **Brokered egress from a spec**: `[cell] allow_hosts` with a tool declaring
  `builtin = "fetch"`. The cell still has no network stack — the host performs
  the fetch, HTTPS only, DNS pinned before connect, each redirect
  re-authorised, size and time bounded.
- **`[agent]` blocks.** The spec keeps the policy — tools, memory, hosts — and
  a model fills in the program. `celln run --task` overrides the task;
  `celln agent --tool python "…"` does the same without a file.
- **`celln tools`** lists what the host has attested rather than a count.

### Fixed

- **The VFS↔memslot proofs were red.** The Celln rename widened `PROBE_MAGIC`
  from 8 bytes to 9 *and* relaxed its type from `&[u8; 8]` to `&[u8]`, turning
  two compile-checked lengths into runtime bugs. The join this design rests on
  was unverified.
- **Sealed images mounted read-write**, because the read-only remount sat
  behind an early return taken whenever a test fixture was absent. Writes
  returned success, appeared to create files, and landed nowhere.
- **A warm hit matched on alias, not content.** Two images can both claim
  `/bin/sh`; the host attested one image's bytes while the other's ran.
- **`Manifest::resolve_alias` returned revoked entries.**
- **Image sizing counted hardlinks repeatedly** — busybox links ~400 applets to
  one binary, so a 4 MiB rootfs was sized as ~400 MiB.
- **Scratch directories leaked per run** into `/tmp`, image-sized, and `/tmp` is
  a tmpfs on most hosts.
- **The tool window capped images at 32 MiB.** It is now sized to the image.
  Moving it above RAM does not work: pmem past `last_pfn` is parsed and then
  never registered, so no device appears.

### Known limits

Images are capped at 512 MiB; past roughly a gigabyte the guest panics in
`kernel_init`. `curl` deliberately cannot use the fetch capability — reaching it
through curl means brokering raw TCP rather than a validated URL, which discards
the DNS pinning and redirect re-authorisation that make it safe. File ownership
in built images is still the extracting user's, and cell scratch still lives in
`/tmp`. See `docs/OCI_TOOL_LANE.md`.
