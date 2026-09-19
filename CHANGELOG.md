# Changelog

## [0.5.22](https://github.com/sympozium-ai/celln/compare/v0.5.21...v0.5.22) (2026-09-19)


### Features

* **dispatch:** read-only GET /v1/cells listing on dispatcher and router ([aef410e](https://github.com/sympozium-ai/celln/commit/aef410eb4af05494b610e61f2f4db860489d940a))
* **dispatch:** read-only GET /v1/cells listing on dispatcher and router ([30ddfad](https://github.com/sympozium-ai/celln/commit/30ddfadeae4a5300ac74333a110bbdbe6cce2676))
* **parent:** keep long conversations alive and widen the turn bounds ([504dfa2](https://github.com/sympozium-ai/celln/commit/504dfa2d0395b3a1c5e6afcf0f5532d753ab3ed2))
* **parent:** keep long conversations alive and widen the turn bounds ([7d61d37](https://github.com/sympozium-ai/celln/commit/7d61d3774a5ee50da70738a9720009180e2392f0))

## [0.5.21](https://github.com/sympozium-ai/celln/compare/v0.5.20...v0.5.21) (2026-09-17)


### Bug Fixes

* **parent:** keep parents alive across long worker turns ([daeef20](https://github.com/sympozium-ai/celln/commit/daeef204ba07d578defd2382e4df8447be9d94d2))
* **parent:** keep parents alive across long worker turns ([cdb82e5](https://github.com/sympozium-ai/celln/commit/cdb82e567e605975908009533cda64a289dcbf63))

## [0.5.20](https://github.com/sympozium-ai/celln/compare/v0.5.19...v0.5.20) (2026-09-15)


### Bug Fixes

* **starter:** look for packaging tools under sbin too ([fa70d12](https://github.com/sympozium-ai/celln/commit/fa70d12d27b56a148ef2c215fe60e568008a31c5))
* **starter:** look for packaging tools under sbin too ([3ca6b80](https://github.com/sympozium-ai/celln/commit/3ca6b806a8228bd4d2cdffd0bb3e3ad512ad5435))

## [0.5.19](https://github.com/sympozium-ai/celln/compare/v0.5.18...v0.5.19) (2026-09-15)


### Features

* **harness:** 32 KiB model request wire budget for two dozen tools ([0063841](https://github.com/sympozium-ai/celln/commit/0063841dfcaf6e526213bc5309bb7ae6dce4c5a3))
* **starter:** workspace list/append/search/delete and credential-free JSON POST tools ([4dc50b9](https://github.com/sympozium-ai/celln/commit/4dc50b91974f6f042d1fa5f9b929bd31d83c30c9))
* **starter:** workspace list/append/search/delete and credential-free JSON POST tools ([cad57b3](https://github.com/sympozium-ai/celln/commit/cad57b363d10ecdd587067016597c6a3cf2706cf))


### Bug Fixes

* **vmm:** buffer 32 KiB broker requests from a cell ([1ba40eb](https://github.com/sympozium-ai/celln/commit/1ba40ebf488c766cc6aee170c66452fc2b594a85))

## [0.5.18](https://github.com/sympozium-ai/celln/compare/v0.5.17...v0.5.18) (2026-09-15)


### Features

* **tools:** borrow real commands from pinned images as argv tools ([b16db8a](https://github.com/sympozium-ai/celln/commit/b16db8ac628db33c339ecff4464f0b4d5fdf440d))
* **tools:** borrow real commands from pinned images as argv tools ([4c90df5](https://github.com/sympozium-ai/celln/commit/4c90df5268d23db391f32859c6795738b1992e1b))

## [0.5.17](https://github.com/sympozium-ai/celln/compare/v0.5.16...v0.5.17) (2026-09-14)


### Bug Fixes

* **parent:** a failed child is a failed turn, not lost parent context ([5ebbcfb](https://github.com/sympozium-ai/celln/commit/5ebbcfb8291dba0a4760fafa54912c73e44d6966))
* **parent:** a failed child is a failed turn, not lost parent context ([6d04a99](https://github.com/sympozium-ai/celln/commit/6d04a9945e51c0c97c8f4b171799d17689365759)), closes [#124](https://github.com/sympozium-ai/celln/issues/124)

## [0.5.16](https://github.com/sympozium-ai/celln/compare/v0.5.15...v0.5.16) (2026-09-14)


### Features

* **router:** place new parents on the owner with the most spare capacity ([8d515bd](https://github.com/sympozium-ai/celln/commit/8d515bd8cfdcc665a4fdfabbcfe1fc8a3ab76d40))
* **router:** place new parents on the owner with the most spare capacity ([38e5d14](https://github.com/sympozium-ai/celln/commit/38e5d147144db3640cad9639cd02f0e52cea0b44))

## [0.5.15](https://github.com/sympozium-ai/celln/compare/v0.5.14...v0.5.15) (2026-09-14)


### Features

* **starter:** operator host limits — lease up to 24h, turn and token ceilings per plan ([c922759](https://github.com/sympozium-ai/celln/commit/c922759c9923e930f9c950112cad6232e4c90ea6))
* **starter:** operator host limits — lease up to 24h, turn and token ceilings per plan ([74817f1](https://github.com/sympozium-ai/celln/commit/74817f1d32852c261691883cc0eb43162496ef59))

## [0.5.14](https://github.com/sympozium-ai/celln/compare/v0.5.13...v0.5.14) (2026-09-14)


### Bug Fixes

* **egress:** accept Anthropic thinking blocks without forwarding them ([bbfab46](https://github.com/sympozium-ai/celln/commit/bbfab4653253a0a55985d19da8c462bad1924de6))
* **egress:** accept Anthropic thinking blocks without forwarding them ([a8c8682](https://github.com/sympozium-ai/celln/commit/a8c8682d929bbbdd28220242125340836a840d02))

## [0.5.13](https://github.com/sympozium-ai/celln/compare/v0.5.12...v0.5.13) (2026-09-14)


### Bug Fixes

* **dispatcher:** bound model requests by the turn deadline instead of a fixed 45 seconds ([24b30c0](https://github.com/sympozium-ai/celln/commit/24b30c000a363dc9d227c9f074d0a76dad9eb024))
* **dispatcher:** bound model requests by the turn deadline instead of a fixed 45 seconds ([7be438c](https://github.com/sympozium-ai/celln/commit/7be438c08fee16805cfbb1d1a4f4c101db612591))

## [0.5.12](https://github.com/sympozium-ai/celln/compare/v0.5.11...v0.5.12) (2026-09-14)


### Bug Fixes

* **dispatcher:** charge exact broker slots per parent so a node holds more than one parent ([a1aa888](https://github.com/sympozium-ai/celln/commit/a1aa88808ad9970f7a48c2e5150ed59a0e763c00))
* **dispatcher:** charge exact broker slots per parent so a node holds more than one parent ([2341461](https://github.com/sympozium-ai/celln/commit/2341461a3d06b06d38aaca8a71f7fb36a2bca3f2))

## [0.5.11](https://github.com/sympozium-ai/celln/compare/v0.5.10...v0.5.11) (2026-09-14)


### Features

* **parents:** provision on the owning dispatcher; router binds affinity at provisioning ([#109](https://github.com/sympozium-ai/celln/issues/109)) ([bd17846](https://github.com/sympozium-ai/celln/commit/bd1784618ba011cddba4f559f80fb45437949539))
* **router:** re-resolve --backends-srv so owners can join or leave live ([#110](https://github.com/sympozium-ai/celln/issues/110)) ([4c08bcd](https://github.com/sympozium-ai/celln/commit/4c08bcdba1e50df8d0227a8925651367445592a0))

## [0.5.10](https://github.com/sympozium-ai/celln/compare/v0.5.9...v0.5.10) (2026-09-11)


### Features

* **router:** route /v1/parents with durable parent affinity; dispatcher drain ([#103](https://github.com/sympozium-ai/celln/issues/103)) ([f5403e5](https://github.com/sympozium-ai/celln/commit/f5403e507748985de740febd2e1b98c65461ae97))

## [0.5.9](https://github.com/sympozium-ai/celln/compare/v0.5.8...v0.5.9) (2026-09-11)


### Features

* **egress:** opt-in HTTP and self-signed model endpoints ([#101](https://github.com/sympozium-ai/celln/issues/101)) ([ccc6367](https://github.com/sympozium-ai/celln/commit/ccc63677643653e0687b139a5c48188df2802c1c))

## 0.5.8

### Added

- Native persistent Harness parents with disposable per-turn cells, bounded
  host-model access and explicitly borrowed workspace read/write and HTTPS tools.
- Operator-signed starter packaging, hardware admission and reviewed configuration
  commands. Linux amd64 archives now include the native parent, turn worker and
  starter tool binaries; a matching versioned router/provisioner image is published.

### Fixed

- Preserve execution ownership and receipts across authenticated router restarts.
- Confirm crashed native-owner cleanup from its recorded prelaunch process identity
  without replaying work or claiming restored context.

### Limits

- Persistent means live context, not crash recovery. Parent loss loses volatile
  context/files; old journals and host reboot cases remain conservatively fenced.
- Native starter support is Linux amd64/KVM only. Python, shell, arbitrary OCI
  Harness compatibility, checkpoints and pause/resume are not included.

## 0.5.7

### Added

- **Runs can declare an explicit environment.** `[run.env]` and `[agent.env]`
  pass a reviewed map to the workload after it enters its sealed image. The
  map is the complete workload environment: Celln never inherits ambient host
  variables into a cell.

### Fixed

- **OCI tools that require runtime environment variables can now run.** A
  trimmed Go distribution, for example, can declare
  `GOROOT = "/usr/local/go"` rather than failing because pilot previously
  launched every workload with an empty environment.

## 0.5.6

### Added

- **`celln agent` now runs a declared agent spec directly.**
  `celln agent cell.toml --prompt "…"` keeps the spec's policy and overrides
  its prompt, while `celln agent "…"` remains the inline form. This makes the
  agent entry point consistent whether policy lives in a file or in memory.

### Changed

- **Provider input is now called a prompt.** New specs use `[agent].prompt`
  and the CLI uses `--prompt`, which says what the value is instead of calling
  the same thing a task in the cell. Existing `[agent].task` and `--task`
  spellings remain accepted for compatibility.

### Fixed

- **A provider prompt could be silently ignored for a static spec.** Passing
  `--task` to a `[run]` spec used to execute its pinned empty or static argv;
  it now refuses and explains that a prompt requires `[agent]`.

## 0.5.5

### Added

- **A spec can now ask a provider to supply arguments for any declared tool.**
  `[agent]` no longer requires an interpreter: when its `exec` names one, the
  provider writes a program as before; otherwise it writes a JSON argv for the
  named tool. This makes a declared non-interpreter such as `curl` usable from
  a reviewed task spec. The CLI warns that model-authored argv retains the
  tool lane; use `[run]` to pin an invocation without a provider.

### Fixed

- **A cell could boot without `pilot` and then execute nothing.**
  `mkinitramfs.sh` previously printed that the guest supervisor was skipped
  yet returned success, leaving the useful cause buried behind a later
  `pilot=absent` guest report. Launch now checks that static guest assets can
  be packaged or the musl target can build them; the initramfs builder fails
  directly otherwise. Runtime setup also refuses to package a host-native
  `pilot`, since the stripped guest has no host dynamic loader.

- **Publishing a crate before a sibling it depends on silently shipped a
  version that cannot be installed.** Cargo resolves a requirement to the
  newest version satisfying it, so a dependent published ahead of its
  dependency does not fail — it succeeds, and breaks for whoever runs
  `cargo install`. Every inter-crate requirement was pinned at `0.5.0` while
  the workspace was four releases past it, which made this reachable at any
  time; 0.5.4 came within one command of it, with `celln-cli` calling a
  `celln-spec` function that published `celln-spec` did not have.

  Requirements now track the workspace version exactly, so a missing sibling
  is a publish-time refusal instead. They live in `[workspace.dependencies]`
  so there is one place to move them, `scripts/release.sh --bump` moves them
  with the version, and `--check` fails if one drifts — which ci runs on
  every PR. `--publish` derives its order from the dependency graph and waits
  for each crate to reach the index before the next.

### Changed

- **`celln agents` is now `celln providers`.** Those entries are inference
  backends — who *writes* a program — while "agent" already names what runs
  inside a cell and the lane it runs in. One word for both invited exactly the
  wrong reading of `celln agents`, which lists neither agents nor anything to
  do with the agent lane. `celln agent` is unchanged, and so is the `[agent]`
  spec block.

  Nothing breaks. `celln agents` still works as a hidden alias, `--agent`
  remains an alias for `--provider`, and `CELLN_AGENT` is still read
  (`CELLN_PROVIDER` takes precedence). The saved default moves from `[agent]`
  to `[provider]` in `config.toml`; an existing file is still read, and is
  rewritten to `[provider]` the next time the default is set.

  `--json` event names are deliberately unchanged — they are a machine
  contract, and renaming them belongs with a deliberate decision about
  consumers rather than riding along with a wording fix.

- The README's spec example moved below installation, so the page reads
  one-liner, what it is, install, then the durable form.

## 0.5.4

### Changed

- **Naming a tool the host does not have now says how to get one.** `celln
  agent --tool go` listed what was available and stopped there, which tells
  you the command failed but not what to do about it. It now gives the
  `celln image add` line, including the `--name` form for when a tool is
  published under a different name than you call it — `go` lives in `golang`.

- **Being told a tool cannot run model-written code now says why, and what
  to use instead.** The old message named a missing `language` and
  `code_flag` without explaining that `--tool` needs an interpreter taking a
  program on a flag, which plenty of useful tools have no reason to do. It
  now points at `celln image spec NAME`, which is how those are lent.

### Fixed

- **`celln image add` produced entries that `celln agent --tool` then
  refused.** It wrote `interpreter` but never `language` or `code_flag`, so
  adding an interpreter and immediately using it failed on a field the user
  was never told to write. A recognised interpreter now records the flag it
  takes code on, and adding one is enough to use it.

- **The weekly digest refresh could not have worked.** It exists so a moved
  upstream tag arrives as a reviewable PR rather than silently at pull time,
  and it had never run its own body — it is gated on a digest having moved,
  and none had. Three faults, which only made sense to fix together:

  - Its one verification ran `cargo test -p celln-cli --lib catalogue`, and
    `celln-cli` has no library target, so the command errors instead of
    running the tests. That step failing is the only thing that would have
    stopped the next two from reaching a pull request.
  - A registry answering with something that is not a digest — an empty
    string on a hiccup, `unauthorized` on a rate limit — was pinned verbatim,
    producing `ref = "docker.io/library/python@"`. No pull can satisfy that.
  - Stripping the tag off a reference ate the port of any registry that has
    one, turning `reg:5000/team/tool:v1` into `reg`.

  The refresher is now `scripts/refresh-tool-digests.sh` rather than a block
  of YAML, so it can be run and tested without a registry. Its `--self-test`
  stubs skopeo and covers all three, and runs in ci on every PR — the point
  being that weekly-only code is otherwise tested exclusively in production.

## 0.5.3

### Fixed

- **`celln image pull python` failed on a fresh store**, so a new install could
  not materialise the flagship tool. Every file occupies whole blocks, and
  `python:3.12-slim` is mostly small stdlib files, so summing file sizes built
  an image too small to hold its own contents: `Could not allocate block in
  ext2 filesystem`. Sizing now counts blocks and directories.

  A regression from 0.5.1. Deduping hardlinked inodes was correct — `mke2fs -d`
  preserves hardlinks — but it tightened the estimate enough to cross the line.
  Hosts that already had the image were unaffected.

- **A failed image build left a partial filesystem behind**, which `image list`
  reported as materialised and a spec could have sealed. It is removed on
  failure, and mke2fs's own error is surfaced rather than a generic one.

- **`celln setup` skipped tool images when no agent CLI was present**, returning
  before it reached them. Which model writes code has nothing to do with which
  tools a host can lend; the two are now independent, and the exit code still
  reports the missing backend.

- **A Kubernetes node never got its tool images.** The installer runs setup in
  the host namespace, where there is no skopeo. Agent config and runtime assets
  are now installed there with `--no-tools`, and images are materialised from
  inside the installer container — which carries skopeo — into the host store
  over the existing `/host` mount.

## 0.5.2

### Security

- **A declared interpreter could be ignored, running agent-authored code in the
  tool lane.** The laundering ban turns on `Entry::interpreter`, and
  `Assayer::resolve` used the caller's declaration only when admitting bytes it
  had not seen. On a warm hit it returned the stored entry and discarded the
  declaration — so if any spec had admitted a tool as a plain binary, every
  later spec that correctly marked it an interpreter was ignored, and
  agent-authored input ran with full tool-lane authority. Nothing warned.

  Interpreter-ness now only ever tightens: declaring it re-admits before
  anything runs, and declaring `false` cannot loosen an entry already marked.
  It is a property of the bytes, not of whoever admitted them first.

  Affects 0.5.0 and 0.5.1, and only a host whose store already held the tool
  as a non-interpreter — a fresh store admits the declared value correctly.

## 0.5.1

### Fixed

- `celln image list` showed a bare sha256 per image, which identifies nothing
  a person is trying to recall. It now shows the name the image was pulled
  under, its size, a shortened digest and the tag it was pinned from. An image
  whose catalogue entry has gone shows as `(untracked)` with its digest, so it
  can still be identified and cleaned up. JSON keeps the full digest and gains
  the name and tag.

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
