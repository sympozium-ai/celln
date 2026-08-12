# Changelog

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
