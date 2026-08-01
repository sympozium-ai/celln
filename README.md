# nouscell

**Nouscell** ( _NOWSS-cell_ ) — an agent-native operating system: a tiny, fast,
hardware-isolated **cell** that intelligence is launched into, where every tool
is attested memory the host lends in and can revoke in microseconds.

> This repository is the **proof-of-concept**. It builds the trust core and the
> control-flow of the full design in Rust, and demonstrates the five-beat proof
> loop end-to-end in a **mock backend that runs on any host** — no KVM required.
> With the `kvm` feature on a host with `/dev/kvm`, **M1 and the sealing half of
> M2 are real**: the cell is a genuine microVM (CoW-forked from a warm template),
> tool pages are sealed read-only at stage-2, and revocation unmaps pages from a
> running cell. **Claim C1 is proven** — a guest that enters protected mode and
> maps the sealed page writable *in page tables it wrote itself* still cannot
> write it. Run `make demo-kvm`, `make test-kvm`, `make bench-kvm` to see the
> hardware say no and to reproduce the numbers. Remaining hardware work
> (stripped mote kernel, the VFS↔memslot join, vsock, guest userland) is in
> `docs/NOUSCELL_BUILD_PLAN.md`; the open risk is recorded in
> `docs/findings/m2.md`.

Rust for code · Make for orchestration · shell for glue.

---

## Quickstart

```sh
make doctor    # check host readiness (mock runs anywhere)
make build     # build the workspace
make test      # run the unit tests
make demo      # run the five-beat proof loop (mock, any host)
make test-kvm  # run warden's hardware tests on REAL KVM (needs /dev/kvm)
make demo-kvm  # run the five-beat proof on REAL KVM (needs /dev/kvm)
make bench-kvm # measure the M1/M2 gates -> bench/results/ (needs /dev/kvm)
make boot-kvm  # boot a STOCK kernel + prove the VFS<->memslot join by file path
               #   (needs /dev/kvm, gcc, cpio, e2fsprogs)
```

## Measured on real hardware

`make bench-kvm`, x86_64 / kernel 7.1 / VT-x — raw JSON in `bench/results/`.
Latency moves with host load; ranges span observed runs on a busy workstation.

**Spawning a real cell** — a stock Linux kernel booted once, parked, and forked.
This is the design's central claim and the number that matters:

| Gate | Measured | Target |
|---|---|---|
| cells reaching userspace, having booted nothing | 50 / 50 | all |
| **spawn → userspace work, p50 / p99** | **6.3 ms / 9.4 ms** | **p99 < 5 ms — ✘ MISSED** |
| the CoW fork itself | 36 µs | — |
| booting the same guest instead | 4,175 ms | — |
| speedup of forking over booting | **663×** | — |

The mechanism is validated; the latency gate is not met, and neither pooling nor
pre-faulting closes it. The cost is the guest re-faulting its working set after
resume. Full analysis, including three negative results and what they imply for
the mote kernel: **`docs/findings/m1-spawn.md`**.

**VMM overhead floor** — forking a 16 KiB hand-assembled guest. Useful as a
lower bound on the VMM's own cost; *not* a spawn time, and previously reported as
if it were:

| | Measured | |
|---|---|---|
| concurrent toy cells, all reaching guest instructions | 1000 / 1000 | ≥ 1000 |
| toy fork latency p50 / p99 | 184–630 µs / 0.5–3.2 ms | p99 < 5 ms |
| private RSS per idle toy cell | 0.26 KiB | — |

**Sealing and revocation** (claim C1 and the kill wire):

| Gate | Measured | Target |
|---|---|---|
| 1 MiB tool across 500 cells | 1 physical copy, 71× saving | ~one copy |
| revocation across 200 running cells | 7.5–24 ms (37–118 µs/cell) | < 1 s |
| sealed memslots per VM (KVM's real limit) | 32,762 | — |
| private RSS per live real cell | 7.4 MiB | — |

## What's real vs stubbed

| Piece | Status | Where |
|-------|--------|-------|
| Content-addressed store (put/get by BLAKE3, dedup, integrity-checked reads) | **real, tested** | `crates/nous-store` |
| Manifest: exec-by-hash gate, revocation, stand-in signing | **real, tested** | `crates/nous-manifest` |
| Taint lanes + the laundering ban (incl. `python -c` arg-string channel) | **real, tested** | `crates/nous-manifest`, `crates/pilot` |
| Tiered resolution (warm → Verified → Forged async upgrade) | **real, tested** | `crates/forgectl` |
| Authority ratchet (P1→P2→P3, host-enforced, monotonic) | **real, tested** | `crates/warden` |
| VMM behind a trait; mock backend | **real, tested** | `crates/warden` (`vmm.rs`) |
| Real KVM backend: CoW fork, stage-2 read-only tool sealing, live unmap revocation, dissolve freeze | **real, hardware-tested (M1)** | `crates/warden` (`vmm/kvm.rs`, feature `kvm`) |
| Sealing vs. a guest with its own page tables (claim C1); one shared copy per tool hash | **real, hardware-proven (M2 sealing half)** | `crates/warden` (`vmm/kvm.rs`), `docs/findings/m2.md` |
| Stock Linux kernel boots on the substrate, to real guest userspace, with a sealed tool region in its address space | **real, hardware-tested** | `crates/warden` (`vmm/boot.rs`), `guest/init/init.c` |
| Guest userspace maps a sealed tool, executes out of it, and cannot modify it | **real, hardware-proven** | `vmm/boot.rs` tests, `guest/init/init.c`, ADR-0005 |
| **VFS↔memslot join**: guest `open()`s a tool by path under DAX and gets the sealed pages, not a copy | **real, hardware-proven** | `vmm/boot.rs` tests, `scripts/mktoolfs.sh`, ADR-0005 |
| Hermetic build farm (real forging) | **simulated** | `forgectl::Forge::run_one_rebuild` |
| Per-tool granularity through the DAX path (currently the unit is the filesystem image) | **not started** | ADR-0005 |
| Stripped mote kernel, vsock transport, guest musl userland | **not started** | build plan M5 |

The proof guests are hand-assembled real-mode / 32-bit programs (no kernel yet),
so only tools mapped in the low 64 KiB are reachable by them; the sealing
mechanism is size-independent and is the same one a real mote kernel will live
under. Everything the backend can't do is an `Unsupported` error, not a fake.

## Layout

```
crates/
  nous-manifest/   shared types: Hash, Tier, Lane, Manifest, laundering ban
  nous-store/      content-addressed store (the on-disk half of forgectl)
  forgectl/        fleet daemon: tiered resolution + CLI  (where the distro lives)
  warden/          per-cell VMM: ratchet + VMM trait + mock/kvm backends + Linux boot
  pilot/           in-cell supervisor: exec-by-hash, lanes, explain + the demos
guest/init/        freestanding guest init (no libc) for boot testing
docs/              design corpus (proposal, build plan, conventions, diagrams)
  decisions/       ADRs · findings/  milestone verdicts
bench/results/     committed measurements
scripts/           doctor.sh, demo.sh, mkinitramfs.sh
```

## Vocabulary

- **mote** — the substrate at rest (stripped kernel + `pilot`). The seed.
- **cell** — a live, sealed, tool-loaned mote. The seed put to work. *Every cell is a sealed mote.*
- **forgectl / warden / pilot** — host daemon / per-cell VMM / in-cell supervisor. 1 warden : 1 microVM : 1 cell.

Full glossary: `docs/NAMES_AND_CONVENTIONS.md`.

## Status

Pre-alpha, single-host. Working name pending trademark/domain clearance.
**Claim C1 holds end to end** (`docs/findings/m2.md`): a guest opens a tool by
path, executes out of it, and cannot modify it — the mapping reaches the sealed
memslot, not a page-cache copy. Cells fork from a booted kernel and resume in
userspace without booting.

**The M1 latency gate is missed** (`docs/findings/m1-spawn.md`): real cells spawn
in 6.3 ms p50 against a 5 ms p99 target. That is 663× better than booting and 30×
worse than the toy benchmark suggested. The design corpus's "~1 ms spawn" is not
supported by measurement.

See `docs/NOUSCELL_BUILD_PLAN.md` for the milestone plan, `docs/decisions/` for
ADRs 0001–0005, and `docs/diary/` for how it actually went.
