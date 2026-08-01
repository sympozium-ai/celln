# nouscell

**Nouscell** ( _NOWSS-cell_ ) — an agent-native operating system: a tiny, fast,
hardware-isolated **cell** that intelligence is launched into, where every tool
is attested memory the host lends in and can revoke in microseconds.

> *Software is a service the host provides to the process, not property the
> machine owns.*

This repository is the **proof-of-concept**: the security substrate, built and
tested against real hardware. You cannot run an agent in it yet — there is no
`pip install` path, no vsock, no toolplane. What you can do is check whether the
idea holds up, in about five minutes.

## Try it

```sh
make doctor     # what this machine can run (only cargo is required)
make demo       # the five-beat loop — no KVM needed, runs anywhere
make boot-kvm   # a real kernel: guest opens a tool by path, runs it, can't modify it
make bench-kvm  # the numbers, including the gate we miss
```

**→ [docs/TRY_IT.md](docs/TRY_IT.md)** walks through each one, with the output
and what to look for. Readable without running anything.

The single most interesting line comes out of `make boot-kvm`:

```
✔ executed the tool from the mapping     ok
✔ write through the file mapping refused  landed=no
✔ revoked mid-run, tool gone from the mapping  revoked
```

A real process on a stock Linux kernel opened a file, executed code out of it,
could not modify it, and then had it taken away mid-run. Nothing in the guest is
enforcing that — the guest is root. The seal is a stage-2 page table it cannot
reach.

## Where it stands

**Proven on real hardware** (`docs/findings/m2.md`):

- **Claim C1** — a guest that enters protected mode and maps a sealed tool page
  writable *in page tables it wrote itself* still cannot write it.
- **The VFS↔memslot join** — a guest reaches lent tool code by file path under
  DAX and gets the sealed pages, not a page-cache copy.
- **Density** — 500 cells share one 1 MiB tool at a single physical copy (71×);
  KVM's real memslot budget is 32,762 per VM, so per-tool sealing is viable.
- **Cells fork from a booted kernel** and resume in userspace having booted
  nothing — 663× faster than booting one.

**Not met** (`docs/findings/m1-spawn.md`): the M1 spawn gate. Real cells spawn in
**6.3 ms p50 / 9.4 ms p99** against a 5 ms p99 target. It is page-fault-bound,
and pooling, shrinking the mote, and pre-faulting all failed to fix it. The
design corpus's "~1 ms spawn" is not supported by measurement.

**Not started**: stripped mote kernel, vsock transport, guest userland, the
hermetic build farm, per-tool granularity through the DAX path.

## Reading

| | |
|---|---|
| **Start here** | [docs/TRY_IT.md](docs/TRY_IT.md) |
| What is proven, and what is not | [docs/findings/](docs/findings/) |
| Why each choice was made | [docs/decisions/](docs/decisions/) — ADRs 0001–0005 |
| How it actually went, wrong turns included | [docs/diary/](docs/diary/) |
| The milestone plan | [docs/NOUSCELL_BUILD_PLAN.md](docs/NOUSCELL_BUILD_PLAN.md) |
| Committed measurements | [bench/results/](bench/results/) |
| House rules for working on it | [AGENTS.md](AGENTS.md) |

## Vocabulary

- **mote** — the substrate at rest (stripped kernel + `pilot`). The seed.
- **cell** — a live, sealed, tool-loaned mote. *Every cell is a sealed mote.*
- **forgectl / warden / pilot** — host daemon / per-cell VMM / in-cell
  supervisor. 1 warden : 1 microVM : 1 cell.

Full glossary: [docs/NAMES_AND_CONVENTIONS.md](docs/NAMES_AND_CONVENTIONS.md).

## Layout

```
crates/nous-manifest   trust core: Hash, Tier, Lane, exec-by-hash, laundering ban
crates/nous-store      content-addressed store
crates/forgectl        fleet daemon: tiered resolution
crates/warden          per-cell VMM: ratchet, KVM backend, Linux boot + fork
crates/pilot           in-cell supervisor + the demos
guest/init             freestanding guest init (no libc)
docs/                  design corpus, ADRs, findings, diary
```

Rust for code · Make for orchestration · shell for glue.

Pre-alpha, single-host. Working name pending trademark/domain clearance.
