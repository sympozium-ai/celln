# Findings — M1 spawn latency: the gate is MISSED, and the toy was lying

Date: 2026-08-01 · Host: x86_64, kernel 7.1, Intel VT-x, `/dev/kvm`
Raw numbers: `bench/results/m1-m2-kvm.json` → `thesis_real_cell_spawn`
Reproduce: `make bench-kvm` · Test: `cells_fork_from_a_booted_kernel_without_booting`

> **The design's central claim is "the guest never boots in the hot path — spawn
> is a CoW fork of a warm mote."** That claim had never been tested. Everything
> M1 measured was a fork of a 16 KiB hand-assembled guest, which says nothing
> about forking a real one. This document tests it with a stock Linux kernel and
> reports what came back, including a **failed gate**.

## The headline

| | |
|---|---|
| **Spawn → cell doing userspace work, p50** | **6.3 ms** |
| **Spawn → cell doing userspace work, p99** | **9.4 ms** |
| M1 gate | **p99 < 5 ms — MISSED** |
| Booting the same guest instead | 4,175 ms |
| Speedup of forking over booting | **663×** |
| Cells that reached userspace | 50 / 50 |
| Cells that booted a kernel | **0** — it is a fork, not a boot |

**The mechanism is validated; the number is not.** Forking a booted guest works
and is three orders of magnitude better than booting one. It is also **6× worse
than the gate**, and about **30× worse than the toy benchmark implied.**

## What the previous numbers actually measured

The M1 harness reports fork p50 ≈ 184 µs. That is a fork of a **16 KiB guest
running hand-assembled real-mode code**, from a "warm snapshot" that is a marker
string in a memfd. Nothing boots; nothing reaches userspace. The build plan's
exit criterion says *"1,000 concurrent forks, all reach guest **userspace**"* —
the toy reaches guest *instructions*, which is a different and much cheaper
claim.

Both numbers are now reported separately and labelled, because the toy figure is
still useful (it bounds the VMM's own overhead) and actively misleading if read
as a spawn time.

## Where the 6.3 ms goes

Measured per phase, mean over 50 spawns:

| Phase | Cost | |
|---|---|---|
| create VM + irqchip + PIT | 758 µs | fixed |
| **CoW mmap of mote RAM** | **36 µs** | *the fork itself* |
| memslot ioctls | 1,817 µs | dominated by page-table work |
| create vCPU | 306 µs | fixed |
| restore vCPU state (MSRs, LAPIC, regs) | 171 µs | fixed |
| — fork call total | ~2.8 ms | |
| **guest resume to first userspace instruction** | **~3.5 ms** | |

**The fork is nearly free — 36 µs.** The design's intuition about copy-on-write
is right. Everything expensive is around it.

## Three things that did not fix it

Recording the negative results, because each is the obvious next idea:

**1. A smaller mote does nothing.** Halving mote RAM from 512 MiB to 256 MiB
moved p50 from 5.9 ms to 5.7 ms — inside the noise. Spawn cost is not
proportional to parked RAM.

**2. Pre-warming a pool does nothing.** Constructing cells in advance and timing
only their activation gives **6.6 ms p50** — no better than a cold spawn, despite
skipping ~2.8 ms of VM construction. That is the result that relocates the
problem: if removing the construction cost does not help, the cost is not
construction.

**3. Pre-faulting the mapping makes it far worse.** `MADV_POPULATE_READ` on the
CoW mapping pushes the fork call to 17 ms p50 (94 ms p99) — it touches every
page to save faults the guest was never going to take. Notably the memslot ioctl
cost *collapsed* from 1,817 µs to 333 µs when the mapping was pre-populated,
which confirms that "memslot ioctl time" is really page-fault time wearing a
different hat.

## The actual cost, and what it implies

Taken together: the guest's post-resume **write** faults are what dominate. A
forked guest shares every page until it touches one; each page it writes takes
an EPT violation and a copy. Read pre-faulting does not help because the reads
were not the problem. Pooling does not help because the faults happen at
activation whichever side of the pool they fall on.

That has a sharp design consequence, and it is not the one I expected:

> **The stripped mote kernel (M5) is now justified by spawn latency, not just by
> attack surface.** What matters is not how much RAM a mote has parked — that was
> measured and it does not matter — but **how many pages the guest touches
> between resuming and doing useful work**. A full Fedora kernel resuming into
> glibc-less init still dirties enough to cost milliseconds. A stripped kernel
> with a small resident working set is the only lever measured here that
> attacks the actual cost.

Secondary levers worth measuring before M5 commits:

- **Huge pages for guest RAM.** 2 MiB pages would cut the fault *count* by up to
  512×. This is the cheapest untested idea and should be tried first.
- **Parking the mote later.** The mote here is parked after init has done a lot
  of one-off work. Parking at a point closer to "about to receive a task" may
  leave a smaller dirty set to re-fault.
- **UFFD-based pre-copy of a known hot set**, if profiling shows the touched
  pages are stable across cells.

## Honest limits of this measurement

- One vCPU, one guest, one host, `n = 50`. Not a concurrency study; the earlier
  1,000-cell figure is the toy, and the equivalent for real cells is untested.
- The guest signals liveness with a single `OUT` to an unused port. Saying it on
  the console instead costs **23 ms**, which measures our interrupt-driven 8250
  emulation rather than spawn. That artifact is why the port exists.
- The template is parked at one specific instruction. A different park point
  would give a different dirty set and therefore a different number.
- `NOUS_PREFAULT=1` reproduces the pre-faulting experiment.

## Verdict

The fork path works and is validated in kind: cells resume from a booted kernel,
in userspace, having booted nothing, 663× faster than booting. **The M1 latency
gate is missed at 9.4 ms p99 against 5 ms**, and the naive fixes do not close it.
This is not a reason to change substrate — the build plan's kill criterion is
"can't reach single-digit-ms forks", and we are at single-digit ms — but the
"~1 ms spawn" figure in the design corpus is **not supported by measurement** and
should be treated as an aspiration with a named dependency: shrinking the guest's
post-resume working set.
