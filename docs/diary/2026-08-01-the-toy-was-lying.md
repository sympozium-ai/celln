# Diary — 2026-08-01: the benchmark was measuring a toy

A critical pass over what had been built, which turned into finding that the
project's headline latency number was off by about 30× and that the design's
central claim had never actually been tested.

## The question I should have asked earlier

The M1 benchmark reports a fork p50 of 184 µs and I had put that in the README
under "measured on real hardware". It is measured, and it is real hardware. It
is also a fork of a **16 KiB hand-assembled guest running real-mode code**, from
a "warm snapshot" that is a marker string in a memfd.

Meanwhile the stock kernel took 2.6 seconds to boot.

Those two facts sat in the same README for hours without me connecting them. The
whole thesis is *"the guest never boots in the hot path — spawn is a CoW fork of
a warm mote."* We had a fast fork of a toy, a slow boot of a real kernel, and
nothing bridging them. The build plan's own M1 exit criterion says *"1,000
concurrent forks, all reach guest **userspace**"* — the toy reaches guest
*instructions*, which is a much cheaper claim wearing the same words.

So: snapshot a booted Linux guest and fork cells from it. That is the test.

## Building it

Firecracker-shaped snapshot/restore. Guest RAM moves to a memfd — the template
maps it `MAP_SHARED` so its writes land in the file, and every cell maps the same
memfd `MAP_PRIVATE`. Everything not in RAM has to travel explicitly: vCPU
registers, sregs, FPU, XCRs, LAPIC, vcpu_events, mp_state, a curated MSR set,
plus the in-kernel PIC/IOAPIC/PIT and the KVM clock.

The MSR list is curated rather than taken from `KVM_GET_MSR_INDEX_LIST`, because
most of that list is not restorable and the failures are per-MSR and silent. The
ones that matter are syscall entry, segment bases, TSC, and the KVM paravirt
clock — the guest is using kvm-clock, and without those two MSRs time stops
making sense on the far side of a fork.

Parking needs a clean exit boundary. The guest prints a marker; the host stops
the run there and captures. Cells resume at the next instruction, so everything
after that line in `init.c` runs once per *cell*, having never booted.

It worked on the first run, which after the last two days felt suspicious enough
to check twice. It holds: 50/50 cells reach userspace, 0 boot a kernel.

## The number

**6.3 ms p50, 9.4 ms p99. The gate is 5 ms p99. Missed.**

Booting the same guest takes 4,175 ms, so forking is **663× better** — the
mechanism is validated in kind. It is also **30× worse than the toy implied**,
and it fails the gate the build plan set.

I could have buried this. The toy number is real, it is on real hardware, and
nobody reading the README would have known to ask. Writing it down as a missed
gate is the only version of this that is worth anything.

## Three things that did not work

**Halve the mote.** 512 MiB → 256 MiB moved p50 from 5.9 ms to 5.7 ms. Inside
the noise. Spawn cost is not proportional to parked RAM, which surprised me.

**Pre-warm a pool.** Build the cells first, time only activation: **6.6 ms** — no
better than a cold spawn, despite skipping ~2.8 ms of VM construction. This is
the result that relocated the problem. If removing the construction cost doesn't
help, construction wasn't the cost.

**Pre-fault the mapping.** `MADV_POPULATE_READ` pushed the fork call to 17 ms
p50, 94 ms p99 — touching every page to save faults the guest was never going to
take. One useful side effect: the "memslot ioctl" time collapsed from 1,817 µs
to 333 µs when the mapping was pre-populated, which proves that line item was
page-fault work all along, not ioctl overhead.

## What it actually is

The phase breakdown is the good part:

```
create VM + irqchip + PIT      758 µs
CoW mmap of mote RAM            36 µs   <- the fork itself
memslot ioctls               1,817 µs   <- really page-fault work
create vCPU                    306 µs
restore vCPU state             171 µs
guest resume to userspace    ~3,500 µs
```

**The fork is 36 µs.** The design's intuition about copy-on-write is completely
right. What costs is the guest re-faulting its working set after resume: every
page it writes takes an EPT violation and a copy. Read pre-faulting doesn't help
because reads weren't the problem; pooling doesn't help because the faults
happen at activation either way.

## The design consequence, which I didn't expect

> The stripped mote kernel (M5) is now justified by **spawn latency**, not just
> by attack surface.

What matters is not how much RAM a mote has parked — measured, doesn't matter —
but how many pages the guest dirties between resuming and doing useful work. A
full Fedora kernel resuming into a libc-less init still dirties milliseconds
worth. A stripped kernel with a small resident working set is the only lever in
this experiment that attacks the real cost.

That reframes M5 from "reduce attack surface, pay a CVE-tracking cost" to
"reduce attack surface *and* the only known path to the latency target". It also
makes M0 more urgent, since M0 gates M5.

Untested and cheaper than M5: **2 MiB huge pages for guest RAM**, which would cut
the fault count by up to 512×. That is the first thing I would try next, and it
is a couple of hours rather than a milestone.

## What I'd tell someone reading the old README

The 184 µs number was not a lie, but it was an invitation to believe something
false, which is worse than useless in a document whose whole job is to say what
is real. Both numbers are now in there, labelled: one as the VMM's overhead
floor, one as what it costs to spawn a cell. The gap between them is the
interesting part.
