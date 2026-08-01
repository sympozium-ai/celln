# Diary — 2026-08-01: from a stub that refused to a guest that couldn't

Going from `KvmVmm` returning `Unsupported` on every method to a real guest
process executing lent tool code it cannot modify. Written as I went, kept
honest about the parts that were wrong first.

---

## The starting position

ADR-0001 left the KVM backend as a stub that returns `Unsupported` rather than
faking a hardware guarantee, because the machine that built the POC had no
`/dev/kvm`. This machine does — VT-x, kernel 7.1.3, `/dev/kvm` world-readable —
so nothing needed installing. That was the first surprise: I had budgeted time
for host setup and needed none.

## M1: the fork path

`kvm-ioctls` + `kvm-bindings` rather than pulling in Firecracker or Cloud
Hypervisor. The whole argument for warden is that the policy is ours and the VM
surface is tiny; inheriting a full VMM would have inverted that. The backend
came out around 500 lines.

Two design choices that mattered more than they looked:

**Fork = `MAP_PRIVATE` of a template memfd.** The "warm mote" is a memfd; sealing
a cell maps it copy-on-write. Clean pages are shared across every cell of a
lineage, dirty pages are private. This is a real CoW fork, not a simulation of
one, and it made the idle-cell numbers fall out for free later.

**`KVM_MEM_READONLY` memslots are the seal.** Not a convention we enforce — the
CPU takes an EPT violation and exits to the host. `KvmVmm::new` refuses to start
if `KVM_CAP_READONLY_MEM` is missing rather than quietly degrading, which felt
like the only choice consistent with "never fake a hardware guarantee".

It compiled first try and all seven hardware tests passed on the first run,
which made me suspicious rather than pleased. The suspicion turned out to be
justified, just not about the code.

## The test that was too easy

M1's sealing test showed a privileged guest write bouncing off a sealed page.
Green, and worth almost nothing. Real mode *is* maximum privilege — no paging,
no protection, direct physical addressing — so I could argue it proved "even at
ring 0". But the adversary the design actually assumes is a **fully compromised
guest kernel**, and the thing that makes a guest kernel dangerous isn't its
privilege level, it's that it owns address translation.

So I rewrote the adversary. The hostile guest now enters 32-bit protected mode,
installs a page directory and page table it wrote itself, identity-maps the
first 4 MiB with the writable bit set — including the sealed tool page — and
writes to it.

Guest-side that write is entirely legal: CPL 0, PTE present and writable, no
fault. It still doesn't land.

The test asserts four things, and I needed all four before I believed it: the
guest's own PTE reads present+writable, the write was refused, the tool bytes
are unchanged, and a completion marker proves the guest reached the end of its
32-bit code rather than dying early and looking like a pass. That last one is
the assertion I'd have skipped if I were moving fast, and it's the one that
distinguishes "the hardware refused" from "the guest crashed".

Hand-encoding the 16→32-bit transition was the fiddliest hour of the day. The
`lgdt` was the trap: real-mode addressing is 16-bit, so the GDT pseudo-descriptor
has to live in the low 64 KiB even though the page tables it enables are at
3 MiB. I had it at `0x12030` first, which silently loads garbage.

## Measurement, because assertions are cheap

AGENTS.md says performance claims become committed numbers. `nous-bench-kvm`
now measures and writes `bench/results/m1-m2-kvm.json`:

| | measured | gate |
|---|---|---|
| concurrent cells, all reaching guest instructions | 1000/1000 | ≥ 1000 |
| fork p50 / p99 | 184 µs / 509 µs | p99 < 5 ms |
| private RSS, idle cell | **0.26 KiB** | — |
| private RSS, after running | 12.3 KiB | < 1 MiB |
| 1 MiB tool across 500 cells | 1 copy, 71× saving | ~one copy |
| revocation, 200 running cells | 7.5 ms (37 µs/cell) | < 1 s |
| sealed memslots per VM | **32,762** | unknown before |

Two of these changed decisions rather than confirming them.

The idle cell costs 0.26 KiB because CoW pages aren't faulted until touched. I
expected "small". I did not expect "essentially free", and it makes the parked-
mote story stronger than the design doc claims.

The memslot budget was an open question the build plan flagged as a possible
forcing function for coarser layer packing (ADR-0004's layer format). Measured:
32,762 per VM. A cell would need >32k independently sealed tools to hit it.
**Per-tool sealing is not constrained by memslots**, so layer packing survives
only on its own merits. My first probe capped at 2,000 and I nearly reported
that as the answer — it was my loop bound, not KVM's. Worth remembering: a
measurement that returns exactly your limit is measuring you.

## "Why don't we have a real kernel yet?"

A fair challenge, and the answer has two halves, because there are two things
called "the kernel".

The **stripped mote kernel** is M5 and gated on M0: the config comes from a
syscall allowlist derived from ~2,000 real agent trajectories. Building it first
means guessing what to cut and finding the mistakes as mysterious failures in
the M5 benchmark. It also carries a permanent CVE-tracking burden, so you want
to cut once, from data.

The **VFS↔memslot join** was the genuinely overdue one — and the plan agrees,
annotating M2 as "alone; gates everything (incl. VFS join)".

There's also a reason going kernel-less first was right rather than merely
convenient: a real kernel makes C1 *harder* to prove, not easier. With a stock
kernel you have to disentangle "the hardware refused this" from "the guest
kernel refused this", and only the first is the claim. No kernel, no ambiguity.

## Booting something real

The 64-bit Linux boot protocol against an unmodified Fedora bzImage: load the
protected-mode image at 1 MiB, hand-build `boot_params` with an e820 map,
identity-map the first GiB with 2 MiB pages, long mode, jump to `startup_64`
with the zero page in `%rsi`. It came up on the first attempt and printed
`Linux version 7.1.4` — which was a genuinely good moment — then panicked at
`prepare_namespace` for want of a root filesystem, exactly as it should.

Then two failures whose symptoms point nowhere near their causes.

**The one-character console.** With an initramfs, init ran — `Run /init as init
process` — and emitted exactly one character, `N`, before the machine rebooted.
It reads unmistakably as a broken init. It isn't: `earlyprintk` *polls* the line
status register, but the real `ttyS0` driver transmits **interrupt-driven**. It
sends one byte and waits for a THR-empty interrupt that never comes because I
hadn't wired IRQ 4. The whole kernel log arriving intact is what makes this
misleading — the working path and the broken path are different code.

**The hang that wasn't.** A guest idling in HLT blocks `KVM_RUN` forever. Every
run is now bounded by a watchdog thread sending SIGUSR1, with the handler
installed *without* `SA_RESTART` so it actually interrupts the ioctl. Get that
flag wrong and the signal is delivered, handled, and the syscall resumes.

Guest userspace is a 5 KB freestanding init, no libc, raw syscalls. It reports
`NOUS:key=value` lines the host asserts on. That channel is the point: it keeps
the discipline that guest-side claims are proven by guest code actually trying.

## Splitting the join in two

The join was recorded as one risk. Sitting down to it, it's clearly two, and
they differ in both difficulty and consequence:

1. Does the seal survive a userspace mapping at all — real pages, executable,
   writes still refused? If no, the approach is dead.
2. Which mechanism gets a *file path* there without a page-cache copy? If that
   fails, the guest interface changes but the design survives.

Answering (1) alone, via `/dev/mem`, meant a negative result would arrive
cheaply. It's the shortest unambiguously-direct mapping with no filesystem or
page cache anywhere near it.

Result: guest userspace maps the sealed region, reads `NOUSTOOL`, **calls a
function out of the mapping** and gets `0x5a` back, then writes — and the write
doesn't land. Byte unchanged, host counts the refusal.

Three assertions, all load-bearing. Magic alone would pass on a copy. Execution
alone would pass on a copy. The **write** is the one that decides it, because a
page-cache copy would absorb the write silently and the host would count zero
refusals. `/dev/mem` would happily hand back a copy for a RAM-backed region,
which is exactly why I didn't trust the first two.

## Where this leaves things

C1 holds, including against a guest that controls its own translation. Density
holds. A real kernel boots and a real process executes lent code it cannot
modify. What's left of the join is plumbing a file path to those pages — DAX
over pmem, virtio-fs DAX, or a small driver — and the awkward part is that the
sealed region is read-only, so whatever mounts it must tolerate never writing.

The thing I'd tell someone picking this up: the tests that mattered were the
ones where I made the guest genuinely try to win. Every time I wrote a test that
asserted a property from the host side, I later had to replace it with one where
guest code attacked and failed.
