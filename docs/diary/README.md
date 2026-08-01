# Developer diary

Narrative record of how the work actually went — what was tried, what was wrong
first, and which failures gave no useful signal at the point they occurred.

This exists because the ADRs in `docs/decisions/` record *what was decided* and
the findings in `docs/findings/` record *what was proven*, and neither captures
the thing that costs the most time: failures whose symptoms point nowhere near
their causes. Those are not inferable from the code that fixes them, so if they
are not written down they get rediscovered.

| Entry | Covers |
|---|---|
| [2026-08-01 — from a stub that refused to a guest that couldn't](2026-08-01-from-stub-to-real-hardware.md) | M1 fork path, claim C1 against a guest controlling its own page tables, the measurement harness, stock-kernel bring-up |
| [2026-08-01 — four wrong turns to a file path](2026-08-01-hunting-the-vfs-join.md) | Closing the VFS↔memslot join: DAX over pmem, the four silent failures on the way, and revoking a tool from under a guest holding it |
| [2026-08-01 — the benchmark was measuring a toy](2026-08-01-the-toy-was-lying.md) | Critical pass: snapshotting a booted kernel, the M1 spawn gate being missed, and three fixes that did not work |

## The ones worth knowing before you hit them

- **The interrupt-driven console.** `earlyprintk` polls; the real `ttyS0` driver
  waits for a THR-empty IRQ. Without IRQ 4 wired, the entire kernel log arrives
  looking healthy and userspace output dies after one character — which reads
  as a broken init.
- **`SA_RESTART` defeats a watchdog.** A guest idling in HLT blocks `KVM_RUN`;
  the signal that interrupts it must be installed *without* `SA_RESTART`, or it
  is delivered, handled, and the syscall resumes.
- **Persistent memory above `last_pfn` is parsed and ignored.** The e820 entry
  prints correctly and never becomes an iomem resource.
- **`pci=off` silently disables DAX.** PRAM resources are registered only from
  `pcibios_resource_survey()`. On a VM with no PCI devices, turning PCI off
  looks like obvious cleanup.
- **The console is not a pipe.** The tty line discipline translates newlines
  (ONLCR), so matching guest output on a marker ending in `\n` never fires.
- **A benchmark that measures a toy is worse than no benchmark.** The M1 fork
  figure was real, on real hardware, and 30x away from what it appeared to
  claim. Check what the harness actually constructs before quoting it.
- **If removing a cost does not help, it was not the cost.** Pre-warming a pool
  skipped ~2.8 ms of VM construction and changed spawn latency by nothing,
  which is what located the real expense (post-resume page faults).
- **Trust your instrument before your theory.** Two of the four wrong turns in
  the join hunt were bad measurements — a single `read()` of a seq_file, and a
  `head -16` — not bad designs. Both times the conclusion "the feature is
  missing" was really "my view of the evidence is truncated".
