# Diary — 2026-08-01: four wrong turns to a file path

Closing the second half of the VFS↔memslot join: making `open("/tools/probe")`
+ `mmap(PROT_EXEC)` land on the sealed memslot rather than a page-cache copy.
It works. Getting there took four wrong turns, and every one of them failed
*silently* — the system reported success at each step and simply did not
produce a device. Writing them down because none is inferable from the fix.

## The shape of the problem

The seal already survives a userspace mapping — the `/dev/mem` probe settled
that. What was missing is a *file path* to those pages with nothing copying in
between. DAX is exactly that property: "map the file's pages directly, do not go
through the page cache."

The chain: sealed region → declared as persistent memory → nvdimm drivers →
`/dev/pmem0` → ext2 image inside it mounted `dax=always` → `open` + `mmap`.

The kernel had what I needed: `CONFIG_FS_DAX=y` and `CONFIG_DAX=y` built in,
`libnvdimm`/`nd_pmem`/`nd_e820` as modules, and `MODULE_SIG_FORCE` unset. The
guest init loads the modules itself with `finit_module` (staged uncompressed
into the initramfs, since the guest has no xz decompressor). The tool filesystem
is built host-side with `mke2fs -d`, which populates an image without root or a
loopback mount. ext2 rather than ext4 deliberately: no journal to replay against
a device whose writes get dropped.

## Wrong turn 1: parking the region above RAM

The sealed window was at 4 GiB, above the top of guest RAM, on the reasoning
that memory the kernel knows nothing about is memory it can never allocate.

The kernel accepted the e820 entry and printed it:

```
user: [mem 0x0000000100000000-0x0000000100ffffff]  persistent RAM (type 12)
last_pfn = 0x20000
```

All three modules loaded, `rc=0` each. No `/dev/pmem0`.

`last_pfn` is the tell. RAM stops at 512 MiB; the region sits at 4 GiB. The
entry is parsed and printed but never becomes an iomem resource, so
`register_e820_pmem()` — which walks iomem looking for legacy persistent memory
— finds nothing and never creates the platform device the driver binds to.

Fix: punch the tool window *inside* the RAM span. Guest RAM is now two memslots
either side of a hole at 384 MiB, with the sealed memslots filling it. Costs a
little complexity in the memory setup and it is the only layout that works.

## Wrong turn 2: believing a single `read()`

With the region moved, `/proc/iomem` still showed nothing above 384 MiB. I very
nearly concluded the move hadn't helped.

`/proc/iomem` is a seq_file: one `read()` returns a chunk, not the file. My
freestanding `grep_file` did a single read and got a plausible-looking, complete-
looking, truncated map. Looping until EOF changed what I was looking at.

The lesson isn't about seq_files. It's that my *diagnostic* was lying, and I was
about to make a decision on it. Two of these four wrong turns were bad
measurements rather than bad designs.

## Wrong turn 3: `head -16`

Same failure mode, one layer out. With the read loop fixed, I piped the output
through `head -16` while other `NOUS:` lines were also matching, so the iomem
tail scrolled off and the region again looked absent.

Worth stating plainly: twice in a row I diagnosed "the feature is missing" when
what was missing was my view of the evidence. Both times the fix was to look
harder at the instrument before theorising about the system.

## Wrong turn 4: `pci=off`

With the layout right and the evidence trustworthy, `/proc/iomem` showed RAM on
both sides of the hole and *still* no persistent-memory entry. That is a real
kernel behaviour, and it took reading the resource-registration path to see it.

`e820__reserve_resources()` does not insert every entry. `do_mark_busy()`
returns false for `E820_TYPE_PRAM` — persistent memory is treated like device
memory, reserved for a driver — so those resources are deferred to
`e820__reserve_resources_late()`. On x86 that function has exactly one caller:
`pcibios_resource_survey()`.

We booted with `pci=off`, because we emulate no PCI devices and switching it off
looked like obvious noise reduction. No PCI init → no resource survey → no pmem
resource → no device. Every module still loading cleanly the whole time.

Removing `pci=off` wasn't enough: with no PCI host bridge at all,
`pci_legacy_init()` decides the system has no PCI and returns before the survey.
The kernel detects type-1 config access by writing `0xcf8` and reading it back,
so the VMM now keeps a 32-bit latch for that port — about ten lines — and
returns all-ones for config *data* reads, which reads as "no device here". Then
`pci=conf1` on the cmdline to take the probe path.

Platform device present. `/dev/pmem0` present. ext4 driver mounted our ext2
image `r/w without journal`.

## The result

```
✔ pmem device from the sealed region     present
✔ filesystem mounted with dax=always     ok
✔ opened the tool by path                ok
✔ mmap(PROT_READ|WRITE|EXEC)             ok
✔ it is the sealed page-set              match
✔ executed the tool from the mapping     ok
✔ write through the file mapping refused landed=no
  host counted 513 refused write(s) into sealed regions
```

513 is a nice detail: 512 of those are the ext4 driver writing metadata to a
device that silently drops writes, plus our one deliberate probe write. The
filesystem carries on regardless, which is the read-only-region story working
exactly as it needs to.

The write is the assertion that matters. Magic proves we mapped the right
thing; execution proves the pages are r-x to a real process; but only the
refused write distinguishes *direct* from *copied*, because a page-cache copy
would have absorbed it silently and the host would have counted zero.

## One regression, and what it taught

Adding these tests broke `one_physical_copy_serves_many_cells`, which asserted
`shared_tool_count() == before + 1`. The tool registry is process-global and the
new boot tests seal into it too, so under parallel execution the count moves
underneath the assertion.

The fix was to stop asserting on a global count and assert the actual claim:
the host address backing that hash is the same before and after 64 cells map
it. Better test, immune to neighbours. A count was always a proxy; it only
looked fine while nothing else used the registry.

## What is left

The join is closed. `/dev/mem` and DAX both stay in the suite — the first is
unambiguously direct, so when the DAX path regresses, having both says which
half broke.

Honest limits: `pci=conf1` plus a config-port latch is a real dependency, and
the mote kernel will need to either keep PCI initialisation or carry pmem
resource registration that doesn't route through the PCI survey. That is a
finding about the mote kernel's config, arrived at the hard way, and worth
having before M5 rather than during it.
