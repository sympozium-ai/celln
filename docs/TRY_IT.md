# Try it

Four commands, about five minutes. Each one proves a specific claim, and this
page says what to look for so you can read it without running anything.

> **First, the honest part.** You cannot run an agent in Nouscell today. There
> is no `pip install` path, no vsock, no toolplane, no shell. What exists is the
> **security substrate** underneath all of that, built and tested against real
> hardware. These commands demonstrate that substrate. If you are evaluating
> whether the idea works, this is the evidence. If you are looking for something
> to run a workload on, it is too early.

---

## 1. Does this machine have what it needs?

```sh
make doctor
```

```
Nouscell host doctor
  ✔ /dev/kvm present
  ✔ CPU virtualization extensions present (vmx/svm)
  ✔ kernel 7.1.3 (>= 6.12)
  ✔ cargo present (1.96.0)
  ✔ bootable kernel image readable (vmlinuz-7.1.4-200.fc44.x86_64)
  ✔ guest image toolchain present (gcc, cpio, e2fsprogs)
```

Only `cargo` is required. Everything else gates a specific demo, and anything
missing makes those tests **skip** rather than fail — so `make ci` is green on a
laptop, a container, or a CI runner with no virtualization at all.

---

## 2. The idea, on any machine

```sh
make demo
```

No KVM needed. This walks the five-beat loop the design is built around, with
the trust core doing real work against a mock VM backend:

```
● beat 1  seal from intent — fork a warm mote into a cell
   cell cell-001 sealed, phase = Materialise

● beat 2  loan a warm tool — pip install of a seen package is a page-map
   resolve python -> blake3:6617e0e4… tier=forged warm=true

● beat 3  cold tool, still fast — unseen package served Verified, Forged queued
   resolve leftpad -> tier=verified warm=false upgrade_queued=true

● beat 4  demote on exec — attested python fed a data-lane script runs collared
   python evil.py -> runs in data lane (demoted)
   python -c "<tainted>" -> runs in data lane (demoted)
   first tainted exec -> ratchet phase = Work
   further tool loan denied: verb Materialise denied in phase Work

● beat 5  kill fleet-wide — revoke a hash; it stops executing everywhere
   { "denied": "exec blake3:6617e0e4…",
     "reason": "hash was revoked fleet-wide",
     "instead": "use a non-revoked alternative; …" }

● beat 6  task completes -> cell dissolves
```

**What to notice.** Beat 4 is the interesting one: `python` is fully attested,
but the moment it is fed something the agent wrote, *that invocation* drops to
the collared lane — including the `python -c "…"` form, which file-level taint
tracking misses. And once any tainted code has run, the cell can never be lent
another tool. Authority only shrinks.

Beat 5's output is a structured `explain` record rather than a bare error,
because the failure surface is how an agent learns to correct itself.

---

## 3. The substrate, on real hardware

```sh
make boot-kvm     # needs /dev/kvm, gcc, cpio, e2fsprogs
```

This boots an **unmodified Fedora kernel** in a microVM, seals an attested tool
into its physical address space, and then hands the question to guest userspace:

```
The join, by file path — `open("/tools/probe")` under DAX
  ✔ pmem device from the sealed region     present
  ✔ filesystem mounted with dax=always     ok
  ✔ opened the tool by path                ok
  ✔ mmap(PROT_READ|WRITE|EXEC)             ok
  ✔ it is the sealed page-set              match
  ✔ executed the tool from the mapping     ok
  ✔ write through the file mapping refused  landed=no
    host counted 513 refused write(s) into sealed regions
  ✔ revoked mid-run, tool gone from the mapping  revoked
```

**What to notice.** A real process, on a stock kernel, opened a file by path,
executed code out of it, and **could not modify it** — then had it taken away
while still holding the mapping.

The write is the assertion that matters. Reading the right bytes and executing
them would both succeed against a page-cache *copy*; only a direct mapping puts
the store against read-only memory where the hardware refuses it. 513 refused
writes is mostly the ext4 driver's own metadata bouncing off a read-only device,
which it survives.

Why this is not just a filesystem permission: nothing in the guest is enforcing
it. The guest is root. The seal is a stage-2 page table the guest cannot reach.

---

## 4. The numbers, including the bad one

```sh
make bench-kvm    # writes bench/results/m1-m2-kvm.json
```

```
THESIS — spawning real cells from a parked mote
  ✔ reached userspace and did work                  50/50
  ✔ cells that booted a kernel                          0
    template boot (off hot path)                   4101 ms
  ✘ spawn -> userspace work p99                    9437 µs   gate: p99 < 5 ms
      of which: CoW mmap of mote RAM                 36 µs
    pages dirtied per activation          2511 (10045 KiB)
    → a cell reaches userspace 663x faster than booting one
```

**What to notice.** Cells fork from an already-booted kernel and resume in
userspace having booted nothing — 663× faster than booting one. And the latency
gate **fails**: 9.4 ms p99 against a 5 ms target.

That failure is left in the output on purpose. The number is page-fault-bound —
2,511 copy-on-write faults at ~1.6 µs each — and the fork itself is only 36 µs,
so the copy-on-write design is right and the cost is elsewhere. Three obvious
fixes were tried and none worked. See [findings/m1-spawn.md](findings/m1-spawn.md).

---

## Also worth running

```sh
make test-kvm     # 22 hardware tests, incl. the hostile-guest proof
make ci           # mock-only; green on any machine
```

The test worth reading is `ring0_guest_with_own_page_tables_cannot_write_sealed_pages`.
It builds a guest that enters protected mode, installs page tables **it wrote
itself**, maps the sealed page writable in them, and writes. Guest-side that
write is entirely legal — ring 0, PTE says writable, no fault. It still does not
land.

---

## If something skips

| Message | Fix |
|---|---|
| `no /dev/kvm` | Virtualization off in BIOS, or a VM without nested virt |
| `no readable /boot/vmlinuz-*` | Pass your own: `cargo run -p pilot --features kvm --bin nous-boot-kvm -- /path/to/bzImage` |
| `no target/nous-initramfs.cpio` | `make guest` (needs gcc, cpio, e2fsprogs) |
| `no /lib/modules for <version>` | Boot tests pick a kernel whose modules are installed; install `kernel-modules` for the newest one |

Hardware tests skip rather than fail by design. If you want them to be
load-bearing in CI, run `make test-kvm` on a machine with `/dev/kvm` and treat a
skip as a failure there.

---

## Where to go next

| | |
|---|---|
| What is proven, and what is not | [findings/m2.md](findings/m2.md) |
| Why spawn latency misses its gate | [findings/m1-spawn.md](findings/m1-spawn.md) |
| Why each design choice was made | [decisions/](decisions/) (ADRs 0001–0005) |
| How it actually went, including the wrong turns | [diary/](diary/) |
| The full milestone plan | [NOUSCELL_BUILD_PLAN.md](NOUSCELL_BUILD_PLAN.md) |
| Vocabulary — mote, cell, lane, tier | [NAMES_AND_CONVENTIONS.md](NAMES_AND_CONVENTIONS.md) |
