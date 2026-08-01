# Nouscell — Local Proof Build Plan

**Audience:** an autonomous coding agent (Fable) executing milestone by milestone.
**Scope:** prove the *single-host* story end to end. No distribution, no Kubernetes, no CDN, no GPU.
**Definition of success:** the five-beat proof demo in §7 runs, recorded, on one bare-metal box.

---

## 0. How to use this document

- Work **one milestone at a time, in the order given**. Do not start a milestone until the prior milestone's exit criteria are green, *except* M0 which runs in parallel with M1.
- Every milestone has **exit criteria that are executable tests**. "Done" means the test in `tests/<milestone>/` passes in CI, not that the code looks finished.
- Each milestone has a **kill criterion**. If you hit it, stop, write up what you found in `docs/findings/<milestone>.md`, and surface it — do not work around it silently. A cheap, honest "this doesn't hold" is a successful outcome.
- **Do not build anything marked OUT OF SCOPE.** Where an interface will later cross a host boundary, define it as a protocol (gRPC/protobuf over a socket) rather than an in-process call, then implement only the local side. This keeps the distribution seam clean without building it.
- Prefer **measurement over assertion**. Where the plan says "measure X," the number goes in `bench/results/` as committed JSON, and the exit criterion compares against it.
- If a design choice is underspecified here, choose the option that (a) reduces guest attack surface and (b) is reversible. Record the choice in `docs/decisions/NNNN-title.md` (ADR format).

---

## 1. Non-negotiable constraints

These are load-bearing. Violating one invalidates the proof.

1. **The guest never boots in the hot path.** Production spawn is a copy-on-write fork of a warm **mote** (the stripped kernel + pilot substrate) into a **cell** (the live, sealed, tool-loaned instance). Booting is a build-time cost only. See `NAMES_AND_CONVENTIONS.md` — mote and cell are a hierarchy, never synonyms: every cell is a sealed mote.
2. **The guest has no in-kernel network stack.** `AF_INET`/`AF_INET6` are preserved as an ABI but implemented *outside* the in-kernel TCP/IP stack — bytes are marshalled over vsock to a host-side proxy. **This is real work, not a shim** (see ADR-0002): with static musl there is no dynamic linker to interpose, so the redirect lives either in a minimal in-guest socket layer that speaks vsock, or in the VMM's virtio transport. The host proxy owns DNS, TLS termination, egress policy, and credential injection **via a Nouscell CA installed in every cell's trust store** (so pip/git TLS can be inspected and credentials injected). Zero general-purpose network CVE surface in the guest kernel.
3. **The filesystem has no authority to run code.** Execution is by content hash against a signed manifest. There is no path-based `execve` that can run an unattested page.
4. **Tool code is unwritable from the guest side.** Enforced below the guest kernel (KVM stage-2 / read-only memslots), so it survives a full guest-kernel compromise.
5. **Authority only shrinks.** The ratchet is enforced host-side (in warden), never by the guest asking nicely.
6. **Compatibility is a feature.** The agent must experience a normal Linux box. Every ABI break is a silent latency tax — avoid unless a constraint above forces it.

---

## 1.5 Decisions to make before writing code

These came out of a design critique. Each is an ADR to be written and resolved at the milestone noted; they change scope, so don't discover them late.

- **ADR-0002 — Network ABI under static libc (resolve during M1).** The AF_INET-over-vsock redirect cannot be a userspace `LD_PRELOAD` shim because guest binaries are static. Decide: (a) minimal in-guest socket layer that speaks vsock, or (b) VMM/virtio-transport redirect. Includes the CA-in-guest decision for TLS inspection and credential injection. This is the single most under-scoped piece of systems work in the plan.
- **ADR-0003 — Tiered trust model (resolve during M2/M3).** Attestation ≠ rebuilding. Three tiers (see below). This is what keeps launch time fast without abandoning provenance.
- **ADR-0004 — Layer format (resolve during M2).** The universal unit of tool delivery is a **sealed page-set + manifest delta**, not a filesystem tarball. Defined below; M2 and M3 both build against it.
- **ADR-0005 — VFS↔memslot join (resolve during M2).** How a guest `mmap(PROT_EXEC)` of `/tools/python` lands on the sealed physical memslot rather than a page-cache copy (DAX-style direct mapping). This is the actual hard part of M2 — call it out, don't let it hide inside "map into guests."
- **ADR-0006 — Shell strategy (resolve during M5).** Ship shell-as-*telemetry* first (parse + pass through to a real `sh`, log gaps), promote to shell-as-*executor* only where gap data says it's safe. Avoids a compatibility tar pit fighting the "compatibility is a feature" principle.

### The tiered trust model (ADR-0003) — why launch is never slow

The plan must never put a hermetic rebuild on the request path. Split "attested" from "rebuilt":

| Tier | What it is | Time to produce | Use |
|------|-----------|-----------------|-----|
| **1 · Forged** | rebuilt hermetically from source, signed | minutes | background only; the target state for common artifacts |
| **2 · Verified** | upstream binary (PyPI wheel, npm tarball) hash-pinned, scanned, signed by forgectl | seconds | the cold path a user actually waits on |
| **3 · Unsealed** | no attestation, still hardware-isolated | instant | escape hatch / onboarding (see adoption path) |

**Serve fast, upgrade trust asynchronously.** A cold request gets Tier-2 in seconds; forgectl queues the Tier-1 rebuild in the background; future cells silently get Forged. The manifest records which tier every running cell received. Per-customer policy: a regulated buyer can mandate Tier-1-only and accept cold-build waits; the default is Tier-2-then-upgrade. **Latency never waits on trust.**

### The layer format (ADR-0004)

A **layer** = a set of sealed, executable page images + the signed manifest entries that make them runnable + a tier tag. Consequences:

- **At launch:** layers pre-composed into snapshot-forest nodes cost zero — they're part of the forked image. Warm launch stays ~1 ms no matter how many layers are stacked.
- **Mid-cell:** injecting a layer into a *running* cell is a memslot map + manifest push over the control lane — microseconds, no restart. (The pip shim is just the first consumer of this path.)
- **Composites:** the fleet-learning loop pre-composes hot combinations (e.g. `python+scipy+pandas`) into single layers so common stacks inject in one map.

### Adoption path (design requirement, informs M3/M5)

- **Unsealed mode is a first-class cell type**, not a debug flag. A user is never blocked waiting for their private packages/monorepo/internal registry to be onboarded — they run in a plain hardened microVM (Tier-3) and turn sealing on per-workload as artifacts get forged. Sealing is a ratchet the user climbs, not a wall they hit.
- **Ship prebuilt inventory:** the top ~500 PyPI + ~300 npm artifacts pre-forged as Tier-1 layers *in the product*, so the common path never sees a cold build. Finite, solvable engineering cost.
- **Persistent workspace:** a cell dissolves, but its workspace volume can outlive it and re-mount into the next cell. The design must answer "where does my agent's durable state live across sessions" — cattle cells, pet workspace.

---

## 2. Target hardware & base stack

### Packaging decision (read first)

**Nouscell is a runtime that sits on an existing Linux host with KVM — not an appliance OS.** The novel parts are the three daemons (`forgectl`, `warden`, `pilot`); they run *on top of* a stock host kernel, they do not replace it. The bring-up model is "install a daemon and point agents at it," closer to installing Firecracker than to installing Harvester/ESXi.

Keep the host **boring and inspectable** for the entire local proof. You want to SSH in, run a stock Debian microVM next to a Nouscell cell on the same box, and compare them directly (M5 depends on exactly this). An immutable/appliance host image — where Nouscell's host OS gets the same stripping treatment as the guest — is a **distribution-phase packaging choice**, explicitly deferred (see §8). Do not build it now; it forces host-image and immutability engineering unrelated to the three claims under test.

### Host requirements

- **KVM on real silicon — the one hard requirement.** The host must expose `/dev/kvm`. Verify: `egrep -c '(vmx|svm)' /proc/cpuinfo` > 0 and `/dev/kvm` present.
- **Bare metal, or a VM with *nested* virtualization enabled.** Nested-on-a-cloud-VM is acceptable for dev iteration only — **never for benchmarks** (density and latency numbers are meaningless under nesting). For any committed number in `bench/results/`, use a bare-metal instance (AWS `*.metal`, Equinix, Hetzner/OVH dedicated) or an owned box.
- **CPU:** x86-64 with VT-x/AMD-V and modern EPT/NPT — the page-sealing mechanism (M2) rides on second-stage page tables, so EPT/NPT is load-bearing, not optional. ARM64 with EL2 is a valid *second* target, not the first.
- **Host kernel ≥ 6.12** — mature Landlock (ABI v4+ for network rules) and current memslot handling.
- **RAM is the scarce resource, not CPU.** The density story is memory-bound: each cell is hundreds of KB of dirty pages plus its workspace over a *shared* tool cache. Dev floor 64 GB; the interesting density numbers (M6) want 128–256 GB.
- **Storage:** local NVMe for the content-addressed store and snapshot forest — this is the cold-materialisation hot path. Not network storage, not spinning disk.
- **Count:** **one box is enough for M0–M6.** Multi-host distribution is out of scope until the five-beat demo runs.

**Concrete starter spec:** one dedicated server, recent AMD EPYC or Intel Xeon, 128 GB RAM, 1–2 TB NVMe, stock Ubuntu 24.04 or Debian 13 on a 6.12+ kernel. That is the entire shopping list for the local proof.

### Bring-up sketch (target end-state — none of this is built yet)

The install shape the daemons should present by end of M3:

1. Start from the stock host above; confirm `/dev/kvm`. Nothing custom on the host yet.
2. Bring up `forgectl` (host daemon): initialises the CAS store on NVMe, builds the initial snapshot forest (bare → +python → …), starts serving pages.
3. `warden` is the per-cell VMM that `forgectl` launches — no separate host-side configuration for the proof.
4. `pilot` is **never installed on the host** — it lives inside the snapshots, baked in at snapshot-build time.
5. Hand a task to `forgectl`; it seals a cell. `seal(intent) → cell`.

Mental model: `install nouscell → a daemon comes up → point agents at it`. Not "boot an ISO."

### Base stack

- **Languages:** Rust for `warden`, `pilot`, `forgectl` (matches the ecosystem — the fast-fork and microVM prior art is Rust; strong story for static, no-libc guest binaries). Python for the eval/bench harness only.
- **Hypervisor substrate:** start from an existing minimal VMM. **Default: libkrun** (embeddable, KVM-backed, already the isolation layer for several agent sandboxes). **Fallback: Firecracker** if snapshot/memslot control is easier to reach. Record the choice in an ADR after M1 spike.
- **Guest libc:** musl, static. No dynamic linker resolution at runtime in the guest.
- **Content addressing:** BLAKE3 for all hashes (fast, keyed-mode available for future attestation).

---

## 3. Repository layout

```
nouscell/
├── AGENTS.md                 # points here; house rules for the agent
├── NAMES_AND_CONVENTIONS.md  # canonical glossary — mote/cell, components, colours
├── crates/
│   ├── warden/               # per-cell VMM: wraps one microVM; KVM fds, vsock, sealing, ratchet
│   ├── pilot/                # mote PID 1: tool-call ABI, shell parser, taint, toolplane
│   ├── forgectl/             # host daemon: snapshot forest, CAS store, manifests, mmap server
│   ├── manifest/             # shared: signed manifest format, hash types, revocation feed
│   └── proto/                # protobuf defs for the control lane (local now, host-crossing later)
├── guest/
│   ├── kernel/               # Kconfig fragments + build; derived from M0 histogram — the mote kernel
│   └── motes/                # build recipes for the snapshot forest nodes (motes)
├── bench/
│   ├── harness/              # Python: runs trajectories, collects tokens/turns/wallclock/syscalls
│   ├── suites/               # task suites (SWE-bench subset, data, Node/JS, browser)
│   └── results/              # committed JSON baselines and runs
├── tests/                    # per-milestone acceptance tests (m0/ … m6/)
└── docs/
    ├── decisions/            # ADRs
    └── findings/             # milestone write-ups incl. kill-criterion hits
```

Write `AGENTS.md` first (M1 task 0). It should restate §0 and §1 and point at `NAMES_AND_CONVENTIONS.md`, so any sub-agent picking up a single crate inherits both the constraints and the vocabulary.

---

## 4. Claims under test

The whole point of the local proof is these three. Everything else is assembly of demonstrated parts.

| # | Claim | Proven by | If it fails |
|---|-------|-----------|-------------|
| C1 | A guest, even at ring 0, cannot modify lent tool code; one physical copy serves N guests | **M2** | Fall back to hash-verify-on-exec (weaker, no ring-0 guarantee). Re-evaluate whether project clears the bar. |
| C2 | Interpreter demotion closes the "trusted binary runs untrusted code" hole without breaking real work | **M4** | If laundering is unclosable or breakage >5% of tasks, the security story shrinks to isolation-only. |
| C3 | Legibility + warm materialisation measurably cut tokens, turns, and wall-clock at equal success rate | **M5** | If no delta, security must carry the project alone — escalate as a strategy decision. |

**The real risk is not the architecture — it's the compatibility surface.** The three claims are about the novel core (sealing, taint, economics), and that core survives. What can quietly kill adoption is workload breakage: jitless Node/V8 (5–20× on compute paths), browser automation (Chromium wants JIT + GPU-ish surfaces + `/dev/shm`), and shell-parser gaps. **Decide the target workload explicitly in M0** — if browser/heavy-Node is in scope, it must be in the M0 suite and have an owned answer; if not, say so in writing and ship an incompatibility list. Do not let these surface as mysterious task failures in M5.

---

## 5. Milestones

### M0 — Measure the workload (2 wks, parallel with M1)

**Goal:** replace every "we think this is safe to cut" with evidence.
**Proves:** nothing directly — produces the inputs to M4/M5 and the kernel config.

**Tasks**
- Build `bench/harness`: run N real agent trajectories in a stock Debian microVM under a **logging seccomp filter** and `strace`-equivalent syscall capture.
- Assemble `bench/suites`: a SWE-bench-style coding subset, a data-analysis set, **and — critically — a Node/JS set and a browser-automation (Playwright) set**, because those are the workloads most likely to break under jitless execution and must be measured, not assumed. Aim ≥ 2,000 trajectories total.
- Emit five artifacts to `bench/results/m0/`:
  1. `syscall_histogram.json` — frequency by syscall.
  2. `proc_access.json` — every `/proc` and `/sys` path read, by reading process.
  3. `tool_cooccurrence.json` — which tool sets appear together per trajectory (seeds the snapshot forest **and** the prebuilt-inventory list).
  4. `failure_taxonomy.json` — failed turns bucketed by cause (perm denied, parse error, missing tool, timeout, ambiguous output…), with token cost per bucket.
  5. `workload_profile.json` — JIT dependence and browser/GPU/`/dev/shm` usage by task class, to feed the scope decision below.

**Exit criteria (`tests/m0/`)**
- All five artifacts present and non-empty, generated reproducibly from a single command.
- Histogram shows a clear knee (expected: ~99.9% of calls in ≲70 syscalls, though `clone3`/`rseq`/`statx`/`membarrier`/`futex_waitv` will likely appear — let the data set the number, stop quoting ~70 until it does). Commit the knee cutoff as `guest/kernel/syscall_allowlist.json`.
- **Written scope decision** (`docs/decisions/0001-target-workload.md`): is heavy-Node / browser automation in or out? If in, it's in every later suite and needs an owned answer; if out, ship an incompatibility list. This decision gates who the product is for.

**Kill criterion:** if the long tail is fat (no clear knee, >150 syscalls needed for 99.9%), the stripped-kernel thesis is weaker than assumed — document and reconsider kernel scope before M5.

**Out of scope:** any Nouscell code. This milestone uses stock tooling only.

---

### M1 — The fork path (2–3 wks)

**Goal:** own the snapshot→fork code path we will later modify. Nothing novel; assembly only.
**Proves:** the speed floor is reachable.

**Tasks**
- Spike libkrun vs. Firecracker for snapshot + `mmap(MAP_PRIVATE)` + vCPU restore control. Write ADR-0001 with the choice.
- `warden` v0: take a warm snapshot, fork a KVM VM from it, run a trivial guest that prints and exits.
- Instrument spawn latency (task-arrival → guest first instruction) and per-idle-cell private RSS.

**Exit criteria (`tests/m1/`)**
- p99 spawn latency **< 5 ms** from a warm snapshot.
- Idle cell private memory **< 1 MB**.
- **1,000 concurrent** forks on the box, all reach guest userspace.
- Numbers committed to `bench/results/m1/`.

**Kill criterion:** if the chosen VMM can't reach single-digit-ms forks with shared read-only pages, revisit substrate before proceeding — M2 depends on the memslot model.

---

### M2 — The sealed store (4–6 wks) — GATING RISK, DO FIRST AND ALONE

**Goal:** prove C1. This is the milestone most likely to kill or bless the project.
**Proves:** hypervisor-sealed, hash-addressed tool execution.

**Tasks**
- `forgectl` v0 (store half): a content-addressed store on NVMe; a region that `warden` maps into guests via **read-only KVM memslots**. Verify stage-2 protection holds independent of guest page tables.
- **The VFS↔memslot join (ADR-0005 — the actual hard part).** A guest `mmap(PROT_EXEC)` of `/tools/python` must land on the sealed physical memslot, not a page-cache copy — otherwise you've sealed pages nothing executes from. Prototype DAX-style direct mapping (virtio-fs DAX window or an equivalent). If this doesn't work, C1 is not proven regardless of what the memslot test says. **Do this before the RSS-sharing measurement**, because sharing depends on it.
- **Memslot budget.** Measure memslot count and fragmentation at per-tool granularity; KVM has limits. If per-tool sealing exhausts them, the layer format (ADR-0004) must pack tools into coarser sealed regions.
- `pilot` v0: **exec-by-hash only.** `exec(blake3:…)` resolves against a signed manifest; there is no path-based exec that runs an unattested page. Provide `/usr/bin/python`-style names as manifest aliases.
- Build a **deliberately hostile guest kernel** for the test: one that tries to remap, write, or `mprotect` the tool region and execute the result.
- Measure host RSS with one CPython image shared across many guests (only meaningful once the VFS join works).
- Wire revocation: removing a hash from the manifest must stop execution in *already-running* guests.

**Exit criteria (`tests/m2/`)**
- Hostile guest attempting to write/remap tool pages **faults**; test asserts the fault and that tool bytes are unchanged.
- One CPython image demonstrably shared across **≥ 500 guests**; host RSS attributable to CPython is ~one copy (measure and assert against a ceiling).
- Revoking a hash halts its execution in running cells in **< 1 s**.
- Exec of an unattested hash is refused with a structured error.

**Kill criterion:** if memslot granularity, count limits, or VM-exit overhead make per-tool sealing impractical at scale → fall back to **hash-verify-on-exec** (pilot verifies page hashes before mapping executable; no ring-0 guarantee). Record in `docs/findings/m2.md` and flag: this weakens C1 materially.

**Out of scope:** the build farm (M3), taint (M4). Tools are hand-staged into the store here.

---

### M3 — The loan machinery + tiered trust (4–5 wks)

**Goal:** make `pip install` a host-side loan, invisibly, **and never slow.**
**Proves:** warm materialisation is a page-map; cold materialisation is seconds (Tier-2), never minutes.

**Tasks**
- Control lane: `proto/` defines the vsock protocol; implement local endpoints in `pilot` (client) and `forgectl` (server).
- **Layer as the unit (ADR-0004).** Injection maps a *layer* (sealed page-set + manifest delta + tier tag), not a package tarball. The pip/npm shim is the first consumer of this path.
- **Tiered resolution (ADR-0003).** `pip install X` resolves in this order: warm layer → **Tier-2** (hash-pin upstream wheel, scan, sign, map — seconds) → queue **Tier-1** hermetic rebuild in the *background*. Serve fast; upgrade trust async. The manifest records the tier served.
- **Prebuilt inventory.** Pre-forge the top ~500 PyPI + ~300 npm artifacts (from M0's co-occurrence data) as Tier-1 layers shipped with the build. The common path never sees a cold build.
- **Unsealed mode.** A Tier-3 cell type that runs anything with no attestation (still hardware-isolated) — the never-blocked onboarding path. Sealing is a per-workload ratchet, not a wall.
- `forgectl` build half v0: hermetic builder (Nix or equivalent) + signing key + scanner + mmap server. "Hermetic-enough" is acceptable locally; the production farm is out of scope.
- **Persistent workspace prototype:** a workspace volume that survives cell dissolution and re-mounts into the next cell.

**Exit criteria (`tests/m3/`)**
- **Warm** (`pip install numpy`, seen before) = page mapping in **< 10 ms**, behaviour identical to real pip.
- **Cold, unseen top-1000 package** = Tier-2 served in **< 10 s** (this is the number that protects adoption); a Tier-1 rebuild lands in the background and the manifest tier flips on the next cell.
- **Prebuilt inventory hit** = never a cold build for a top-500/300 artifact.
- Top-50 PyPI + top-30 npm packages install and import/run correctly at Tier-2 or better.
- Guest holds **no** registry credentials and makes **no** direct outbound connection during install (assert via the proxy log; TLS inspected via the Nouscell CA).
- Unsealed mode runs an arbitrary package the farm has never seen, with isolation intact and the manifest marking it Tier-3.

**Kill criterion:** if Tier-2 verify+sign+map can't hit <10 s for common native-extension packages, the cold path is too slow for adoption — record it; the fix is more prebuilt inventory, not a slower default.

---

### M4 — Taint lanes + the ratchet (4 wks)

**Goal:** prove C2.
**Proves:** two-lane provenance, interpreter demotion, host-enforced authority decay.

**Tasks**
- `pilot`: track one provenance bit per file — **tool lane** (manifest-attested) vs **data lane** (born in the cell). Inheritance: data-lane children and writes stay data-lane.
- **The laundering ban — and it must cover more than files.** A tool-lane interpreter fed tainted input is demoted *for that invocation*. The critical subtlety: taint arrives through **many channels, not just file arguments.** Each must be handled or explicitly deferred with justification:
  - **argv/string:** `python -c "<tainted>"`, `bash -c`, `node -e` — the input is a string, not a file. This is the sharpest hole; file-only taint tracking misses it entirely.
  - **stdin/pipes:** `curl … | sh`, `cat evil | python`.
  - **fd passing** across exec, **mmap** of tainted files, **env vars** as payload carriers, shebang indirection.
- Data-lane execution runs under a per-exec **Landlock + seccomp collar**: workspace-only FS view, no control-lane access, no privileged verbs.
- `warden`: the ratchet. On the **first tainted execve** (a kernel-observable event reported by pilot, re-verified host-side), permanently revoke materialisation + host-fetch verbs for that lineage. On task completion, disable exec entirely (dissolve phase).
- **Red-team weeks (plural — budget two, not one).** Attempt laundering via every channel above plus `memfd`, ptrace-alikes, and shared memory. Most low-level vectors should already be compiled out — assert it; the string/pipe channels are the ones that need real logic.

**Exit criteria (`tests/m4/`)**
- No laundering path found across **all named channels** (each has a test asserting it's blocked or absent). The argv/string and pipe channels are explicitly covered, not just file inputs.
- Ratchet transitions hold **even with a cooperatively-malicious pilot** (warden enforces; test injects a lying pilot).
- **Tiered breakage budget** (5% flat is too generous — at fleet scale 5% task failure is catastrophic): **< 0.5%** of the coding suite breaks under the collars; a documented incompatibility list covers the rest. Measured against the M0 baseline.
- The ratchet phase is part of any checkpoint (forward-declare the field even though cross-host migration is out of scope).

**Kill criterion:** any named laundering channel unclosable, or coding-suite breakage > 0.5% → C2 fails as stated; record and reduce the security claim to isolation-only.

---

### M5 — Stripped guest + toolplane, and the money benchmark (4–6 wks)

**Goal:** prove C3 — the economics.
**Proves:** the whole thesis pays off in tokens, turns, and wall-clock.

**Tasks**
- Build the **mote kernel** from `guest/kernel/syscall_allowlist.json` (M0). No block layer, modules, io_uring, userfaultfd, eBPF, perf, ptrace, ACPI, swap, USB/sound/graphics, SysV IPC, in-kernel net. The mote is this kernel + pilot; a cell is a sealed, tool-loaned fork of it. **Note the maintenance cost:** a bespoke kernel config is a forever security-patch burden — track upstream CVEs against the enabled config; this is real ongoing work, not a one-time cut.
- **Synthetic `/proc` and `/sys/fs/cgroup`** that lie correctly: Go's `GOMAXPROCS`, the JVM's heap sizing, and Node's `os.cpus()`/`meminfo` must see the cell's real limits, not the host's. **Reuse lxcfs's decade of prior art here — don't rediscover it.** Test each runtime explicitly.
- **JIT policy (from the M0 scope decision).** If heavy-Node/browser is in scope, jitless V8 is a 5–20× tax on compute paths — decide per workload whether JIT output runs as data-lane code (writable-then-executable, collared) or the workload is de-scoped. Do not let this appear as a mystery slowdown in the benchmark.
- **Toolplane** static multicall binary: coreutils surface (`ls cat grep find stat tar …`) rewritten for machine callers — deterministic output ordering, structured JSON on a dedicated fd, human-readable text on stdout, explicit exit taxonomies, no TTY detection, no color, no locale variance.
- **Shell strategy — staged (ADR-0006).** Ship **shell-as-telemetry first**: parse POSIX `sh`, execute via a real `sh`, log every construct and any parser gap. Promote to **shell-as-executor** (structured exec graph, no `/bin/sh`) only for constructs the telemetry proves are safe. This keeps the "compatibility is a feature" principle from fighting the parser.
- The **`explain` verb:** any denial anywhere returns a structured cause+remedy record.
- **The benchmark:** same M0 task suite, same model, stock Debian sandbox vs. Nouscell. Report tokens/task, failed turns/task, wall-clock/task, and success rate — **broken out by workload class**, so a Node/browser regression can't hide inside a coding-suite win.

**Exit criteria (`tests/m5/`)**
- Kernel builds and boots to a snapshot with the M0 allowlist; guest passes the M0 trajectory suite (compat check).
- Go/JVM/Node correctly detect a 2-core/2 GB cell on a large host (assert reported values).
- Measurable reduction in **tokens/task AND failed-turns/task AND wall-clock/task**, with **success rate not regressing on the coding suite**, vs. the committed M0 baseline. Regressions on out-of-scope workload classes are acceptable *only if* M0 declared them out of scope.
- Shell-as-telemetry covers the M0 shell corpus; the gap list is committed and non-growing.
- `explain` returns a valid structured record for each denial class in `failure_taxonomy.json`.

**Kill criterion:** no economic delta → C3 fails. Escalate: does isolation + supply-chain alone justify the project? Strategy decision, not an engineering one.

---

### M6 — Density + the kill wire (2 wks)

**Goal:** the headline numbers.
**Proves:** the density economics and revocation latency under load.

**Tasks**
- Saturate one box: thousands of live cells doing real M0 work. Plot dirty-page growth over cell lifetime.
- Fire fleet-local (host-local) revocations while under load; measure propagation to running cells.

**Exit criteria (`tests/m6/`)**
- A defensible **"N concurrent agents per host"** number, with the methodology committed.
- Revocation p99 under load committed to `bench/results/m6/`.

---

## 6. Sequencing & staffing

```
Week →  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 20 22 24
M0     ███
M1     ██████
M2        █████████████████         ← alone; gates everything (incl. VFS join)
M3                    ██████████
M4                    █████████████  ← overlaps M3 tail; two red-team weeks
M5                                 ██████████████
M6                                              ████
```

- **~3–4 engineers, ~3–4 quarters** — the original "3 engineers, 2 quarters" was optimistic by ~1.5–2×. M2 alone is deep systems work (memslots + the VFS↔memslot join + a hostile-guest harness), and the network-ABI work (ADR-0002) and taint channels (M4) are heavier than a first read suggests.
- **One engineer owns `bench/` full-time** from day one — the eval harness is a product asset, not test scaffolding, and C3 lives or dies on its rigour.
- M2 is solo and first among the novel work, and now explicitly includes the VFS↔memslot join. Do not let M3/M4 start against an unproven store.

---

## 7. The proof demo — definition of done

One recorded run on one bare-metal box, showing all beats in sequence:

1. **Seal from intent** — a task arrives, classifier routes to the nearest warm snapshot, cell reaches first instruction in ~1 ms (no boot).
2. **Loan a warm tool** — `pip install <seen-pkg>` resolves as a host-side page map, not a download; agent sees normal pip.
3. **Cold tool, still fast** — `pip install <unseen-pkg>` is served Tier-2 in seconds; the manifest shows the tier, and a Tier-1 rebuild is queued in the background. *(This is the beat that answers "it's not acceptable to be slow.")*
4. **Demote on exec** — the agent runs its own script (and a `python -c "<string>"`); both execute collared as data-lane despite using an attested interpreter.
5. **Kill fleet-wide** — a tool hash is revoked mid-task; execution of that hash halts in the running cell in < 1 s.
6. **Task still completes** — the agent finishes despite the revocation (permitted alternative), and the cell transitions to read-only harvest, then dissolves — while its **persistent workspace survives** into a fresh cell.

If that run records cleanly and each beat has a passing test behind it, the local story is proven and the K8s/distribution phase is unblocked.

---

## 8. Explicitly out of scope (local proof)

Build the *interfaces* so these can exist later; build *none* of the implementations.

- Scheduler / placement / warmth index (define the `forgectl` protocol; don't route across hosts).
- Cross-host branching, checkpoint-delta format (forward-declare the checkpoint struct incl. ratchet phase; don't ship deltas).
- CDN / global content store / peer page fetch.
- Kubernetes CRDs, operator, pod-as-lease.
- GPU passthrough (VFIO) — noting it will force the hypervisor choice later.
- The production hardened, reproducible-from-source build farm. Local uses "hermetic-enough."

---

## 9. Guardrails for the executing agent

- When in doubt between two implementations, pick the one that **reduces guest attack surface** and is **reversible**; record it as an ADR.
- Never add a capability to the guest to make a test pass. If a test needs a capability the constraints forbid, the test is wrong or the milestone is mis-scoped — surface it.
- Treat a kill-criterion hit as a **successful, valuable outcome**. Write it up; don't engineer around it silently.
- Keep the distribution seam clean: `forgectl` talks a protocol, not function calls, from M3 onward.
- Every performance claim in this document must end as a committed number in `bench/results/`, not a comment in code.
