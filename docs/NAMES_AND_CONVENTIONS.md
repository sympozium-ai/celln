# Nouscell — Names & Conventions

The canonical glossary. When a term is used in the build plan, the proposal, the diagrams, or the code, it means what it means here. If a document drifts from these definitions, this document wins.

---

## The core distinction (read first)

Two small-unit words do different jobs. Do not use them interchangeably — that collapse is the one naming risk in the system.

- **mote** — the *substrate at rest*. The stripped kernel plus `pilot`, as a snapshot image, before it is anything. The seed. Motes live in the snapshot forest.
- **cell** — a *live, sealed, tool-loaned instance* of a mote, running a task. The seed grown.

> **The rule:** every cell is a sealed mote. A mote becomes a cell when it is forked, sealed, and loaned tools. The mote is the seed; the cell is the seed put to work.

State it this way whenever the relationship matters, so the two terms stay a hierarchy and never become synonyms.

---

## Product

| Term | Pronunciation | Meaning |
|------|---------------|---------|
| **Nouscell** | NOWSS-cell | The product. _Nous_ (Greek νοῦς, mind/intellect) + _cell_ (sealed right-sized unit) → "a sealed cell of intelligence." Names the thesis, not the trend; says nothing about "agents." Working name, pending trademark/domain clearance. |

Thesis line: _software is a service the host provides to the process, not property the machine owns._

---

## Substrate & runtime units

| Term | Meaning | Register |
|------|---------|----------|
| **mote** | The stripped guest substrate: ~70-syscall Linux kernel (no in-kernel network stack) + `pilot` + static musl + empty tmpfs workspace. A bootable Linux image that is deliberately almost empty. Not a distribution — no userland, no package manager, no init beyond pilot. The thing stored in the snapshot forest. | lowercase, technical |
| **cell** | A running, hardware-isolated instance: a mote that has been CoW-forked, sealed, and had tool pages loaned into it. The unit that does work and then dissolves. | lowercase, technical |
| **snapshot forest** | The tree of warm motes (bare → +python → +python+scipy → …), pre-faulted, that cells are forked from. | descriptive |
| **layer** | The unit of tool delivery: a sealed page-set + manifest delta + tier tag. Pre-composed into motes (zero launch cost) or injected into a running cell (microseconds). | descriptive |

---

## Components (the daemons)

Plain, humble, lowercase role-names. They can be renamed into a themed set at branding time without touching architecture — but the roles are fixed.

| Component | Role | Runs where |
|-----------|------|------------|
| **assay** | Fleet daemon. Grades bytes and admits them: content-addressed store, manifests, tiers, authorship, revocation, page cache. The only component that touches the outside world. **This is where "the distro" lives** — the curated software moved off the guest and onto the host, into assay's store. Named for the assay office, which determines what a metal *is* and stamps a grade on it; it deliberately does not claim to have built anything. | host · privileged · one per host |
| **forge** | Build plane. Rebuilds an artifact from its recorded source — twice, in different directories — and reports whether the bytes matched. Makes the `Forged` tier **earned** rather than asserted. Separate from assay on purpose: the component that builds must not be the one that certifies its own build. | host · privileged |
| **warden** | Per-cell VMM. A thin, jailed userspace process that wraps and drives exactly one microVM (one cell). Holds the KVM fds, vsock, and sealed page maps; enforces the authority ratchet. Jailed so an escaped agent lands inside a process that has nothing. | host · unprivileged · one per cell |
| **pilot** | Cell supervisor. PID 1 inside the mote. The tool-call ABI, the shell-as-parser, the taint tracker, and the toolplane binary — one static binary that replaces init, shell, coreutils, and package manager. | guest · baked into every mote |

Relationship: **forge** rebuilds an artifact and proves it reproduced; **assay** grades what forge reports and owns the motes and the tools; **warden** turns one mote into one cell and steers its microVM; **pilot** runs inside and speaks to the workload. One warden : one microVM : one cell, always 1:1:1.

---

## Trust & provenance

| Term | Meaning |
|------|---------|
| **tool lane** | Files/pages that came through the attestation gate. Manifest-attested, hypervisor-sealed. Runs with the cell's full (small) authority. Rendered **teal**. |
| **data lane** | Files born inside the cell — agent scripts, downloads, JIT output. Can execute, but always under a per-exec Landlock+seccomp collar. Rendered **amber**. |
| **the laundering ban** | An attested (tool-lane) interpreter fed tainted input — via argv, stdin/pipe, file, fd, mmap, or env — is demoted to data lane for that invocation. `python -c "<tainted>"` runs collared even though python is attested. |
| **the authority ratchet** | A cell's rights only shrink, enforced host-side by warden. **P1 Materialise** → **P2 Work** (first tainted exec revokes materialisation for the lineage) → **P3 Dissolve** (exec disabled, read-only harvest, then struck). |

### Trust tiers

| Tier | Name | What | Speed |
|------|------|------|-------|
| **1** | Forged | rebuilt hermetically from source, signed | minutes · background only |
| **2** | Verified | upstream binary hash-pinned, scanned, signed | seconds · the cold path |
| **3** | Unsealed | no attestation, still hardware-isolated | instant · onboarding / escape hatch |

Rule: **serve fast, upgrade trust async.** Cold requests get Tier 2 now; a Tier-1 rebuild runs behind the traffic.

---

## Lifecycle verbs

| Verb | Meaning |
|------|---------|
| **seal** | `seal(intent) → cell`. The lifecycle spawn: CoW-fork a mote, seal it, loan tools. Literally a fork, ~1 ms. |
| **dissolve** | End of life: exec disabled, workspace harvested read-only, cell struck. Nothing persists unless the workspace volume was made persistent. |
| **demote** | Move an invocation from tool lane to data lane (the laundering ban in action). |
| **revoke** | Yank a hash from the manifest; execution of it halts in all running cells, < 1 s. |

---

## Colour convention (diagrams & UI)

| Colour | Means |
|--------|-------|
| **teal** `#5fd0b5` | host-lent · attested · tool lane |
| **amber** `#e8a15f` | guest-born · collared · data lane |
| **blue** `#7aa2d6` | host plane · trusted components |
| **red** `#e06c5f` | danger / dissolve / revocation moments |

Apply strictly: teal is always "lent," amber is always "born." Do not use them decoratively.

---

## Usage examples (for consistent prose)

- ✔ "Cells are forked from warm motes in the snapshot forest."
- ✔ "The mote is ~70 syscalls plus pilot; a cell is a sealed mote with tools loaned in."
- ✔ "warden wraps one microVM per cell."
- ✔ "The tool ran in the data lane because it was fed a tainted file."
- ✘ "Spin up a mote to run the task." → a *cell* runs the task; a mote is the substrate it's forked from.
- ✘ "The mote dissolved." → *cells* dissolve; motes are immutable images.
