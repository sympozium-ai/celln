# AGENTS.md — house rules

Read this before touching the code. It inherits the constraints and vocabulary
of the design corpus in `docs/`.

## Vocabulary (non-negotiable)

- **mote** = the substrate at rest (stripped kernel + `pilot`). **cell** = a
  live, sealed, tool-loaned mote. *Every cell is a sealed mote.* Never use the
  two interchangeably. Full glossary: `docs/NAMES_AND_CONVENTIONS.md`.
- Components: `forgectl` (host daemon, where the distro lives), `warden` (per-cell
  VMM), `pilot` (in-cell supervisor). 1 warden : 1 microVM : 1 cell.

## Constraints (from the build plan §1)

1. The guest never boots in the hot path — spawn is a CoW fork of a warm mote.
2. No in-kernel network stack; AF_INET is marshalled over vsock to a host proxy.
3. The filesystem has no authority to run code — exec is by content hash against
   a signed manifest.
4. Tool code is unwritable from the guest side (stage-2 sealing).
5. Authority only shrinks — the ratchet is host-enforced in `warden`.
6. Compatibility is a feature — every ABI break is a silent latency tax.

## Working rules

- **Never fake a hardware guarantee.** If a backend can't provide a property,
  return `Unsupported` (see `warden::vmm::kvm`). A stub that lies is worse than a
  stub that refuses.
- **Prefer measurement over assertion.** Performance claims become committed
  numbers, not comments.
- **Reduce guest attack surface and stay reversible** when choosing between
  implementations; record the choice as an ADR in `docs/decisions/`.
- Rust for code, Make for orchestration, shell for glue. No Python.
- `make ci` must stay green: `fmt-check build test`.

## Where things are

- Trust core (no I/O): `crates/nous-manifest`
- Store: `crates/nous-store`
- Tiered resolution + CLI: `crates/forgectl`
- Ratchet + VMM trait/backends: `crates/warden`
- Exec gate + lanes + explain + demo: `crates/pilot`
