# nouscell

**Nouscell** ( _NOWSS-cell_ ) — an agent-native operating system: a tiny, fast,
hardware-isolated **cell** that intelligence is launched into, where every tool
is attested memory the host lends in and can revoke in microseconds.

> This repository is the **proof-of-concept**. It builds the trust core and the
> control-flow of the full design in Rust, and demonstrates the five-beat proof
> loop end-to-end in a **mock backend that runs on any host** — no KVM required.
> The hardware guarantees (real CoW fork, stage-2 page sealing) are M1/M2 in
> `docs/NOUSCELL_BUILD_PLAN.md` and require bare metal.

Rust for code · Make for orchestration · shell for glue.

---

## Quickstart

```sh
make doctor   # check host readiness (mock runs anywhere)
make build    # build the workspace
make test     # run the unit tests
make demo     # run the five-beat proof loop
```

## What's real vs stubbed

| Piece | Status | Where |
|-------|--------|-------|
| Content-addressed store (put/get by BLAKE3, dedup, integrity-checked reads) | **real, tested** | `crates/nous-store` |
| Manifest: exec-by-hash gate, revocation, stand-in signing | **real, tested** | `crates/nous-manifest` |
| Taint lanes + the laundering ban (incl. `python -c` arg-string channel) | **real, tested** | `crates/nous-manifest`, `crates/pilot` |
| Tiered resolution (warm → Verified → Forged async upgrade) | **real, tested** | `crates/forgectl` |
| Authority ratchet (P1→P2→P3, host-enforced, monotonic) | **real, tested** | `crates/warden` |
| VMM behind a trait; mock backend | **real, tested** | `crates/warden` (`vmm.rs`) |
| Real KVM backend (fork, stage-2 sealing) | **stub — returns Unsupported** | `crates/warden` (feature `kvm`) |
| Hermetic build farm (real forging) | **simulated** | `forgectl::Forge::run_one_rebuild` |
| Stripped mote kernel, vsock transport, guest musl userland | **not started** | build plan M1/M2/M5 |

The stubs are honest: the KVM backend returns `Unsupported` rather than faking a
hardware guarantee. The POC proves the **logic and control-flow**; it does not
claim the hardware properties yet.

## Layout

```
crates/
  nous-manifest/   shared types: Hash, Tier, Lane, Manifest, laundering ban
  nous-store/      content-addressed store (the on-disk half of forgectl)
  forgectl/        fleet daemon: tiered resolution + CLI  (where the distro lives)
  warden/          per-cell VMM: ratchet + VMM trait + mock/kvm backends
  pilot/           in-cell supervisor: exec-by-hash, lanes, explain + the demo
docs/              design corpus (proposal, build plan, conventions, diagrams)
scripts/           doctor.sh, demo.sh
```

## Vocabulary

- **mote** — the substrate at rest (stripped kernel + `pilot`). The seed.
- **cell** — a live, sealed, tool-loaned mote. The seed put to work. *Every cell is a sealed mote.*
- **forgectl / warden / pilot** — host daemon / per-cell VMM / in-cell supervisor. 1 warden : 1 microVM : 1 cell.

Full glossary: `docs/NAMES_AND_CONVENTIONS.md`.

## Status

Pre-alpha, single-host. Working name pending trademark/domain clearance.
See `docs/NOUSCELL_BUILD_PLAN.md` for the milestone plan this POC is the first slice of.
