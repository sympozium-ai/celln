//! `nous-demo-kvm` — the five-beat proof loop on REAL KVM.
//!
//! Same control-flow as `nous-demo`, but every hardware claim is now enforced
//! by the CPU via `/dev/kvm` and *demonstrated*, not asserted:
//!
//!   * the cell is a genuine microVM, forked CoW from a warm template (timed);
//!   * tools are sealed in as stage-2 read-only pages — the guest executes
//!     code straight out of a sealed page, and a guest write to it exits to
//!     the host instead of landing;
//!   * revocation unmaps pages from the RUNNING cell;
//!   * dissolve freezes the whole cell read-only while the host harvests.
//!
//! Requires /dev/kvm. Run with: make demo-kvm

use assay::Assayer;
use nous_manifest::{Input, Lane};
use pilot::{exec, ExecOutcome};
use std::time::Instant;
use warden::vmm::kvm::{self, guest, GuestEvent, KvmVmm, RunEnd};
use warden::{Cell, Phase};

fn beat(n: u8, title: &str) {
    println!("\n\x1b[36m● beat {n}\x1b[0m  {title}");
}

fn note(s: &str) {
    println!("   {s}");
}

fn main() -> anyhow::Result<()> {
    if !std::path::Path::new("/dev/kvm").exists() {
        eprintln!("no /dev/kvm on this host — run `make demo` for the mock proof instead");
        std::process::exit(1);
    }

    let tmp = std::env::temp_dir().join(format!("nous-demo-kvm-{}", std::process::id()));
    let mut assayer = Assayer::open(&tmp)?;

    println!("\x1b[1mCelln M1 — five-beat proof on REAL KVM\x1b[0m");
    println!("store: {}", tmp.display());

    // Shipped inventory: "python" is pre-forged. Its bytes are real guest code
    // (write 0x99 to scratch, halt) so the cell can execute the sealed page.
    let py_bytes = guest::tool_stub(kvm::SCRATCH, 0x99);
    let py_hash = assayer.admit_verified("/usr/bin/python", &py_bytes, true)?;
    let snapshot = "mote:bare+python";

    // ---- beat 1: seal from intent — fork a real microVM, timed ----
    beat(
        1,
        "seal from intent — CoW-fork a warm mote into a REAL microVM",
    );
    let t0 = Instant::now();
    let mut cell = Cell::seal("cell-kvm-001", KvmVmm::new()?, snapshot)?;
    let fork_a = t0.elapsed();
    let t1 = Instant::now();
    let cell_b = Cell::seal("cell-kvm-002", KvmVmm::new()?, snapshot)?;
    let fork_b = t1.elapsed();
    note(&format!(
        "cell {} sealed in {:?} (vm+vcpu+CoW ram); second cell {} in {:?}",
        cell.id(),
        fork_a,
        cell_b.id(),
        fork_b
    ));
    let marker = kvm::template_marker(snapshot);
    assert_eq!(cell.vmm().read_ram(kvm::MARK_OFF, marker.len())?, marker);
    cell.vmm_mut().write_ram(kvm::MARK_OFF, b"DIRTY")?;
    assert_eq!(cell_b.vmm().read_ram(kvm::MARK_OFF, marker.len())?, marker);
    note("CoW proof: cell-001 dirtied its RAM; cell-002 still sees the pristine template");
    assert_eq!(cell.phase(), Phase::Materialise);

    // ---- beat 2: loan a warm tool ----
    beat(
        2,
        "loan a warm tool — attested python sealed in as stage-2 read-only pages",
    );
    let r = assayer.resolve("/usr/bin/python", &py_bytes, true)?;
    let bytes = assayer.fetch(&r.hash)?;
    cell.map_tool(&r.hash, &bytes)?;
    let py_gpa = cell.vmm().tool_gpa(&r.hash).expect("python just mapped");
    note(&format!(
        "resolve python -> tier={} warm={}; sealed at GPA {py_gpa:#x} (KVM_MEM_READONLY)",
        r.tier, r.warm
    ));
    // the cell executes code straight OUT of the sealed page
    cell.vmm_mut()
        .write_ram(kvm::ENTRY as usize, &guest::prog_jmp_far(py_gpa as u16))?;
    let rep = cell.vmm_mut().run_guest(kvm::ENTRY)?;
    assert_eq!(rep.end, RunEnd::Halted);
    assert_eq!(cell.vmm().read_ram(kvm::SCRATCH as usize, 1)?, [0x99]);
    note("vCPU jumped into the sealed page and ran it: scratch = 0x99 (r-x proven by execution)");

    // ---- beat 3: cold tool, still fast ----
    beat(
        3,
        "cold tool, still fast — unseen package served Verified, Forged queued",
    );
    let r = assayer.resolve("/usr/lib/leftpad", b"leftpad-upstream-bytes", false)?;
    note(&format!(
        "resolve leftpad -> tier={} warm={} upgrade_queued={}",
        r.tier, r.warm, r.upgrade_queued
    ));
    let bytes = assayer.fetch(&r.hash)?;
    cell.map_tool(&r.hash, &bytes)?;
    assayer.run_one_rebuild();
    note("mapped; background rebuild landed -> future cells get Forged");

    // ---- beat 4: the hardware seal, attacked ----
    beat(
        4,
        "attack the seal — guest writes to the sealed python page; the CPU says no",
    );
    let attack = guest::prog_poke_then_mark(py_gpa as u16, 0x41, kvm::SCRATCH, 0x55);
    cell.vmm_mut().write_ram(kvm::ENTRY as usize, &attack)?;
    let rep = cell.vmm_mut().run_guest(kvm::ENTRY)?;
    assert!(rep
        .events
        .contains(&GuestEvent::SealedWriteBlocked { gpa: py_gpa }));
    assert_eq!(
        cell.vmm().tool_bytes(&py_hash, 0, 1).expect("still mapped"),
        py_bytes[..1]
    );
    assert_eq!(cell.vmm().read_ram(kvm::SCRATCH as usize, 1)?, [0x55]);
    note(&format!(
        "guest write to {py_gpa:#x} exited to host (KVM_EXIT_MMIO) — page byte intact, guest kept running"
    ));
    // lane policy on top of the hardware: attested python fed tainted input is demoted
    match exec(assayer.manifest(), &py_hash, Input::File(Lane::Data)) {
        ExecOutcome::Run { lane, .. } => {
            assert_eq!(lane, Lane::Data);
            note("pilot: python evil.py -> demoted to data lane (laundering ban)");
        }
        ExecOutcome::Denied(e) => panic!("unexpected denial: {}", e.to_json()),
    }
    cell.on_first_tainted_exec();
    note(&format!(
        "first tainted exec -> ratchet phase = {:?}; tool loans now closed",
        cell.phase()
    ));

    // ---- beat 5: kill fleet-wide, live ----
    beat(
        5,
        "kill fleet-wide — revoke python; pages vanish from the RUNNING cell",
    );
    assayer.revoke(&py_hash);
    cell.revoke_tool(&py_hash)?;
    let probe = guest::prog_copy_byte(py_gpa as u16, kvm::SCRATCH);
    cell.vmm_mut().write_ram(kvm::ENTRY as usize, &probe)?;
    let rep = cell.vmm_mut().run_guest(kvm::ENTRY)?;
    assert!(rep
        .events
        .contains(&GuestEvent::UnmappedRead { gpa: py_gpa }));
    assert_eq!(cell.vmm().read_ram(kvm::SCRATCH as usize, 1)?, [0x00]);
    note("guest probe of the old python GPA reads unmapped zeros — revocation reached a live cell");
    match exec(assayer.manifest(), &py_hash, Input::None) {
        ExecOutcome::Denied(e) => {
            note("and the manifest gate refuses it everywhere:");
            for line in e.to_json().lines() {
                println!("       {line}");
            }
        }
        ExecOutcome::Run { .. } => panic!("revoked hash must not run"),
    }

    // ---- beat 6: dissolve ----
    beat(
        6,
        "task completes -> dissolve: cell frozen read-only, host harvests",
    );
    cell.vmm_mut()
        .write_ram(kvm::ENTRY as usize, &guest::prog_poke(kvm::SCRATCH, 0x21))?;
    cell.dissolve()?;
    let rep = cell.vmm_mut().run_guest(kvm::ENTRY)?;
    assert!(rep
        .events
        .iter()
        .any(|e| matches!(e, GuestEvent::SealedWriteBlocked { .. })));
    let harvest = cell.vmm().read_ram(kvm::MARK_OFF, 5)?;
    note(&format!(
        "guest write after freeze: blocked by hardware; host harvest reads workspace: {:?}",
        String::from_utf8_lossy(&harvest)
    ));
    assert_eq!(cell.phase(), Phase::Dissolve);

    let _ = std::fs::remove_dir_all(&tmp);

    println!("\n\x1b[32m✔ all five beats ran on real KVM hardware.\x1b[0m");
    println!(
        "  fork latency: {fork_a:?} (first, incl. template create) / {fork_b:?} (warm template)"
    );
    println!(
        "  seal, revocation and freeze were enforced by EPT below the guest — not by software."
    );
    Ok(())
}
