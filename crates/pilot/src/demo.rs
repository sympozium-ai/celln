//! `nous-demo` — the five-beat proof loop, in mock mode (no KVM required).
//!
//! This is the POC's headline: it drives assay (tiered resolution), warden
//! (the ratchet + mock VMM), and pilot (exec-by-hash + taint) through the exact
//! sequence the build plan's §7 defines, and prints each beat. Everything the
//! hardware would enforce is enforced here in software so the *control flow* is
//! demonstrable today; the hardware guarantees (sealing, real fork) are M1/M2.

use assay::Assayer;
use nous_manifest::{Hash, Input, Lane};
use pilot::{exec, ExecOutcome};
use warden::vmm::MockVmm;
use warden::{Cell, Phase};

fn beat(n: u8, title: &str) {
    println!("\n\x1b[36m● beat {n}\x1b[0m  {title}");
}

fn note(s: &str) {
    println!("   {s}");
}

fn main() -> anyhow::Result<()> {
    let tmp = std::env::temp_dir().join(format!("nous-demo-{}", std::process::id()));
    let mut assayer = Assayer::open(&tmp)?;

    println!("\x1b[1mNouscell POC — five-beat proof (mock mode)\x1b[0m");
    println!("store: {}", tmp.display());

    // Shipped inventory: python is pre-forged (Tier 1). This is what makes the
    // common path never cold.
    let py_hash = assayer.admit_verified("/usr/bin/python", b"cpython-3.13-bytes", true)?;

    // ---- beat 1: seal from intent ----
    beat(
        1,
        "seal from intent — fork a warm mote into a cell (~1ms in HW; mock here)",
    );
    let mut cell = Cell::seal("cell-001", MockVmm::new(), "mote:bare+python")?;
    note(&format!(
        "cell {} sealed, phase = {:?}",
        cell.id(),
        cell.phase()
    ));
    assert_eq!(cell.phase(), Phase::Materialise);

    // ---- beat 2: loan a warm tool ----
    beat(
        2,
        "loan a warm tool — pip install of a seen package is a page-map",
    );
    let r = assayer.resolve("/usr/bin/python", b"cpython-3.13-bytes", true)?;
    note(&format!(
        "resolve python -> {} tier={} warm={}",
        r.hash, r.tier, r.warm
    ));
    let bytes = assayer.fetch(&r.hash)?;
    cell.map_tool(&r.hash, &bytes)?;
    note("mapped python pages r-x into the cell");

    // ---- beat 3: cold tool, still fast ----
    beat(
        3,
        "cold tool, still fast — unseen package served Verified, Forged queued",
    );
    let r = assayer.resolve("/usr/lib/leftpad", b"leftpad-upstream-bytes", false)?;
    note(&format!(
        "resolve leftpad -> {} tier={} warm={} upgrade_queued={}",
        r.hash, r.tier, r.warm, r.upgrade_queued
    ));
    let bytes = assayer.fetch(&r.hash)?;
    cell.map_tool(&r.hash, &bytes)?;
    assayer.run_one_rebuild();
    note("background rebuild landed -> future cells get Forged");

    // ---- beat 4: demote on exec ----
    beat(
        4,
        "demote on exec — attested python fed agent-authored input uses the agent lane",
    );
    // The agent writes its own script (data lane) and runs it with python.
    match exec(assayer.manifest(), &py_hash, Input::File(Lane::Data)) {
        ExecOutcome::Run { lane, .. } => {
            note(&format!("python evil.py -> runs in {lane} lane (demoted)"));
            assert_eq!(lane, Lane::Data);
        }
        ExecOutcome::Denied(e) => panic!("unexpected denial: {}", e.to_json()),
    }
    // And the sharp channel: python -c "<tainted>"
    match exec(assayer.manifest(), &py_hash, Input::ArgString(Lane::Data)) {
        ExecOutcome::Run { lane, .. } => {
            note(&format!(
                "python -c \"<tainted>\" -> runs in {lane} lane (demoted)"
            ));
            assert_eq!(lane, Lane::Data);
        }
        ExecOutcome::Denied(e) => panic!("unexpected denial: {}", e.to_json()),
    }
    // first tainted exec ratchets authority shut
    cell.on_first_tainted_exec();
    note(&format!(
        "first tainted exec -> ratchet phase = {:?}",
        cell.phase()
    ));
    // materialising new tools is now permanently closed for this cell
    match cell.map_tool(&Hash::of(b"late-tool"), b"late-tool") {
        Err(e) => note(&format!("further tool loan denied: {e}")),
        Ok(_) => panic!("materialisation should be closed in Work phase"),
    }

    // ---- beat 5: kill fleet-wide ----
    beat(
        5,
        "kill fleet-wide — revoke a hash; it stops executing everywhere",
    );
    assayer.revoke(&py_hash);
    match exec(assayer.manifest(), &py_hash, Input::None) {
        ExecOutcome::Denied(e) => {
            note("python revoked; exec now refused with a structured explain:");
            for line in e.to_json().lines() {
                println!("       {line}");
            }
        }
        ExecOutcome::Run { .. } => panic!("revoked hash must not run"),
    }

    // ---- close: task completes, cell dissolves ----
    beat(
        6,
        "task completes -> cell dissolves (read-only harvest, then struck)",
    );
    cell.dissolve()?;
    note(&format!("cell phase = {:?}", cell.phase()));
    assert_eq!(cell.phase(), Phase::Dissolve);

    // cleanup
    let _ = std::fs::remove_dir_all(&tmp);

    println!("\n\x1b[32m✔ all five beats ran; control-flow proof holds in mock mode.\x1b[0m");
    println!(
        "  (hardware guarantees — real CoW fork, stage-2 page sealing — are M1/M2 on bare metal.)"
    );
    Ok(())
}
