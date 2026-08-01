//! `nous-pilot` — pilot, running **inside the cell**.
//!
//! Everything else in this crate is a library the host links against. This is
//! the binary that runs in the guest, and it is the first piece of pilot to do
//! so. Built statically against musl so it needs nothing from the guest
//! filesystem: the initramfs carries this one file and a manifest.
//!
//! What it does today, which is the whole of pilot's security-critical job:
//!
//!   1. Read the signed manifest the host staged in the cell.
//!   2. For each thing it is asked to run, hash the actual bytes and check
//!      that hash against the manifest — **exec-by-hash**. The filesystem has
//!      no authority to run code; only content does.
//!   3. Apply the laundering ban: an attested interpreter fed input the agent
//!      wrote is demoted to the collared lane for that invocation.
//!   4. Refuse with a structured record rather than an error string, because
//!      the failure surface is how an agent corrects itself.
//!
//! What it does not do yet: actually `execve` anything. That needs the
//! collar (Landlock + seccomp per exec) to exist first, and running code
//! before the thing that constrains it would be exactly backwards.

use nous_manifest::{resolve_exec_lane, Hash, Input, Lane, Manifest};
use pilot::{exec, ExecOutcome};

/// Report an observation the host can assert on, same protocol the guest init
/// uses: one `NOUS:key=value` line per fact, on the console.
fn report(key: &str, val: &str) {
    println!("NOUS:{key}={val}");
}

/// Where the host stages the cell's manifest and the tools it attested.
const MANIFEST: &str = "/nous/manifest.json";
const TOOLS_DIR: &str = "/nous/tools";

fn main() {
    report("pilot", "alive");

    let manifest: Manifest = match std::fs::read(MANIFEST) {
        Ok(bytes) => match serde_json::from_slice(&bytes) {
            Ok(m) => m,
            Err(e) => {
                report("pilot_manifest", "unparseable");
                eprintln!("pilot: {MANIFEST}: {e}");
                return finish(1);
            }
        },
        Err(_) => {
            report("pilot_manifest", "absent");
            return finish(1);
        }
    };

    // A manifest that does not verify is not a manifest. Say so loudly: this
    // is the difference between attested execution and a list of hashes.
    let signed = manifest.verify_standin();
    report("pilot_manifest", if signed { "signed" } else { "UNSIGNED" });
    report("pilot_entries", &manifest.len().to_string());

    // Everything the host staged, hashed here rather than trusted. A tool that
    // was tampered with between attestation and now hashes differently and is
    // refused, which is the entire point of exec-by-hash.
    let mut checked = 0usize;
    let mut permitted = 0usize;
    if let Ok(dir) = std::fs::read_dir(TOOLS_DIR) {
        let mut entries: Vec<_> = dir.filter_map(|e| e.ok()).map(|e| e.path()).collect();
        entries.sort();
        for path in entries {
            let Ok(bytes) = std::fs::read(&path) else {
                continue;
            };
            checked += 1;
            let hash = Hash::of(&bytes);
            let name = path.file_name().unwrap_or_default().to_string_lossy();

            // The agent wrote whatever this is being fed, so an interpreter
            // must be demoted. That is the laundering ban, applied in-cell.
            match exec(&manifest, &hash, Input::File(Lane::Data)) {
                ExecOutcome::Run { lane, .. } => {
                    permitted += 1;
                    report(&format!("pilot_exec_{name}"), &format!("permitted:{lane}"));
                    // Say why, since "tool" vs "data" is the whole decision.
                    if let Some(entry) = manifest.get(&hash) {
                        let undemoted = resolve_exec_lane(entry, Input::None);
                        if undemoted != lane {
                            report(
                                &format!("pilot_demoted_{name}"),
                                "interpreter fed agent-authored input",
                            );
                        }
                    }
                }
                ExecOutcome::Denied(e) => {
                    report(&format!("pilot_exec_{name}"), "denied");
                    // The structured record, on the console, for the agent.
                    for line in e.to_json().lines() {
                        println!("NOUS:explain {line}");
                    }
                }
            }
        }
    }
    report("pilot_checked", &checked.to_string());
    report("pilot_permitted", &permitted.to_string());

    // An unattested hash must be refused even though nothing else about it is
    // suspicious. Proving that in-cell, every boot, is cheap.
    let ghost = Hash::of(b"code the agent wrote itself");
    match exec(&manifest, &ghost, Input::None) {
        ExecOutcome::Denied(_) => report("pilot_unattested", "refused"),
        ExecOutcome::Run { .. } => report("pilot_unattested", "PERMITTED"),
    }

    report("pilot", "done");
    finish(0)
}

/// Pilot is PID 1 in a cell, so returning is not an option — the kernel panics
/// if init exits. Ask for a reboot, which the host sees as a clean shutdown.
///
/// Only when we are actually PID 1. Running this binary on a developer's own
/// machine as root would otherwise reboot their machine, which is not a
/// mistake anyone should be able to make twice.
fn finish(code: i32) {
    println!("NOUS:done");
    if std::process::id() == 1 {
        unsafe {
            libc::sync();
            libc::reboot(libc::RB_AUTOBOOT);
        }
    }
    std::process::exit(code);
}
