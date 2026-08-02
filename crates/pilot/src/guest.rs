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
//! It will `execve` a program, but **only into the tool lane** — code whose
//! bytes hash to an attested entry and which was not fed anything the agent
//! wrote. Data-lane exec stays refused until the collar (Landlock + seccomp
//! per exec) exists, because running collared code before the collar exists
//! would be exactly backwards. The lane split is what makes that a principled
//! line rather than a missing feature.

use nous_manifest::{resolve_exec_lane, Hash, Input, Lane, Manifest};
use pilot::{exec, ExecOutcome};
use serde::Deserialize;

/// Report an observation the host can assert on, same protocol the guest init
/// uses: one `NOUS:key=value` line per fact, on the console.
fn report(key: &str, val: &str) {
    println!("NOUS:{key}={val}");
}

/// Where the host stages the cell's manifest and the tools it attested.
const MANIFEST: &str = "/nous/manifest.json";
const TOOLS_DIR: &str = "/nous/tools";

/// What the host asked this cell to run, if anything. Staged next to the
/// manifest rather than passed on the kernel cmdline: a request to run
/// something is data, and it goes through the same hash check as everything
/// else regardless of how it arrived.
const RUN_REQUEST: &str = "/nous/run.json";

#[derive(Deserialize)]
struct RunRequest {
    /// Where the bytes live in the cell — normally on the sealed DAX mount.
    path: String,
    /// What the agent calls it. Only used for reporting; authority comes from
    /// the hash, never from the name or the path.
    alias: String,
    #[serde(default)]
    args: Vec<String>,
    /// Whether the input this invocation is being fed was written by the agent.
    #[serde(default)]
    agent_authored_input: bool,
}

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

    run_requested(&manifest);

    report("pilot", "done");
    finish(0)
}

/// Run what the host asked for, if it asked for anything.
///
/// The path is where to find the bytes; it carries no authority. Authority
/// comes from hashing what is actually at that path and finding that hash in
/// the manifest. A tool swapped after attestation hashes differently and never
/// runs, which is the only reason a filesystem is safe to exec out of at all.
fn run_requested(manifest: &Manifest) {
    let Ok(bytes) = std::fs::read(RUN_REQUEST) else {
        return; // nothing asked of this cell
    };
    let req: RunRequest = match serde_json::from_slice(&bytes) {
        Ok(r) => r,
        Err(e) => {
            report("pilot_run", "unparseable");
            eprintln!("pilot: {RUN_REQUEST}: {e}");
            return;
        }
    };

    let Ok(code) = std::fs::read(&req.path) else {
        report(&format!("pilot_run_{}", req.alias), "absent");
        return;
    };
    let hash = Hash::of(&code);

    // Anything the agent wrote demotes this invocation, per the laundering ban.
    let input = if req.agent_authored_input {
        Input::File(Lane::Data)
    } else {
        Input::None
    };

    match exec(manifest, &hash, input) {
        ExecOutcome::Denied(e) => {
            report(&format!("pilot_run_{}", req.alias), "denied");
            for line in e.to_json().lines() {
                println!("NOUS:explain {line}");
            }
        }
        ExecOutcome::Run { lane, .. } => {
            report(&format!("pilot_run_{}", req.alias), &format!("permitted:{lane}"));

            // The honest line: the tool lane is code we attested and did not
            // feed anything the agent wrote, so it runs with authority. The
            // data lane needs the per-exec collar, and until that exists,
            // refusing is the only defensible answer.
            if lane != Lane::Tool {
                report(&format!("pilot_run_{}", req.alias), "refused:collar-absent");
                return;
            }

            // Everything between these markers is the program's own output.
            // The host slices on them so a cell can be piped like any process.
            println!("NOUS:out-begin");
            let status = std::process::Command::new(&req.path).args(&req.args).status();
            println!("NOUS:out-end");

            match status {
                Ok(s) => report(
                    &format!("pilot_run_{}_exit", req.alias),
                    &s.code().unwrap_or(-1).to_string(),
                ),
                Err(e) => {
                    report(&format!("pilot_run_{}", req.alias), "exec-failed");
                    eprintln!("pilot: exec {}: {e}", req.path);
                }
            }
        }
    }
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
