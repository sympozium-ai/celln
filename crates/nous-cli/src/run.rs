//! The verbs that do something.

use crate::exit;
use crate::host::Host;
use crate::out::{bold, dim, green, red, Out};
use anyhow::{Context, Result};
use assay::Assayer;
use nous_manifest::{Hash, Input, Lane, Tier};
use nous_spec::Spec;
use std::path::Path;

/// Map the spec's tier vocabulary onto the manifest's.
fn tier_of(t: nous_spec::Tier) -> Tier {
    match t {
        nous_spec::Tier::Forged => Tier::Forged,
        nous_spec::Tier::Verified => Tier::Verified,
        nous_spec::Tier::Unsealed => Tier::Unsealed,
    }
}

fn input_of(i: nous_spec::Input, lane: Lane) -> Input {
    match i {
        nous_spec::Input::None => Input::None,
        nous_spec::Input::Tool => Input::File(Lane::Tool),
        nous_spec::Input::Data => Input::File(lane),
    }
}

/// Load a spec, reporting problems the way a compiler would.
fn load(path: &Path, o: &Out) -> Result<Spec, u8> {
    match Spec::load(path) {
        Ok(s) => Ok(s),
        Err(nous_spec::SpecError::Invalid { path, problems }) => {
            if o.is_json() {
                for p in &problems {
                    o.event(
                        "spec_problem",
                        serde_json::json!({"field": p.field, "message": p.message, "fix": p.fix}),
                        "",
                    );
                }
            } else {
                eprintln!("{} in {}", red("invalid spec"), path.display());
                for p in &problems {
                    eprintln!("  {} {}", red("✘"), p.field);
                    eprintln!("    {}", p.message);
                    eprintln!("    {}", dim(&format!("fix: {}", p.fix)));
                }
            }
            Err(exit::SPEC_INVALID)
        }
        Err(e) => {
            eprintln!("{}: {e}", red("error"));
            Err(exit::SPEC_INVALID)
        }
    }
}

/// `nous spec check` — validate, then say what would happen.
pub fn check(path: &Path, o: &Out) -> Result<u8> {
    let spec = match load(path, o) {
        Ok(s) => s,
        Err(code) => return Ok(code),
    };

    for w in spec.warnings() {
        if o.is_json() {
            o.event(
                "spec_warning",
                serde_json::json!({"field": w.field, "message": w.message}),
                "",
            );
        } else {
            o.warn(format!("{}: {}", w.field, w.message));
        }
    }

    o.event(
        "spec_ok",
        serde_json::json!({
            "name": spec.name,
            "memory_bytes": spec.memory_bytes(),
            "require_tier": spec.cell.require_tier.to_string(),
            "tools": spec.tools.len(),
        }),
        format!(
            "{} {}  {} tool(s), {} memory, require_tier={}",
            green("✔"),
            bold(&spec.name),
            spec.tools.len(),
            spec.cell.memory,
            spec.cell.require_tier
        ),
    );

    // The part worth reading: what each tool becomes, and how the declared run
    // would be classified. This is the whole trust model, applied to your file,
    // before you run anything.
    o.say("");
    o.say(bold("tools"));
    for t in &spec.tools {
        let kind = if t.interpreter {
            "interpreter"
        } else {
            "binary"
        };
        o.event(
            "tool",
            serde_json::json!({"alias": t.alias, "path": t.path, "interpreter": t.interpreter}),
            format!(
                "  {:<24} {}  {}",
                t.alias,
                dim(kind),
                dim(&t.path.display().to_string())
            ),
        );
    }

    if let Some(run) = &spec.run {
        let interp = spec
            .tools
            .iter()
            .find(|t| t.alias == run.exec)
            .map(|t| t.interpreter)
            .unwrap_or(false);
        let demoted = interp && run.input == nous_spec::Input::Data;
        let lane = if demoted { "data" } else { "tool" };
        o.say("");
        o.say(bold("run"));
        o.event(
            "run_plan",
            serde_json::json!({
                "exec": run.exec, "args": run.args,
                "input": format!("{:?}", run.input).to_lowercase(),
                "lane": lane, "demoted": demoted,
            }),
            format!(
                "  {} {}\n  runs in the {} lane{}",
                run.exec,
                run.args.join(" "),
                bold(lane),
                if demoted {
                    dim(" — demoted: an interpreter fed agent-authored input")
                } else {
                    String::new()
                }
            ),
        );
    }

    let h = Host::probe();
    if !h.can_seal() {
        o.note(dim(
            "\nthis host cannot seal cells; `nous run` would refuse. `nous doctor` says why.",
        ));
    }
    Ok(exit::OK)
}

/// `nous run` — seal a cell from the spec and drive its lifecycle.
pub fn run(path: &Path, root: &Path, dry_run: bool, o: &Out) -> Result<u8> {
    let spec = match load(path, o) {
        Ok(s) => s,
        Err(code) => return Ok(code),
    };
    for w in spec.warnings() {
        o.warn(format!("{}: {}", w.field, w.message));
    }

    let h = Host::probe();
    if !h.can_seal() {
        eprintln!(
            "{}: this host cannot seal cells. Run `nous doctor`.",
            red("error")
        );
        return Ok(exit::HOST_INCAPABLE);
    }

    let mut assayer =
        Assayer::open(root).with_context(|| format!("opening store {}", root.display()))?;

    // Write the cell down before it exists, so `nous ps` can see it while it
    // runs and still has a record if this process is killed mid-cell.
    let mut record = crate::cells::begin(
        root,
        &spec.name,
        path,
        spec.tools.iter().map(|t| t.alias.clone()).collect(),
    )
    .ok();

    o.event(
        "cell_sealing",
        serde_json::json!({"name": spec.name, "memory_bytes": spec.memory_bytes()}),
        format!("{} sealing cell {}", green("●"), bold(&spec.name)),
    );

    // Resolve every tool the spec asks for. Warm ones are a page map; cold ones
    // are admitted at Verified now and queued for a Forged rebuild behind the
    // traffic — serve fast, upgrade trust async.
    let mut resolved = Vec::new();
    for t in &spec.tools {
        let bytes = std::fs::read(&t.path)
            .with_context(|| format!("reading tool {} from {}", t.alias, t.path.display()))?;
        let r = assayer.resolve(&t.alias, &bytes, t.interpreter)?;
        o.event(
            "tool_resolved",
            serde_json::json!({
                "alias": t.alias, "hash": r.hash.to_string(), "tier": r.tier.to_string(),
                "warm": r.warm, "upgrade_queued": r.upgrade_queued, "bytes": bytes.len(),
            }),
            format!(
                "  {} {:<22} {} {}",
                if r.warm { "≡" } else { "+" },
                t.alias,
                dim(&format!("tier={}", r.tier)),
                dim(if r.warm {
                    "warm — page map, no build"
                } else {
                    "cold — verified now, forged queued"
                })
            ),
        );
        if r.tier > tier_of(spec.cell.require_tier) {
            o.warn(format!(
                "{} is {} but the spec requires {} — it will run in the agent lane",
                t.alias, r.tier, spec.cell.require_tier
            ));
        }
        resolved.push((t.clone(), r.hash, bytes));
    }

    if dry_run {
        o.event(
            "dry_run",
            serde_json::json!({"sealed": false}),
            format!(
                "{} dry run: resolved {} tool(s), stopping here",
                dim("·"),
                resolved.len()
            ),
        );
        return Ok(exit::OK);
    }

    // Seal the cell. This is a real microVM with real stage-2 sealing.
    let sealed = match seal_cell(&spec, &resolved, o) {
        Ok(b) => b,
        Err(e) => {
            if let Some(r) = record.as_mut() {
                crate::cells::finish(root, r, "kvm", Some(e.to_string()));
            }
            return Err(e);
        }
    };

    // Apply the exec gate and the laundering ban to the declared run.
    if let Some(r) = &spec.run {
        let entry_hash = resolved
            .iter()
            .find(|(t, _, _)| t.alias == r.exec)
            .map(|(_, h, _)| h.clone());
        if let Some(hash) = entry_hash {
            let lane_if_data = Lane::Data;
            match pilot::exec(assayer.manifest(), &hash, input_of(r.input, lane_if_data)) {
                pilot::ExecOutcome::Run { lane, .. } => {
                    o.event(
                        "exec_permitted",
                        serde_json::json!({"exec": r.exec, "lane": lane.to_string()}),
                        format!(
                            "  {} {} permitted in the {} lane",
                            green("✔"),
                            r.exec,
                            bold(&lane.to_string())
                        ),
                    );
                }
                pilot::ExecOutcome::Denied(e) => {
                    o.event(
                        "exec_denied",
                        serde_json::to_value(&e).unwrap_or_default(),
                        format!("  {} {} refused: {}", red("✘"), r.exec, e.reason),
                    );
                }
            }
        }
    }

    if let Some(r) = record.as_mut() {
        crate::cells::finish(root, r, sealed, None);
    }
    o.event(
        "cell_dissolved",
        serde_json::json!({"id": record.as_ref().map(|r| r.id.clone()), "name": spec.name, "sealed_tools": resolved.len(), "backend": sealed}),
        format!("{} cell dissolved", green("●")),
    );

    if !o.is_json() {
        o.say("");
        o.say(dim(
            "in-cell execution of your command is not wired yet (build plan M5:\n\
             stripped mote kernel + pilot). What ran here is real: a hardware-isolated\n\
             cell, your tools sealed into it as read-only memory, and every trust\n\
             decision applied. `nous verify` proves the isolation on this machine.",
        ));
    }
    Ok(exit::OK)
}

/// Seal a real cell and map the resolved tools into it. Returns the backend name.
#[cfg(target_os = "linux")]
fn seal_cell(
    spec: &Spec,
    resolved: &[(nous_spec::Tool, Hash, Vec<u8>)],
    o: &Out,
) -> Result<&'static str> {
    use warden::vmm::kvm::KvmVmm;
    use warden::Cell;

    let vmm = KvmVmm::new().context("opening /dev/kvm")?;
    let mut cell = Cell::seal(spec.name.clone(), vmm, "mote:nous-cli")?;
    o.event(
        "cell_sealed",
        serde_json::json!({"backend": "kvm", "phase": format!("{:?}", cell.phase())}),
        format!("  {} microVM sealed, phase={:?}", dim("·"), cell.phase()),
    );

    for (t, hash, bytes) in resolved {
        cell.map_tool(hash, bytes)?;
        o.event(
            "tool_sealed",
            serde_json::json!({"alias": t.alias, "hash": hash.to_string()}),
            format!("  {} {} sealed read-only into the cell", dim("·"), t.alias),
        );
    }

    // First tainted exec closes materialisation for this lineage, permanently.
    cell.on_first_tainted_exec();
    o.event(
        "ratchet",
        serde_json::json!({"phase": format!("{:?}", cell.phase())}),
        format!(
            "  {} authority ratcheted to {:?} — no further tools can be lent",
            dim("·"),
            cell.phase()
        ),
    );
    cell.dissolve()?;
    Ok("kvm")
}

#[cfg(not(target_os = "linux"))]
fn seal_cell(
    _spec: &Spec,
    _resolved: &[(nous_spec::Tool, Hash, Vec<u8>)],
    _o: &Out,
) -> Result<&'static str> {
    anyhow::bail!("hardware isolation needs Linux with /dev/kvm")
}

/// `nous ps` — cells, the way `docker ps` shows containers.
///
/// This registry exists because a KVM VM has no identity outside the process
/// that made it: it is a file descriptor, there is no `/proc/kvm` to walk, and
/// `virsh list` only ever shows domains libvirt itself created. If a cell is to
/// be visible at all, `nous` has to write it down.
pub fn ps(root: &Path, all: bool, o: &Out) -> Result<u8> {
    let mut records = crate::cells::list(root);
    if !all {
        records.retain(|r| r.live().is_live());
    }

    if o.is_json() {
        for r in &records {
            o.event(
                "cell",
                serde_json::json!({
                    "id": r.id, "name": r.name, "status": r.live().label(),
                    "tools": r.tools, "spec": r.spec, "backend": r.backend,
                    "started_ms": r.started_ms, "finished_ms": r.finished_ms,
                    "duration_ms": r.duration_ms(), "pid": r.pid, "error": r.error,
                }),
                "",
            );
        }
        return Ok(exit::OK);
    }

    if records.is_empty() {
        o.note(dim(if all {
            "no cells yet — `nous run <spec>` seals one"
        } else {
            // Cells are short-lived, so an empty `ps` is the normal case and
            // saying nothing here would look like a broken command.
            "no live cells — `nous ps -a` shows recent runs"
        }));
        return Ok(exit::OK);
    }

    println!(
        "{}",
        bold(&format!(
            "{:<14} {:<18} {:<12} {:>5}  {}",
            "CELL ID", "NAME", "STATUS", "TOOLS", "CREATED"
        ))
    );
    for r in &records {
        let live = r.live();
        let status = match (live, r.duration_human()) {
            (crate::cells::Live::Running, _) => green("running"),
            (crate::cells::Live::Dissolved, Some(d)) => format!("dissolved {}", dim(&d)),
            (crate::cells::Live::Refused, Some(d)) => format!("refused {}", dim(&d)),
            (crate::cells::Live::Failed, _) => red("failed"),
            (crate::cells::Live::Died, _) => red("died"),
            (s, None) => s.label().to_string(),
        };
        // Pad on the visible text, not the escape codes, or the columns wander.
        let pad = 12usize.saturating_sub(visible_len(&status));
        println!(
            "{:<14} {:<18} {}{:pad$} {:>5}  {}",
            r.id,
            r.name,
            status,
            "",
            r.tools.len(),
            crate::cells::ago(r.started_ms),
            pad = pad,
        );
        if let Some(e) = &r.error {
            println!("  {}", dim(&format!("↳ {e}")));
        }
    }
    Ok(exit::OK)
}

/// Length of a string as a terminal renders it, ignoring ANSI escapes.
fn visible_len(s: &str) -> usize {
    let mut n = 0;
    let mut in_esc = false;
    for c in s.chars() {
        if in_esc {
            if c == 'm' {
                in_esc = false;
            }
        } else if c == '\x1b' {
            in_esc = true;
        } else {
            n += 1;
        }
    }
    n
}

/// `nous tools` — what this host has attested.
pub fn tools(root: &Path, o: &Out) -> Result<u8> {
    let assayer =
        Assayer::open(root).with_context(|| format!("opening store {}", root.display()))?;
    let m = assayer.manifest();
    if m.is_empty() {
        o.note(dim(
            "no tools attested yet — `nous run` admits them as it resolves",
        ));
        return Ok(exit::OK);
    }
    o.event(
        "store",
        serde_json::json!({"root": root, "entries": m.len(), "signed": m.verify_standin()}),
        format!(
            "{} {} tool(s) in {}  {}",
            bold("store"),
            m.len(),
            root.display(),
            dim(if m.verify_standin() {
                "manifest signed"
            } else {
                "manifest UNSIGNED"
            })
        ),
    );
    Ok(exit::OK)
}

/// `nous verify` — prove the isolation on this machine, right now.
#[cfg(target_os = "linux")]
pub fn verify(o: &Out) -> Result<u8> {
    use nous_manifest::Hash;
    use warden::vmm::kvm::{guest, GuestEvent, KvmVmm, RunEnd};
    use warden::vmm::Vmm;

    let h = Host::probe();
    if !h.can_seal() {
        eprintln!(
            "{}: no hardware isolation here. Run `nous doctor`.",
            red("error")
        );
        return Ok(exit::HOST_INCAPABLE);
    }

    o.say(bold("proving isolation on this machine"));
    let mut failures = 0;

    // A guest that owns its own address translation still cannot write lent
    // tool code. This is the claim the whole design rests on.
    let mut v = KvmVmm::new()?;
    v.fork_from_snapshot("mote:verify")?;
    let tool = guest::tool_stub(warden::vmm::kvm::SCRATCH, 0x99);
    let hash = Hash::of(&tool);
    v.map_pages_ro_exec(&hash, &tool)?;
    let gpa = v.tool_gpa(&hash).expect("just mapped");

    let mark = 0x2100u32;
    v.map_scratch_rw(&guest::hostile::scratch_image(gpa as u32, mark, 0x41))?;
    for (off, bytes) in guest::hostile::gdt_blobs() {
        v.write_ram(off, &bytes)?;
    }
    v.write_ram(
        warden::vmm::kvm::ENTRY as usize,
        &guest::hostile::entry_stub(),
    )?;
    let report = v.run_guest(warden::vmm::kvm::ENTRY)?;

    let ran = report.end == RunEnd::Halted && v.read_ram(mark as usize, 1)? == [0x77];
    let blocked = report
        .events
        .contains(&GuestEvent::SealedWriteBlocked { gpa });
    let intact = v.tool_bytes(&hash, 0, tool.len()).as_deref() == Some(&tool[..]);
    let pass = ran && blocked && intact;
    if !pass {
        failures += 1;
    }
    o.event(
        "proof",
        serde_json::json!({
            "claim": "ring0_guest_with_own_page_tables_cannot_write_lent_code",
            "pass": pass, "guest_completed": ran, "write_refused": blocked, "bytes_intact": intact,
        }),
        format!(
            "  {} a ring-0 guest with its own page tables cannot write lent tool code",
            if pass { green("✔") } else { red("✘") }
        ),
    );

    // Revocation reaches a running cell.
    //
    // A fresh cell, not the one above: the hostile guest left that vCPU in
    // protected mode with its own paging on, and `run_guest` only resets the
    // instruction pointer. Reusing it runs real-mode probe code on a CPU that
    // is no longer in real mode, which fails in a way that looks like
    // revocation not working.
    let mut v2 = KvmVmm::new()?;
    v2.fork_from_snapshot("mote:verify-revoke")?;
    v2.map_pages_ro_exec(&hash, &tool)?;
    let gpa2 = v2.tool_gpa(&hash).expect("just mapped");
    let probe = guest::prog_copy_byte(gpa2 as u16, warden::vmm::kvm::SCRATCH);
    v2.write_ram(warden::vmm::kvm::ENTRY as usize, &probe)?;
    v2.run_guest(warden::vmm::kvm::ENTRY)?;
    let before = v2.read_ram(warden::vmm::kvm::SCRATCH as usize, 1)?[0];
    v2.unmap(&hash)?;
    v2.run_guest(warden::vmm::kvm::ENTRY)?;
    let after = v2.read_ram(warden::vmm::kvm::SCRATCH as usize, 1)?[0];
    let revoked = before == tool[0] && after == 0;
    if !revoked {
        failures += 1;
    }
    o.event(
        "proof",
        serde_json::json!({"claim": "revocation_reaches_a_running_cell", "pass": revoked}),
        format!(
            "  {} revoking a tool stops it in an already-running cell",
            if revoked { green("✔") } else { red("✘") }
        ),
    );

    o.say("");
    if failures == 0 {
        o.say(format!("{} isolation holds on this machine.", green("✔")));
        Ok(exit::OK)
    } else {
        o.say(format!("{} {failures} proof(s) failed.", red("✘")));
        Ok(exit::ERROR)
    }
}

#[cfg(not(target_os = "linux"))]
pub fn verify(o: &Out) -> Result<u8> {
    o.note("hardware isolation needs Linux with /dev/kvm");
    Ok(exit::HOST_INCAPABLE)
}

/// `nous demo` — the five-beat loop, no hardware required.
pub fn demo(o: &Out) -> Result<u8> {
    let tmp = std::env::temp_dir().join(format!("nous-demo-{}", std::process::id()));
    let mut assayer = Assayer::open(&tmp)?;
    let py = assayer.admit_verified("/usr/bin/python", b"cpython-bytes", true)?;

    let beat = |n: u8, title: &str| {
        o.event(
            "beat",
            serde_json::json!({"n": n, "title": title}),
            format!("\n{} {}", green(&format!("● beat {n}")), bold(title)),
        )
    };

    beat(1, "seal from intent — a cell, not a container");
    o.event(
        "sealed",
        serde_json::json!({"cell": "cell-001"}),
        "   cell-001 sealed",
    );

    beat(
        2,
        "loan a warm tool — install is a page map, not a download",
    );
    let r = assayer.resolve("/usr/bin/python", b"cpython-bytes", true)?;
    o.event(
        "resolved",
        serde_json::json!({"alias": "/usr/bin/python", "tier": r.tier.to_string(), "warm": r.warm}),
        format!("   python → tier={} warm={}", r.tier, r.warm),
    );

    beat(
        3,
        "cold tool, still fast — verified in seconds, forged behind it",
    );
    let r = assayer.resolve("/usr/lib/leftpad", b"leftpad-bytes", false)?;
    o.event(
        "resolved",
        serde_json::json!({"alias": "/usr/lib/leftpad", "tier": r.tier.to_string(), "warm": r.warm, "upgrade_queued": r.upgrade_queued}),
        format!("   leftpad → tier={} upgrade_queued={}", r.tier, r.upgrade_queued),
    );
    assayer.run_one_rebuild();

    beat(4, "demote on exec — the laundering ban");
    for (what, input) in [
        ("python evil.py", Input::File(Lane::Data)),
        (
            r#"python -c "<agent-authored>""#,
            Input::ArgString(Lane::Data),
        ),
    ] {
        if let pilot::ExecOutcome::Run { lane, .. } = pilot::exec(assayer.manifest(), &py, input) {
            o.event(
                "lane",
                serde_json::json!({"exec": what, "lane": lane.to_string()}),
                format!("   {what} → runs in the {lane} lane"),
            );
        }
    }

    beat(5, "kill fleet-wide — revoke, and it stops everywhere");
    assayer.revoke(&py);
    if let pilot::ExecOutcome::Denied(e) = pilot::exec(assayer.manifest(), &py, Input::None) {
        o.event(
            "denied",
            serde_json::to_value(&e).unwrap_or_default(),
            format!("   {}\n   {}", e.reason, dim(&e.instead)),
        );
    }

    let _ = std::fs::remove_dir_all(&tmp);
    o.say("");
    let h = Host::probe();
    if h.can_seal() {
        o.say(dim(
            "that was the control flow. `nous verify` proves it in hardware.",
        ));
    } else {
        o.say(dim(
            "that was the control flow, in software. Hardware isolation needs /dev/kvm.",
        ));
    }
    Ok(exit::OK)
}
