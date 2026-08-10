//! The verbs that do something.

use crate::exit;
use crate::host::Host;
use crate::out::{bold, dim, green, red, Out};
use anyhow::{Context, Result};
use assay::Assayer;
use celln_manifest::{Hash, Input, Lane, Tier};
use celln_spec::Spec;
use std::path::Path;

/// Where a tool's bytes come from, for display.
fn source_of(t: &celln_spec::Tool) -> String {
    if let Some(b) = &t.builtin {
        return format!("host capability: {b}");
    }
    match (&t.path, &t.image) {
        (Some(p), _) => p.display().to_string(),
        (_, Some(image)) => match &t.exec {
            Some(exec) => format!("{image} → {exec}"),
            None => image.clone(),
        },
        _ => "(no source)".into(),
    }
}

/// The filesystem image backing an image tool.
fn image_path(t: &celln_spec::Tool, root: &Path) -> Result<std::path::PathBuf> {
    let named = t
        .image
        .as_deref()
        .with_context(|| format!("tool {} has no path or image", t.alias))?;
    let resolved = crate::image::resolve_ref(named, root)?;
    let image = resolved.as_str();
    let digest = image
        .trim_start_matches("docker://")
        .split_once('@')
        .map(|(_, d)| d)
        .with_context(|| format!("tool {} image is not digest-pinned", t.alias))?;
    let path = crate::image::images_dir(root).join(format!("{}.ext2", digest.replace(':', "_")));
    if !path.exists() {
        anyhow::bail!(
            "{} is not materialised — run `celln image pull {image}`",
            t.alias
        );
    }
    Ok(path)
}

/// The bytes a tool's alias is attested against.
///
/// For an image tool that is the executable *inside* the image, not the image
/// itself: pilot re-hashes whatever it finds at that path in the cell, so the
/// manifest has to carry the same thing.
fn tool_bytes(t: &celln_spec::Tool, root: &Path) -> Result<Vec<u8>> {
    if t.builtin.as_deref() == Some("fetch") {
        // Same search order as mkinitramfs.sh: an installed runtime first,
        // then a build tree, so this works from a checkout too.
        let runtime = crate::agent::runtime_root()?;
        for c in [
            runtime.join("pilot/pilot-fetch"),
            runtime.join("target/x86_64-unknown-linux-musl/release/pilot-fetch"),
        ] {
            if c.exists() {
                return std::fs::read(&c).with_context(|| format!("reading {}", c.display()));
            }
        }
        anyhow::bail!("pilot-fetch is not built; run `celln setup`");
    }
    if let Some(p) = &t.path {
        return std::fs::read(p)
            .with_context(|| format!("reading tool {} from {}", t.alias, p.display()));
    }
    let exec = t
        .exec
        .as_deref()
        .with_context(|| format!("tool {} has an image but no exec", t.alias))?;
    crate::image::extract(&image_path(t, root)?, exec)
        .with_context(|| format!("reading {exec} for tool {}", t.alias))
}

/// Map the spec's tier vocabulary onto the manifest's.
fn tier_of(t: celln_spec::Tier) -> Tier {
    match t {
        celln_spec::Tier::Forged => Tier::Forged,
        celln_spec::Tier::Verified => Tier::Verified,
        celln_spec::Tier::Unsealed => Tier::Unsealed,
    }
}

fn input_of(i: celln_spec::Input, lane: Lane) -> Input {
    match i {
        celln_spec::Input::None => Input::None,
        celln_spec::Input::Tool => Input::File(Lane::Tool),
        celln_spec::Input::Data => Input::File(lane),
    }
}

/// Load a spec, reporting problems the way a compiler would.
fn load(path: &Path, o: &Out) -> Result<Spec, u8> {
    match Spec::load(path) {
        Ok(s) => Ok(s),
        Err(celln_spec::SpecError::Invalid { path, problems }) => {
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

/// `celln spec check` — validate, then say what would happen.
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
            serde_json::json!({
                "alias": t.alias, "path": t.path, "image": t.image,
                "exec": t.exec, "interpreter": t.interpreter,
            }),
            format!("  {:<24} {}  {}", t.alias, dim(kind), dim(&source_of(t))),
        );
    }

    let plan = spec.run_list();
    if !plan.is_empty() {
        o.say("");
        o.say(bold("run"));
    }
    for run in plan {
        let interp = spec
            .tools
            .iter()
            .find(|t| t.alias == run.exec)
            .map(|t| t.interpreter)
            .unwrap_or(false);
        let demoted = interp && run.input == celln_spec::Input::Data;
        let lane = if demoted { "agent" } else { "tool" };
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
            "\nthis host cannot seal cells; `celln run` would refuse. `celln doctor` says why.",
        ));
    }
    Ok(exit::OK)
}

/// `celln run` — seal a cell from a spec and drive its lifecycle.
pub fn run(path: &Path, root: &Path, dry_run: bool, task: Option<&str>, o: &Out) -> Result<u8> {
    let spec = match load(path, o) {
        Ok(s) => s,
        Err(code) => return Ok(code),
    };
    run_spec(spec, root, Path::new(path), dry_run, task, o)
}

/// The body of a run, over a spec that may have been built rather than parsed.
///
/// `celln agent --tool` constructs one in memory and comes through here, so an
/// ad-hoc run and a declared one take exactly the same path and reach exactly
/// the same trust decisions.
pub fn run_spec(
    mut spec: Spec,
    root: &Path,
    origin: &Path,
    dry_run: bool,
    task: Option<&str>,
    o: &Out,
) -> Result<u8> {
    // A model fills in the code; the spec keeps the policy.
    if let Some(agent) = spec.agent.clone() {
        let task = task
            .map(str::to_owned)
            .or_else(|| agent.task.clone())
            .context("this cell asks a model for its program but no task was given; pass --task")?;
        let source = crate::agent::write_program(&spec, &agent.exec, &task, root, o)?;
        spec.run = Some(celln_spec::Runs::One(Box::new(celln_spec::Run {
            exec: agent.exec.clone(),
            args: vec![source.flag, source.code],
            input: celln_spec::Input::Data,
        })));
    }
    for w in spec.warnings() {
        o.warn(format!("{}: {}", w.field, w.message));
    }

    let h = Host::probe();
    if !h.can_seal() {
        eprintln!(
            "{}: this host cannot seal cells. Run `celln doctor`.",
            red("error")
        );
        return Ok(exit::HOST_INCAPABLE);
    }

    let mut assayer =
        Assayer::open(root).with_context(|| format!("opening store {}", root.display()))?;

    // Write the cell down before it exists, so `celln ps` can see it while it
    // runs and still has a record if this process is killed mid-cell.
    let mut record = crate::cells::begin(
        root,
        &spec.name,
        origin,
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
        let bytes = tool_bytes(t, root)?;
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

    // Apply the exec gate and the laundering ban to each declared run, on the
    // host, before a cell exists. Pilot repeats the check in-cell against the
    // bytes it actually finds; agreeing twice is the point.
    for r in spec.run_list() {
        let Some(hash) = resolved
            .iter()
            .find(|(t, _, _)| t.alias == r.exec)
            .map(|(_, h, _)| h.clone())
        else {
            continue;
        };
        match pilot::exec(assayer.manifest(), &hash, input_of(r.input, Lane::Data)) {
            pilot::ExecOutcome::Run { lane, .. } => o.event(
                "exec_permitted",
                serde_json::json!({"exec": r.exec, "lane": lane.to_string()}),
                format!(
                    "  {} {} permitted in the {} lane",
                    green("✔"),
                    r.exec,
                    bold(&lane.to_string())
                ),
            ),
            pilot::ExecOutcome::Denied(e) => o.event(
                "exec_denied",
                serde_json::to_value(&e).unwrap_or_default(),
                format!("  {} {} refused: {}", red("✘"), r.exec, e.reason),
            ),
        }
    }

    let outcome = execute(&spec, &resolved, root, o);
    let code = match outcome {
        Ok(code) => {
            if let Some(r) = record.as_mut() {
                crate::cells::finish(root, r, "kvm", None);
            }
            code
        }
        Err(e) => {
            if let Some(r) = record.as_mut() {
                crate::cells::finish(root, r, "kvm", Some(e.to_string()));
            }
            return Err(e);
        }
    };

    o.event(
        "cell_dissolved",
        serde_json::json!({
            "id": record.as_ref().map(|r| r.id.clone()), "name": spec.name,
            "sealed_tools": resolved.len(), "backend": "kvm",
        }),
        format!("{} cell dissolved", green("●")),
    );
    Ok(code)
}

/// Seal a real cell, run every declared invocation in it, and print what they
/// produced.
///
/// A spec's tools are sealed as one filesystem image, so exactly one image tool
/// is supported per cell; single-binary tools are packed alongside it.
#[cfg(target_os = "linux")]
fn execute(
    spec: &Spec,
    resolved: &[(celln_spec::Tool, Hash, Vec<u8>)],
    root: &Path,
    o: &Out,
) -> Result<u8> {
    use warden::vmm::boot::{BootConfig, LinuxCell};

    if !Path::new("/dev/kvm").exists() {
        anyhow::bail!("no /dev/kvm on this host");
    }
    let runtime = crate::agent::runtime_root()?;
    let work = crate::agent::tempdir()?;
    let work = work.path();

    // Every distinct image becomes its own sealed namespace. Tools sharing an
    // image share the mount, so 1:1, many:1 and many:many all fall out of the
    // same mapping.
    let mut images: Vec<(String, Vec<u8>)> = Vec::new();
    for (t, _, _) in resolved.iter().filter(|(t, _, _)| t.image.is_some()) {
        let path = image_path(t, root)?;
        let key = path.display().to_string();
        if !images.iter().any(|(k, _)| *k == key) {
            images.push((key, std::fs::read(&path)?));
        }
    }
    let mount_of = |t: &celln_spec::Tool| -> Option<String> {
        let path = image_path(t, root).ok()?;
        let key = path.display().to_string();
        let idx = images.iter().position(|(k, _)| *k == key)?;
        Some(if idx == 0 {
            "/tools".to_string()
        } else {
            format!("/tools{idx}")
        })
    };
    let files: Vec<&(celln_spec::Tool, Hash, Vec<u8>)> = resolved
        .iter()
        .filter(|(t, _, _)| t.path.is_some())
        .collect();

    // A run request per declared invocation, each naming the bytes pilot must
    // re-hash before it will exec them.
    let mut runs = Vec::new();
    for r in spec.run_list() {
        let Some((tool, _, _)) = resolved.iter().find(|(t, _, _)| t.alias == r.exec) else {
            continue;
        };
        let (path, root_dir) = match (&tool.image, &tool.exec) {
            _ if tool.builtin.as_deref() == Some("fetch") => ("/pilot-fetch".to_string(), None),
            (Some(_), Some(exec)) => (exec.clone(), mount_of(tool)),
            _ => (
                format!(
                    "/tools/{}",
                    tool.path
                        .as_ref()
                        .and_then(|p| p.file_name())
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default()
                ),
                None,
            ),
        };
        runs.push(serde_json::json!({
            "path": path,
            "alias": tool.alias,
            "args": r.args,
            "agent_authored_input": r.input == celln_spec::Input::Data,
            "root": root_dir,
        }));
    }
    let run_json = work.join("run.json");
    std::fs::write(
        &run_json,
        serde_json::to_vec_pretty(&serde_json::json!({ "runs": runs }))?,
    )?;

    // The manifest pilot checks against is this host's store, which already
    // holds every tool resolved above.
    let manifest = root.join("manifest.json");
    let toolfs = work.join("toolfs.img");
    match images.first() {
        Some((_, bytes)) => std::fs::write(&toolfs, bytes)?,
        None => {
            let mut args = vec![toolfs.display().to_string(), "32".into()];
            for (t, _, bytes) in &files {
                let staged = work.join(
                    t.path
                        .as_ref()
                        .and_then(|p| p.file_name())
                        .context("tool path has no file name")?,
                );
                std::fs::write(&staged, bytes)?;
                args.push(staged.display().to_string());
            }
            crate::agent::sh(&runtime, "scripts/mktoolfs.sh", &args)?;
        }
    }

    let initrd = work.join("initramfs.cpio");
    crate::agent::sh_env(
        &runtime,
        "scripts/mkinitramfs.sh",
        &[initrd.display().to_string()],
        &[
            ("CELLN_MANIFEST", manifest.display().to_string()),
            ("CELLN_RUN_JSON", run_json.display().to_string()),
            (
                "CELLN_PILOT_DIR",
                runtime.join("pilot").display().to_string(),
            ),
        ],
    )?;

    let payload = std::fs::read(&toolfs)?;
    let mut lens: Vec<usize> = vec![payload.len()];
    lens.extend(images.iter().skip(1).map(|(_, b)| b.len()));

    let kernel = BootConfig::host_kernel()
        .context("no readable /boot/vmlinuz-* with matching /lib/modules")?;
    let mut cfg = BootConfig::new(&kernel)
        .with_pmems(&lens)
        .with_initrd(&initrd);
    cfg.mem_size = spec.memory_bytes() as usize;

    let mut cell = LinuxCell::boot(cfg).context("booting the cell")?;
    let h = Hash::of(&payload);
    cell.seal_tool(&h, &payload).context("sealing tools")?;
    for (_, bytes) in images.iter().skip(1) {
        cell.seal_tool(&Hash::of(bytes), bytes)
            .context("sealing an additional image")?;
    }
    o.event(
        "cell_sealed",
        serde_json::json!({"backend": "kvm", "hash": h.0, "bytes": payload.len()}),
        format!(
            "  {} cell sealed, {} tool(s) lent read-only",
            dim("·"),
            resolved.len()
        ),
    );

    if !spec.cell.allow_hosts.is_empty() {
        cell.enable_http_fetch(warden::egress::HttpPolicy::new(
            spec.cell.allow_hosts.clone(),
        ));
        o.event(
            "egress",
            serde_json::json!({ "allow_hosts": spec.cell.allow_hosts }),
            format!(
                "  {} egress brokered by the host: {}",
                dim("·"),
                spec.cell.allow_hosts.join(", ")
            ),
        );
    }
    let report = cell.run().context("running the cell")?;
    if !report.console.contains("CELLN:pilot=alive") {
        let tail: Vec<&str> = report.console.lines().rev().take(8).collect();
        anyhow::bail!(
            "the cell booted but pilot never started, so nothing ran. \
             Guest console tail: {}",
            tail.into_iter().rev().collect::<Vec<_>>().join(" | ")
        );
    }
    for m in report
        .console
        .lines()
        .filter_map(|l| l.strip_prefix("CELLN:tools_mounted="))
    {
        o.event(
            "image_mounted",
            serde_json::json!({ "mount": m }),
            format!("  {} image mounted at {}", dim("·"), m),
        );
    }
    let mut code = 0u8;
    for line in report.console.lines() {
        let Some(rest) = line.strip_prefix("CELLN:pilot_run_") else {
            continue;
        };
        let Some((key, val)) = rest.split_once('=') else {
            continue;
        };
        if let Some(alias) = key.strip_suffix("_exit") {
            let exit = val.parse::<i32>().unwrap_or(1).clamp(0, 255) as u8;
            if exit != 0 {
                code = exit;
            }
            o.event(
                "run_exit",
                serde_json::json!({"alias": alias, "exit": exit}),
                format!("  {} {} exit={}", dim("·"), alias, exit),
            );
        } else {
            o.event(
                "pilot_verdict",
                serde_json::json!({"alias": key, "verdict": val}),
                format!(
                    "  {} pilot: {} {}",
                    if val.starts_with("permitted") {
                        green("✔")
                    } else {
                        red("✘")
                    },
                    key,
                    val
                ),
            );
            if val == "denied" {
                code = exit::REFUSED;
                for line in report
                    .console
                    .lines()
                    .filter_map(|l| l.strip_prefix("CELLN:explain "))
                {
                    o.event(
                        "explain",
                        serde_json::json!({ "line": line }),
                        format!("    {}", dim(line.trim())),
                    );
                }
            }
        }
    }
    // One block per invocation, so a cell running several tools prints all of
    // them rather than only the first.
    let mut rest = report.console.as_str();
    while let Some(start) = rest.find("CELLN:out-begin") {
        let Some(nl) = rest[start..].find('\n') else {
            break;
        };
        let after = start + nl + 1;
        let Some(end) = rest[after..].find("CELLN:out-end") else {
            break;
        };
        let text = rest[after..after + end].trim_end_matches(['\r', '\n']);
        if !text.trim().is_empty() {
            let text = text.replace("\r\n", "\n");
            o.event("output", serde_json::json!({"stdout": text}), String::new());
            if !o.is_json() {
                println!("{text}");
            }
        }
        rest = &rest[after + end..];
    }
    Ok(code)
}

#[cfg(not(target_os = "linux"))]
fn execute(
    _spec: &Spec,
    _resolved: &[(celln_spec::Tool, Hash, Vec<u8>)],
    _root: &Path,
    _o: &Out,
) -> Result<u8> {
    anyhow::bail!("hardware isolation needs Linux with /dev/kvm")
}

/// `celln ps` — cells, the way `docker ps` shows containers.
///
/// This registry exists because a KVM VM has no identity outside the process
/// that made it: it is a file descriptor, there is no `/proc/kvm` to walk, and
/// `virsh list` only ever shows domains libvirt itself created. If a cell is to
/// be visible at all, `celln` has to write it down.
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
                    "id": r.id, "description": r.description, "status": r.live().label(),
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
            "no cells yet — `celln run <spec>` seals one"
        } else {
            // Cells are short-lived, so an empty `ps` is the normal case and
            // saying nothing here would look like a broken command.
            "no live cells — `celln ps -a` shows recent runs"
        }));
        return Ok(exit::OK);
    }

    println!(
        "{}",
        bold(&format!(
            "{:<14} {:<28} {:<12} {:>5}  {}",
            "CELL ID", "DESCRIPTION", "STATUS", "TOOLS", "CREATED"
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
        let desc = ellipsis(&r.description, 28);
        println!(
            "{:<14} {:<28} {}{:pad$} {:>5}  {}",
            r.id,
            desc,
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

fn ellipsis(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max - 1; // leave room for '…'
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

/// `celln tools` — what this host has attested.
pub fn tools(root: &Path, o: &Out) -> Result<u8> {
    let assayer =
        Assayer::open(root).with_context(|| format!("opening store {}", root.display()))?;
    let m = assayer.manifest();
    if m.is_empty() {
        o.note(dim(
            "no tools attested yet — `celln run` admits them as it resolves, \
             or `celln prewarm` admits the usual suspects up front",
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

    let mut entries: Vec<_> = m.entries().collect();
    entries.sort_by(|a, b| a.alias.cmp(&b.alias));
    for e in entries {
        let revoked = m.is_revoked(&e.hash);
        o.event(
            "tool_entry",
            serde_json::json!({
                "alias": e.alias,
                "hash": e.hash.to_string(),
                "tier": e.tier.to_string(),
                "interpreter": e.interpreter,
                "author": e.author.to_string(),
                "revoked": revoked,
            }),
            format!(
                "  {} {:<32} tier={:<8} {}{}",
                if revoked { red("✘") } else { green("✔") },
                e.alias,
                e.tier.to_string(),
                dim(&format!(
                    "author={} interpreter={}",
                    e.author, e.interpreter
                )),
                if revoked {
                    format!("  {}", red("REVOKED"))
                } else {
                    String::new()
                }
            ),
        );
    }
    Ok(exit::OK)
}

/// `celln verify` — prove the isolation on this machine, right now.
#[cfg(target_os = "linux")]
pub fn verify(o: &Out) -> Result<u8> {
    use celln_manifest::Hash;
    use warden::vmm::kvm::{guest, GuestEvent, KvmVmm, RunEnd};
    use warden::vmm::Vmm;

    let h = Host::probe();
    if !h.can_seal() {
        eprintln!(
            "{}: no hardware isolation here. Run `celln doctor`.",
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

/// `celln demo` — the five-beat loop, no hardware required.
pub fn demo(o: &Out) -> Result<u8> {
    let tmp = std::env::temp_dir().join(format!("celln-demo-{}", std::process::id()));
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
            "that was the control flow. `celln verify` proves it in hardware.",
        ));
    } else {
        o.say(dim(
            "that was the control flow, in software. Hardware isolation needs /dev/kvm.",
        ));
    }
    Ok(exit::OK)
}
