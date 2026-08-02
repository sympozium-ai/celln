//! `nous agent` — ask Claude for a program, then run it sealed in a cell.
//!
//! This is the end-to-end shape of the thing: a model writes code, the host
//! attests the bytes it actually built, seals them into a hardware-isolated
//! cell as read-only memory, and pilot runs them by hash. What comes back is
//! the program's stdout and nothing else.
//!
//! Two things are worth being precise about, because they are the design.
//!
//! **The model runs on the host, not in the cell.** The cell has no network —
//! not "a firewalled network", none: no virtio, no vsock, no route to
//! anything. That is deliberate (see ADR-0006), and it means the API
//! credential never goes near the cell. The host holds it, calls out, and
//! passes in bytes. Getting the *model* into a cell is the same problem as
//! getting anything else out to the network, and gets the same answer: an
//! attested network stack reached through a broker, never an ambient NIC.
//!
//! **Attestation is provenance, not intent.** Forging says these bytes are
//! what we built from that source. It says nothing about whether the program
//! is correct or benign — the model wrote it, and nobody read it. The cell is
//! what makes running it acceptable anyway.

use crate::out::{bold, dim, green, Out};
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

/// What we ask for. Constrained hard on purpose: one file, no dependencies,
/// answer on stdout. A program with a build system is a supply chain, and the
/// point here is that the whole artifact is something we hashed.
const BRIEF: &str = "\
Write a single-file Rust program (Rust 2021, standard library only, no external \
crates, no Cargo) that does the following:

%TASK%

Requirements:
- exactly one source file, compiled by `rustc` alone
- write the result to stdout
- exit 0 on success

Reply with only the Rust source in a single ```rust fenced block. No prose.";

/// Where the guest will find the program, and what pilot calls it in reports.
const ALIAS: &str = "/agent/program";

/// Which model writes the code.
///
/// Backends are subprocess adapters, not linked SDKs: whatever CLI the user has
/// already authenticated is what gets used, and `nous` never reads, stores, or
/// forwards a key. That is not only convenience — under ADR-0006 the credential
/// belongs to the host and must never approach the cell, and shelling out to a
/// tool that already holds it is the least-privilege way to arrange that.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Backend {
    /// Claude, via the `claude` CLI.
    Anthropic,
    /// OpenAI, via the `codex` CLI.
    Openai,
    /// A local model, via `ollama`. No egress at all.
    Local,
}

impl Backend {
    /// The CLI this backend drives. Its presence is the availability check.
    fn program(self) -> &'static str {
        match self {
            Backend::Anthropic => "claude",
            Backend::Openai => "codex",
            Backend::Local => "ollama",
        }
    }

    /// Used when the user does not name one. `None` means "whatever that CLI
    /// is already configured to use" — the right default when the tool has its
    /// own config and account-specific model availability, which is exactly the
    /// case for `codex`. Overridable with `--model` in every case, because
    /// model names date fast.
    fn default_model(self) -> Option<&'static str> {
        match self {
            Backend::Anthropic => Some("claude-opus-5"),
            Backend::Openai => None,
            // `ollama run` takes the model as a positional, so this one is
            // required rather than optional. It has to be pulled first.
            Backend::Local => Some("qwen2.5-coder"),
        }
    }

    fn label(self) -> &'static str {
        match self {
            Backend::Anthropic => "anthropic",
            Backend::Openai => "openai",
            Backend::Local => "local",
        }
    }

    fn available(self) -> bool {
        which(self.program()).is_some()
    }

    /// Build the one-shot, non-interactive invocation. Each of these CLIs
    /// spells "answer once and exit" differently.
    fn command(self, prompt: &str, model: Option<&str>) -> Command {
        let mut c = Command::new(self.program());
        match self {
            Backend::Anthropic => {
                c.arg("-p").arg(prompt);
                if let Some(m) = model {
                    c.arg("--model").arg(m);
                }
            }
            Backend::Openai => {
                // Read-only sandbox and no git check: it is being asked to
                // write source to stdout, not to touch the working tree.
                c.arg("exec")
                    .arg(prompt)
                    .arg("--sandbox")
                    .arg("read-only")
                    .arg("--skip-git-repo-check");
                if let Some(m) = model {
                    c.arg("-m").arg(m);
                }
            }
            Backend::Local => {
                c.arg("run").arg(model.unwrap_or("qwen2.5-coder")).arg(prompt);
            }
        }
        c
    }
}

/// List the built-in backends and whether this host can use them.
/// Mirrors `nous tools`: the question is always "what is available here".
pub fn agents(o: &Out) -> Result<u8> {
    for b in [Backend::Anthropic, Backend::Openai, Backend::Local] {
        let ok = b.available();
        o.event(
            "agent_backend",
            serde_json::json!({
                "backend": b.label(),
                "program": b.program(),
                "default_model": b.default_model(),
                "available": ok,
            }),
            format!(
                "  {} {:<10} {:<22} {}",
                if ok { green("✔") } else { dim("·") },
                b.label(),
                b.default_model().unwrap_or("(cli default)"),
                if ok {
                    dim(b.program())
                } else {
                    dim(&format!("{} not installed", b.program()))
                }
            ),
        );
    }
    Ok(0)
}

fn which(program: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|d| d.join(program))
            .find(|p| p.is_file())
    })
}

pub fn agent(
    task: &str,
    backend: Backend,
    model: Option<&str>,
    trust_agent_code: bool,
    o: &Out,
) -> Result<u8> {
    let root = repo_root()?;
    let work = tempdir()?;

    // ── 1. the model writes the code, on the host ────────────────────────
    let model = model.or_else(|| backend.default_model());
    if !backend.available() {
        o.warn(format!(
            "{} needs `{}` on PATH — see `nous agents`",
            backend.label(),
            backend.program()
        ));
        return Ok(3);
    }
    o.event(
        "agent_brief",
        serde_json::json!({ "task": task, "backend": backend.label(), "model": model }),
        format!(
            "{} asking {} ({}) for a program",
            bold("●"),
            backend.label(),
            model.unwrap_or("cli default")
        ),
    );
    let source = ask_model(backend, model, &BRIEF.replace("%TASK%", task))?;
    let src_path = work.join("program.rs");
    std::fs::write(&src_path, &source)?;
    o.note(format!(
        "  {} {} lines of rust",
        dim("·"),
        source.lines().count()
    ));

    // ── 2. build it, and attest what we built ────────────────────────────
    //
    // Static musl: the cell carries no libc and no loader, so a dynamically
    // linked binary would have nothing to link against. It also means the
    // thing we hash is the entire program.
    let bin = work.join("program");
    let out = Command::new("rustc")
        .args(["--edition", "2021", "-O", "-C", "strip=symbols"])
        .args(["--target", "x86_64-unknown-linux-musl"])
        .args(["-C", "target-feature=+crt-static"])
        .arg("-o")
        .arg(&bin)
        .arg(&src_path)
        .output()
        .context("running rustc")?;
    if !out.status.success() {
        // The model wrote code that does not compile. That is a normal
        // outcome, not an internal error — say so with the compiler's words.
        o.warn("the generated program does not compile");
        eprintln!("{}", String::from_utf8_lossy(&out.stderr));
        return Ok(1);
    }
    let bytes = std::fs::metadata(&bin)?.len();
    let hash = nous_manifest::Hash::of(&std::fs::read(&bin)?);
    o.event(
        "agent_forged",
        serde_json::json!({ "hash": hash.0, "bytes": bytes, "tier": "forged" }),
        format!(
            "  {} forged  {}  {} KiB",
            green("+"),
            dim(&hash.0),
            bytes / 1024
        ),
    );

    // ── 3. seal it into a tool filesystem, and stage the manifest ────────
    //
    // Both scripts, because both artifacts have to be built before the cell
    // exists: the image is lent read-only, so nothing can be added to it from
    // the inside, and the manifest has to name the hash before pilot boots.
    sh(&root, "scripts/mktoolfs.sh", &[
        "target/nous-toolfs.img".into(),
        "32".into(),
        bin.display().to_string(),
    ])?;
    let mut env = vec![
        ("NOUS_RUN_PROG", bin.display().to_string()),
        ("NOUS_RUN_ALIAS", ALIAS.into()),
    ];
    if trust_agent_code {
        // Explicit, and named for what it actually does. The default is the
        // correct one; this exists so the substrate stays demonstrable while
        // the collar is being built, not as a convenience.
        o.warn("--trust-agent-code: running agent-authored code in the tool lane");
    } else {
        env.push(("NOUS_RUN_AGENT_AUTHORED", "1".into()));
    }
    sh_env(&root, "scripts/mkinitramfs.sh", &[], &env)?;

    // ── 4. seal a cell and run it ────────────────────────────────────────
    run_in_cell(&root, o)
}

#[cfg(target_os = "linux")]
fn run_in_cell(root: &Path, o: &Out) -> Result<u8> {
    use warden::vmm::boot::{BootConfig, LinuxCell};

    if !Path::new("/dev/kvm").exists() {
        o.warn("no /dev/kvm — cannot seal a cell on this host");
        return Ok(3);
    }
    let kernel = BootConfig::host_kernel()
        .context("no readable /boot/vmlinuz-* with matching /lib/modules")?;

    let toolfs = root.join("target/nous-toolfs.img");
    let payload = std::fs::read(&toolfs)?;
    let mut cfg = BootConfig::new(&kernel).with_pmem(payload.len());
    if let Some(initrd) = BootConfig::built_initramfs() {
        cfg = cfg.with_initrd(initrd);
    }

    let mut cell = LinuxCell::boot(cfg)?;
    let h = nous_manifest::Hash::of(&payload);
    cell.seal_tool(&h, &payload)?;
    o.event(
        "cell_sealed",
        serde_json::json!({ "hash": h.0, "bytes": payload.len() }),
        format!("  {} cell sealed, tools lent read-only", dim("·")),
    );

    let r = cell.run()?;

    // pilot's own verdict, which is the part that matters: it re-hashed the
    // bytes it found and decided for itself whether to run them. The exit
    // status rides the same channel but is not a verdict — keep them apart so
    // a program that fails is distinguishable from one that was refused.
    let mut code = 0u8;
    let mut refused: Option<String> = None;
    for line in r.console.lines() {
        let Some(rest) = line.strip_prefix("NOUS:pilot_run_") else {
            continue;
        };
        let Some((key, val)) = rest.split_once('=') else {
            continue;
        };
        if key.ends_with("_exit") {
            code = val.parse::<i32>().unwrap_or(1).clamp(0, 255) as u8;
        } else {
            if val.starts_with("refused") || val == "denied" {
                refused = Some(val.to_string());
            }
            o.event(
                "pilot_verdict",
                serde_json::json!({ "alias": key, "verdict": val }),
                format!("  {} pilot: {} {}", green("✔"), key, val),
            );
        }
    }

    match slice_output(&r.console) {
        Some(text) => {
            o.event(
                "agent_output",
                serde_json::json!({ "stdout": text }),
                String::new(),
            );
            // The payload goes to stdout unadorned, so the cell pipes like any
            // other process.
            if !o.is_json() {
                println!("{text}");
            }
            Ok(code)
        }
        // A refusal is a result, not a failure to produce one. Saying "no
        // output" here would describe the symptom and hide the decision.
        None if refused.is_some() => {
            o.warn(format!(
                "pilot refused to run it: {}",
                refused.unwrap_or_default()
            ));
            o.note(format!(
                "  {} a model wrote this, so it is agent-authored at any tier and\n  {} belongs in the collared lane. The collar does not exist yet.\n  {} --trust-agent-code runs it anyway.",
                dim("·"),
                dim("·"),
                dim("·")
            ));
            Ok(4)
        }
        None => {
            o.warn("the program produced no output — see the cell's console");
            Ok(1)
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn run_in_cell(_root: &Path, o: &Out) -> Result<u8> {
    o.warn("sealing cells needs Linux with /dev/kvm");
    Ok(3)
}

/// Everything pilot printed between its markers is the program's own output.
fn slice_output(console: &str) -> Option<String> {
    let start = console.find("NOUS:out-begin")?;
    let after = console[start..].find('\n')? + start + 1;
    let end = console[after..].find("NOUS:out-end")? + after;
    let text = console[after..end].trim_end_matches(['\r', '\n']);
    (!text.trim().is_empty()).then(|| text.replace("\r\n", "\n"))
}

/// Shell out to whichever provider CLI was selected.
fn ask_model(backend: Backend, model: Option<&str>, prompt: &str) -> Result<String> {
    let program = backend.program();
    let out = backend
        .command(prompt, model)
        .output()
        .with_context(|| format!("running `{program}` — is it installed and logged in?"))?;
    if !out.status.success() {
        bail!(
            "{program} exited {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    extract_rust(&text)
        .with_context(|| format!("no ```rust block in the reply from {}", backend.label()))
}

/// Pull the source out of a fenced block, tolerating the model adding prose
/// around it despite being asked not to.
fn extract_rust(reply: &str) -> Option<String> {
    let start = reply.find("```rust").or_else(|| reply.find("```"))?;
    let body = &reply[start..];
    let after = body.find('\n')? + 1;
    let end = body[after..].find("```")? + after;
    Some(body[after..end].to_string())
}

fn sh(root: &Path, script: &str, args: &[String]) -> Result<()> {
    sh_env(root, script, args, &[])
}

fn sh_env(root: &Path, script: &str, args: &[String], env: &[(&str, String)]) -> Result<()> {
    let mut c = Command::new(root.join(script));
    c.current_dir(root).args(args);
    for (k, v) in env {
        c.env(k, v);
    }
    let out = c.output().with_context(|| format!("running {script}"))?;
    if !out.status.success() {
        bail!("{script}: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}

/// The build scripts live in the repo, so `nous agent` currently has to run
/// from a checkout. `NOUS_REPO` overrides for anything else.
fn repo_root() -> Result<PathBuf> {
    if let Some(p) = std::env::var_os("NOUS_REPO") {
        return Ok(PathBuf::from(p));
    }
    let cwd = std::env::current_dir()?;
    for dir in cwd.ancestors() {
        if dir.join("scripts/mkinitramfs.sh").exists() {
            return Ok(dir.to_path_buf());
        }
    }
    bail!("run `nous agent` from a nouscell checkout, or set NOUS_REPO")
}

fn tempdir() -> Result<PathBuf> {
    let base = std::env::temp_dir().join(format!("nous-agent-{}", std::process::id()));
    std::fs::create_dir_all(&base)?;
    Ok(base)
}
