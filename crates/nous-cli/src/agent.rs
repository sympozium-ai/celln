//! `cell agent` — ask Claude for a program, then run it sealed in a cell.
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
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// What we ask for. Constrained hard on purpose: one file, no dependencies,
/// answer on stdout. A program with a build system is a supply chain, and the
/// point here is that the whole artifact is something we hashed.
const BRIEF: &str = "\
Write a single-file program that does the following:

%TASK%

Available sealed guest runtimes:
%RUNTIMES%

Requirements:
- choose exactly one runtime from the list above
- write the result to stdout
- exit 0 on success

Reply with exactly these two parts and no prose:
runtime: <chosen runtime id>
```<chosen language>
<source>
```
";

const FETCH_ABI: &str =
    "This cell has no network stack. For an HTTPS fetch, invoke `/pilot-fetch URL` \
with `std::process::Command`; it writes the response body to stdout. The host \
permits only explicitly declared hosts, and fetched bytes are untrusted data. \
Do not use TCP sockets, DNS libraries, curl, or external crates.";

/// Where the guest will find the program, and what pilot calls it in reports.
const ALIAS: &str = "/agent/program";

/// Which model writes the code.
///
/// Backends are subprocess adapters, not linked SDKs: whatever CLI the user has
/// already authenticated is what gets used, and `cell` never reads, stores, or
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

/// Execution profiles available inside the current mote.
///
/// This is intentionally a closed list. A language is not supported merely
/// because the host has a compiler: its runtime must be a sealed guest tool.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Runtime {
    /// Rust 2021, standard library only, built as a static musl binary.
    Rust,
}

impl Runtime {
    fn id(self) -> &'static str {
        match self {
            Runtime::Rust => "rust",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Runtime::Rust => "Rust 2021 (static musl)",
        }
    }

    fn capability(self) -> &'static str {
        match self {
            Runtime::Rust => {
                "rust — Rust 2021, static musl, standard library only; compiled by rustc"
            }
        }
    }

    fn from_id(id: &str) -> Option<Self> {
        match id.trim() {
            "rust" => Some(Runtime::Rust),
            _ => None,
        }
    }

    fn source_extension(self) -> &'static str {
        match self {
            Runtime::Rust => "rs",
        }
    }
}

const AVAILABLE_RUNTIMES: &[Runtime] = &[Runtime::Rust];

#[derive(Debug)]
struct GeneratedProgram {
    runtime: Runtime,
    source: String,
}

impl Backend {
    fn saved_name(self) -> &'static str {
        match self {
            Backend::Anthropic => "anthropic",
            Backend::Openai => "openai",
            Backend::Local => "local",
        }
    }

    fn from_saved_name(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "anthropic" | "claude" => Some(Backend::Anthropic),
            "openai" | "codex" => Some(Backend::Openai),
            "local" | "ollama" => Some(Backend::Local),
            _ => None,
        }
    }

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

    /// Whether this backend withholds its result until asked to stop.
    ///
    /// `claude -p` can finish the API call in seconds, print nothing, and hang.
    /// Its stdout stays empty — measured at zero bytes after 40s — and a
    /// SIGTERM makes it immediately flush a complete result object explaining
    /// what went wrong. So a timeout here is not "still working"; it is an
    /// answer being withheld, and terminating politely is how to collect it.
    /// SIGKILL would destroy exactly the diagnosis we want.
    fn flushes_on_sigterm(self) -> bool {
        matches!(self, Backend::Anthropic)
    }

    /// Build the one-shot, non-interactive invocation. Each of these CLIs
    /// spells "answer once and exit" differently.
    fn command(self, prompt: &str, model: Option<&str>) -> Command {
        let mut c = Command::new(self.program());
        match self {
            Backend::Anthropic => {
                // Structured output, so a failure is a field we can read
                // rather than something inferred from silence. It also gives
                // us a completion marker — see `complete_when`.
                c.arg("-p").arg(prompt).arg("--output-format").arg("json");
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
                c.arg("run")
                    .arg(model.unwrap_or("qwen2.5-coder"))
                    .arg(prompt);
            }
        }
        c
    }
}

/// List the built-in backends and whether this host can use them.
/// Mirrors `cell tools`: the question is always "what is available here".
pub fn agents(set_default: Option<Backend>, o: &Out) -> Result<u8> {
    if let Some(backend) = set_default {
        let path = crate::config::set_default_agent(backend.saved_name())?;
        o.event(
            "agent_default",
            serde_json::json!({"backend": backend.saved_name(), "config": path}),
            format!("✔ default agent: {} ({})", backend.label(), path.display()),
        );
    }
    let saved = crate::config::default_agent()?;
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
                "  {} {:<10} {:<22} {}{}",
                if ok { green("✔") } else { dim("·") },
                b.label(),
                b.default_model().unwrap_or("(cli default)"),
                if ok {
                    dim(b.program())
                } else {
                    dim(&format!("{} not installed", b.program()))
                },
                if saved
                    .as_deref()
                    .is_some_and(|name| Backend::from_saved_name(name) == Some(b))
                {
                    "  default"
                } else {
                    ""
                },
            ),
        );
    }
    Ok(crate::exit::OK)
}

pub fn setup(preferred: Option<Backend>, o: &Out) -> Result<u8> {
    let backend = match preferred {
        Some(backend) if backend.available() => backend,
        Some(backend) => {
            o.warn(format!(
                "{} is not available — install and authenticate `{}` first",
                backend.label(),
                backend.program()
            ));
            return Ok(crate::exit::HOST_INCAPABLE);
        }
        None => match discover_backend() {
            Some(backend) => backend,
            None => {
                o.warn("no agent CLI found — install and authenticate codex, claude, or ollama, then rerun `cell setup`");
                return Ok(crate::exit::HOST_INCAPABLE);
            }
        },
    };
    let path = crate::config::set_default_agent(backend.saved_name())?;
    o.event(
        "agent_default",
        serde_json::json!({"backend": backend.saved_name(), "config": path}),
        format!("✔ default agent: {} ({})", backend.label(), path.display()),
    );
    Ok(crate::exit::OK)
}

fn which(program: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|d| d.join(program))
            .find(|p| p.is_file())
    })
}

pub struct AgentRequest<'a> {
    pub task: &'a str,
    /// Persistent cell registry and store root (`--root` / `NOUS_ROOT`).
    pub state_root: &'a Path,
    pub requested_backend: Option<Backend>,
    pub model: Option<&'a str>,
    pub trust_agent_code: bool,
    pub show_source: bool,
    pub timeout: u64,
    pub allow_hosts: &'a [String],
}

pub fn agent(request: AgentRequest<'_>, o: &Out) -> Result<u8> {
    let AgentRequest {
        task,
        state_root,
        requested_backend,
        model,
        trust_agent_code,
        show_source,
        timeout,
        allow_hosts,
    } = request;
    let backend = match select_backend(requested_backend, o)? {
        Some(backend) => backend,
        None => return Ok(crate::exit::HOST_INCAPABLE),
    };

    // ── 1. the model writes the code, on the host ────────────────────────
    let model = model.or_else(|| backend.default_model());
    if !backend.available() {
        o.warn(format!(
            "{} needs `{}` on PATH — see `cell agents`",
            backend.label(),
            backend.program()
        ));
        return Ok(crate::exit::HOST_INCAPABLE);
    }
    let runtime_root = runtime_root()?;
    let work = tempdir()?;
    // The cell has no ambient network (ADR-0006). Do not make an agent spend
    // time generating a program that cannot possibly perform its stated job.
    const NEEDS_EGRESS: &[&str] = &[
        "crawl", "http", "https", "url", "download", "fetch", "scrape", "api", "website", "web ",
        "internet", "network", "request",
    ];
    let lower = task.to_lowercase();
    let needs_egress = NEEDS_EGRESS.iter().any(|w| lower.contains(*w));
    if needs_egress && allow_hosts.is_empty() {
        o.warn(
            "this task appears to need web access, but no host was declared. The cell remains hermetic; \
             add --allow-host example.org to lend the bounded pilot-fetch capability",
        );
        return Ok(crate::exit::UNSUPPORTED);
    } else if needs_egress {
        o.note(format!(
            "  {} web access is brokered by pilot; allowed hosts: {}",
            dim("·"),
            allow_hosts.join(", ")
        ));
    }
    o.event(
        "agent_brief",
        serde_json::json!({ "task": task, "backend": backend.label(), "model": model }),
        format!(
            "{} asking {} ({}) to build: {}",
            bold("●"),
            backend.label(),
            model.unwrap_or("cli default"),
            task
        ),
    );
    o.note(format!(
        "  {} waiting for {} (up to {}s; --timeout changes it)",
        dim("·"),
        backend.program(),
        timeout
    ));
    let started = Instant::now();
    let runtimes = AVAILABLE_RUNTIMES
        .iter()
        .map(|runtime| format!("- {}", runtime.capability()))
        .collect::<Vec<_>>()
        .join("\n");
    let mut brief = BRIEF
        .replace("%RUNTIMES%", &runtimes)
        .replace("%TASK%", task);
    if !allow_hosts.is_empty() {
        brief.push_str(FETCH_ABI);
    }
    let program = ask_model(backend, model, &brief, timeout)?;
    let runtime = program.runtime;
    let source = program.source;
    o.note(format!(
        "  {} replied in {:.0}s",
        dim("·"),
        started.elapsed().as_secs_f32()
    ));
    let src_path = work.join(format!("program.{}", runtime.source_extension()));
    std::fs::write(&src_path, &source)?;
    o.note(format!(
        "  {} selected sealed runtime: {}; {} source lines  {}",
        dim("·"),
        runtime.label(),
        source.lines().count(),
        dim(&src_path.display().to_string())
    ));
    if show_source {
        println!("{source}");
    }

    // ── 2. build it, and attest what we built ────────────────────────────
    //
    // Static musl: the cell carries no libc and no loader, so a dynamically
    // linked binary would have nothing to link against. It also means the
    // thing we hash is the entire program.
    // The build plane builds it — twice, in different directories — and the
    // assayer grades on whether those agreed. Nothing here asserts a tier.
    let (code, proof) = match forge::build_and_verify(source.as_bytes(), &work.join("forge")) {
        Ok(v) => v,
        Err(forge::ForgeError::Build(stderr)) => {
            // A model writing code that does not compile is a normal outcome,
            // not an internal error — say so with the compiler's own words.
            o.warn("the generated program does not compile");
            eprintln!("{stderr}");
            return Ok(crate::exit::ERROR);
        }
        Err(e) => return Err(e.into()),
    };
    let bin = work.join("program");
    std::fs::write(&bin, &code)?;
    let bytes = code.len() as u64;

    let author = if trust_agent_code {
        nous_manifest::Author::Host
    } else {
        nous_manifest::Author::Agent
    };
    let store = work.join("store");
    std::fs::create_dir_all(&store)?;
    let mut assayer = assay::Assayer::open(&store).context("opening the tool store")?;
    let hash = assayer
        .admit_forged_authored(ALIAS, &code, false, author, &proof)
        .context("admitting the generated program")?;
    let entry = assayer
        .manifest()
        .get(&hash)
        .context("admitted entry missing from the manifest")?;
    o.event(
        "agent_forged",
        serde_json::json!({
            "hash": hash.0,
            "bytes": bytes,
            "tier": entry.tier.to_string(),
            "author": entry.author.to_string(),
            "reproduced": proof.reproduced,
            "recipe": entry.recipe.as_ref().map(|r| r.0.clone()),
            "toolchain": proof.toolchain,
        }),
        format!(
            "  {} {}  {}  {} KiB  tier={} author={}",
            green("+"),
            if proof.reproduced {
                "rebuilt, reproduced"
            } else {
                "rebuilt, DID NOT reproduce"
            },
            dim(&hash.0),
            bytes / 1024,
            entry.tier,
            entry.author
        ),
    );

    // What the cell is asked to run. Written here for the same reason: the
    // request and the manifest it is checked against come from one place.
    let run_json = work.join("run.json");
    std::fs::write(
        &run_json,
        serde_json::to_vec_pretty(&serde_json::json!({
            "path": "/tools/program",
            "alias": ALIAS,
            "args": [],
            "agent_authored_input": false,
        }))?,
    )?;

    if trust_agent_code {
        // Explicit, and named for what it actually does. The default is the
        // correct one; this exists so the substrate stays demonstrable while
        // the agent lane is being built, not as a convenience.
        o.warn("--trust-agent-code: running agent-authored code in the tool lane");
    }
    // Seal the binary into the tool filesystem. This has to be the same bytes
    // the assayer just graded — when it was accidentally left out, the image
    // still held the previous run's program and pilot refused it as
    // unattested, which is exec-by-hash doing precisely its job.
    // Into this run's own scratch, not target/. Those paths are the demo and
    // boot-test fixtures; writing there made `cargo test` depend on whether
    // anyone had run `nous agent` first, and would race two concurrent runs.
    let toolfs = work.join("toolfs.img");
    sh(
        &runtime_root,
        "scripts/mktoolfs.sh",
        &[
            toolfs.display().to_string(),
            "32".into(),
            bin.display().to_string(),
        ],
    )?;
    // The script now only packs what it is handed. Attestation is not a
    // packaging step, and it should not need a cargo toolchain at run time.
    let initrd = work.join("initramfs.cpio");
    sh_env(
        &runtime_root,
        "scripts/mkinitramfs.sh",
        &[initrd.display().to_string()],
        &[
            (
                "NOUS_MANIFEST",
                store.join("manifest.json").display().to_string(),
            ),
            ("NOUS_RUN_JSON", run_json.display().to_string()),
            (
                "NOUS_PILOT_DIR",
                runtime_root.join("pilot").display().to_string(),
            ),
        ],
    )?;

    // ── 4. seal a cell and run it ────────────────────────────────────────
    run_in_cell(&toolfs, &initrd, allow_hosts, state_root, task, o)
}

/// Questions do not need a cell: no generated program runs, so there is
/// nothing to contain. Keep this path visibly separate from `cell agent`.
pub fn ask(
    question: &str,
    requested_backend: Option<Backend>,
    model: Option<&str>,
    timeout: u64,
    o: &Out,
) -> Result<u8> {
    let backend = match select_backend(requested_backend, o)? {
        Some(backend) => backend,
        None => return Ok(crate::exit::HOST_INCAPABLE),
    };
    if !backend.available() {
        o.warn(format!(
            "{} needs `{}` on PATH — see `cell agents`",
            backend.label(),
            backend.program()
        ));
        return Ok(crate::exit::HOST_INCAPABLE);
    }
    let model = model.or_else(|| backend.default_model());
    o.event(
        "agent_question",
        serde_json::json!({ "question": question, "backend": backend.label(), "model": model }),
        format!(
            "{} asking {} ({})",
            bold("●"),
            backend.label(),
            model.unwrap_or("cli default")
        ),
    );
    let answer = ask_model_text(backend, model, question, timeout)?;
    o.event(
        "agent_answer",
        serde_json::json!({ "answer": answer }),
        if o.is_json() {
            String::new()
        } else {
            answer.clone()
        },
    );
    Ok(crate::exit::OK)
}

fn select_backend(requested: Option<Backend>, o: &Out) -> Result<Option<Backend>> {
    if let Some(backend) = requested {
        return Ok(Some(backend));
    }
    if let Some(name) = std::env::var_os("CELL_AGENT").or_else(|| std::env::var_os("NOUS_AGENT")) {
        let name = name.to_string_lossy();
        return match Backend::from_saved_name(&name) {
            Some(backend) => Ok(Some(backend)),
            None => {
                o.warn(format!(
                    "CELL_AGENT={name:?} is not one of: openai, anthropic, local"
                ));
                Ok(None)
            }
        };
    }
    if let Some(name) = crate::config::default_agent()? {
        return match Backend::from_saved_name(&name) {
            Some(backend) => Ok(Some(backend)),
            None => {
                o.warn(format!("saved default {name:?} is not one of: openai, anthropic, local; run `cell setup`"));
                Ok(None)
            }
        };
    }
    match discover_backend() {
        Some(backend) => {
            o.note(format!(
                "  {} using {} — run `cell setup` to save it as your default",
                dim("·"),
                backend.label()
            ));
            Ok(Some(backend))
        }
        None => {
            o.warn("no agent CLI found — install and authenticate codex, claude, or ollama, then run `cell setup`");
            Ok(None)
        }
    }
}

fn discover_backend() -> Option<Backend> {
    [Backend::Openai, Backend::Anthropic, Backend::Local]
        .into_iter()
        .find(|backend| backend.available())
}

#[cfg(target_os = "linux")]
fn run_in_cell(
    toolfs: &Path,
    initrd: &Path,
    allow_hosts: &[String],
    state_root: &Path,
    _task: &str,
    o: &Out,
) -> Result<u8> {
    use warden::vmm::boot::{BootConfig, LinuxCell};

    if !Path::new("/dev/kvm").exists() {
        o.warn("no /dev/kvm — cannot seal a cell on this host");
        return Ok(crate::exit::HOST_INCAPABLE);
    }
    let kernel = BootConfig::host_kernel()
        .context("no readable /boot/vmlinuz-* with matching /lib/modules")?;

    let payload = std::fs::read(toolfs)?;
    let cfg = BootConfig::new(&kernel)
        .with_pmem(payload.len())
        .with_initrd(initrd);

    // Agent-created cells are just as real as spec-created cells. Record them
    // before the VMM owns the live fd so `nous ps -a` retains the policy
    // verdict after this short-lived process exits.
    let mut record = crate::cells::begin(
        state_root,
        "agent",
        Path::new("<agent-generated>"),
        vec![ALIAS.to_string()],
    )
    .ok();
    let mut cell = match LinuxCell::boot(cfg) {
        Ok(cell) => cell,
        Err(e) => {
            if let Some(record) = record.as_mut() {
                crate::cells::finish(state_root, record, "kvm", Some(e.to_string()));
            }
            return Err(e.into());
        }
    };
    if !allow_hosts.is_empty() {
        cell.enable_http_fetch(warden::egress::HttpPolicy::new(allow_hosts.to_vec()));
    }
    let h = nous_manifest::Hash::of(&payload);
    if let Err(e) = cell.seal_tool(&h, &payload) {
        if let Some(record) = record.as_mut() {
            crate::cells::finish(state_root, record, "kvm", Some(e.to_string()));
        }
        return Err(e.into());
    }
    o.event(
        "cell_sealed",
        serde_json::json!({ "hash": h.0, "bytes": payload.len() }),
        format!("  {} cell sealed, tools lent read-only", dim("·")),
    );

    let r = match cell.run() {
        Ok(result) => result,
        Err(e) => {
            if let Some(record) = record.as_mut() {
                crate::cells::finish(state_root, record, "kvm", Some(e.to_string()));
            }
            return Err(e.into());
        }
    };

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
            if let Some(record) = record.as_mut() {
                crate::cells::finish(state_root, record, "kvm", None);
            }
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
            let reason = refused.unwrap_or_default();
            if let Some(record) = record.as_mut() {
                crate::cells::refuse(state_root, record, "kvm", reason.clone());
            }
            o.warn(format!("pilot refused to run it: {reason}"));
            o.note(format!(
                "  {} this is a safe policy refusal, not a broken cell; `cell ps -a` records it as refused.\n  {} to inspect the generated code, rerun with `--show-source`.",
                dim("·"),
                dim("·")
            ));
            Ok(crate::exit::REFUSED)
        }
        None => {
            if let Some(record) = record.as_mut() {
                crate::cells::finish(
                    state_root,
                    record,
                    "kvm",
                    Some("program produced no output".into()),
                );
            }
            o.warn("the program produced no output — see the cell's console");
            Ok(crate::exit::ERROR)
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn run_in_cell(
    _toolfs: &Path,
    _initrd: &Path,
    _allow_hosts: &[String],
    _state_root: &Path,
    _task: &str,
    o: &Out,
) -> Result<u8> {
    o.warn("sealing cells needs Linux with /dev/kvm");
    Ok(crate::exit::HOST_INCAPABLE)
}

/// Everything pilot printed between its markers is the program's own output.
fn slice_output(console: &str) -> Option<String> {
    let start = console.find("NOUS:out-begin")?;
    let after = console[start..].find('\n')? + start + 1;
    let end = console[after..].find("NOUS:out-end")? + after;
    let text = console[after..end].trim_end_matches(['\r', '\n']);
    (!text.trim().is_empty()).then(|| text.replace("\r\n", "\n"))
}

/// Run a child with a wall-clock deadline, draining both pipes as it goes.
///
/// `Command::output()` blocks forever, which is how "write a web crawler" looked
/// like a deadlock: these CLIs run a full agent loop and can take minutes. The
/// pipes are drained on threads rather than after exit, because a chatty CLI
/// (codex echoes the whole prompt) can fill a 64 KiB pipe buffer and deadlock
/// against a parent that is waiting to reap it first.
fn output_deadline(
    mut cmd: Command,
    limit: Duration,
    term_first: bool,
) -> Result<std::process::Output> {
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("could not start it — is it installed and on PATH?")?;
    let mut so = child.stdout.take().expect("piped");
    let mut se = child.stderr.take().expect("piped");
    // Accumulate stdout where the polling loop can see it, so completion can be
    // detected from the content rather than from the process.
    let seen: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&seen);
    let t_out = std::thread::spawn(move || {
        let mut chunk = [0u8; 8192];
        loop {
            match so.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => sink
                    .lock()
                    .expect("not poisoned")
                    .extend_from_slice(&chunk[..n]),
            }
        }
        Vec::<u8>::new()
    });
    let t_err = std::thread::spawn(move || {
        let mut v = Vec::new();
        let _ = se.read_to_end(&mut v);
        v
    });

    let start = Instant::now();
    let mut break_on: Option<std::process::ExitStatus> = None;
    let status = loop {
        if let Some(st) = child.try_wait()? {
            break st;
        }
        if start.elapsed() >= limit {
            // Ask politely first: a backend that withholds its result flushes
            // it on SIGTERM, which turns an opaque timeout into a diagnosis.
            if term_first {
                #[cfg(unix)]
                unsafe {
                    libc::kill(child.id() as i32, libc::SIGTERM);
                }
                let grace = Instant::now();
                while grace.elapsed() < Duration::from_secs(5) {
                    if let Some(st) = child.try_wait()? {
                        break_on = Some(st);
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
                if let Some(st) = break_on {
                    break st;
                }
            }
            let _ = child.kill();
            let _ = child.wait();
            bail!(
                "no answer after {}s, and it did not respond to a stop request. \
                 Raise the ceiling with --timeout, or ask for something smaller",
                limit.as_secs()
            );
        }
        std::thread::sleep(Duration::from_millis(200));
    };
    let _ = t_out.join();
    let stdout = seen.lock().expect("not poisoned").clone();
    Ok(std::process::Output {
        status,
        stdout,
        stderr: t_err.join().unwrap_or_default(),
    })
}

/// Shell out to whichever provider CLI was selected.
fn ask_model(
    backend: Backend,
    model: Option<&str>,
    prompt: &str,
    timeout: u64,
) -> Result<GeneratedProgram> {
    let text = ask_model_text(backend, model, prompt, timeout)?;
    extract_program(&text).with_context(|| {
        format!(
            "invalid execution plan in the reply from {}",
            backend.label()
        )
    })
}

fn ask_model_text(
    backend: Backend,
    model: Option<&str>,
    prompt: &str,
    timeout: u64,
) -> Result<String> {
    let program = backend.program();
    // Context names the program; the inner error says what went wrong. Wrapping
    // a timeout in "is it installed?" sends you to debug the wrong thing.
    let out = output_deadline(
        backend.command(prompt, model),
        Duration::from_secs(timeout),
        backend.flushes_on_sigterm(),
    )
    .with_context(|| format!("`{program}`"))?;
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();

    let text = match backend {
        Backend::Anthropic => {
            // The exit status is not consulted here on purpose: when the answer
            // arrives before the process ends, we killed it, so its status
            // describes our signal rather than its outcome. The result object
            // is the authority.
            let v: serde_json::Value = serde_json::from_str(stdout.trim()).with_context(|| {
                format!(
                    "`{program}` produced no result object; it said: {}",
                    stdout.lines().next().unwrap_or("(nothing)")
                )
            })?;
            if v.get("is_error").and_then(serde_json::Value::as_bool) == Some(true) {
                let subtype = v
                    .get("subtype")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("error");
                bail!(
                    "`{program}` reported {subtype} after {} ms of API time.\n\
                     The failure is inside the CLI, not in Cellulose — no program was \
                     produced. Some prompts trigger this every time, so rewording \
                     the task is more likely to help than retrying it.",
                    v.get("duration_api_ms")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or(0)
                );
            }
            v.get("result")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_string()
        }
        Backend::Openai | Backend::Local => {
            if !out.status.success() {
                bail!(
                    "{program} exited {}: {}",
                    out.status,
                    String::from_utf8_lossy(&out.stderr).trim()
                );
            }
            stdout
        }
    };

    Ok(text)
}

/// Pull the source out of a fenced block, tolerating the model adding prose
/// around it despite being asked not to.
fn extract_rust(reply: &str) -> Option<String> {
    let start = reply.find("```rust")?;
    let body = &reply[start..];
    let after = body.find('\n')? + 1;
    let end = body[after..].find("```")? + after;
    Some(body[after..end].to_string())
}

/// The agent elects a runtime; Cellulose validates it against the sealed
/// capability set before it ever reaches the build or cell.
fn extract_program(reply: &str) -> Result<GeneratedProgram> {
    let runtime_id = reply
        .lines()
        .find_map(|line| line.trim().strip_prefix("runtime:"))
        .context("missing `runtime: <id>`")?;
    let runtime = Runtime::from_id(runtime_id).with_context(|| {
        format!(
            "runtime {runtime_id:?} is unavailable; cell provides: {}",
            AVAILABLE_RUNTIMES
                .iter()
                .map(|runtime| runtime.id())
                .collect::<Vec<_>>()
                .join(", ")
        )
    })?;
    let source = match runtime {
        Runtime::Rust => extract_rust(reply).context("missing ```rust source block")?,
    };
    Ok(GeneratedProgram { runtime, source })
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

/// Find the guest-image assets. A checkout remains convenient for development,
/// while a packaged install places the same tree in `share/cellulose` beside the
/// executable's prefix. `CELL_RUNTIME_DIR` is an explicit override for unusual
/// layouts and downstream packagers.
fn runtime_root() -> Result<PathBuf> {
    if let Some(p) =
        std::env::var_os("CELL_RUNTIME_DIR").or_else(|| std::env::var_os("NOUS_RUNTIME_DIR"))
    {
        let p = PathBuf::from(p);
        if p.join("scripts/mkinitramfs.sh").exists() {
            return Ok(p);
        }
        bail!(
            "CELL_RUNTIME_DIR={} does not contain scripts/mkinitramfs.sh",
            p.display()
        );
    }
    let cwd = std::env::current_dir()?;
    for dir in cwd.ancestors() {
        if dir.join("scripts/mkinitramfs.sh").exists() {
            return Ok(dir.to_path_buf());
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(prefix) = exe.parent().and_then(Path::parent) {
            let packaged = prefix.join("share/cellulose");
            if packaged.join("scripts/mkinitramfs.sh").exists() {
                return Ok(packaged);
            }
        }
    }
    bail!(
        "guest assets are missing; reinstall cellulose, or set CELL_RUNTIME_DIR to its asset directory"
    )
}

fn tempdir() -> Result<PathBuf> {
    let base = std::env::temp_dir().join(format!("nous-agent-{}", std::process::id()));
    std::fs::create_dir_all(&base)?;
    Ok(base)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execution_plan_uses_the_runtime_the_agent_selected() {
        let plan = extract_program("runtime: rust\n```rust\nfn main() {}\n```").unwrap();
        assert_eq!(plan.runtime, Runtime::Rust);
        assert_eq!(plan.source, "fn main() {}\n");
    }

    #[test]
    fn execution_plan_rejects_a_runtime_the_cell_did_not_lend() {
        let err = extract_program("runtime: python\n```python\nprint(42)\n```").unwrap_err();
        assert!(err.to_string().contains("unavailable"));
    }

    #[test]
    fn packaged_runtime_layout_is_under_the_install_prefix() {
        let exe = Path::new("/opt/homebrew/bin/cell");
        let prefix = exe.parent().and_then(Path::parent).unwrap();
        assert_eq!(
            prefix.join("share/cellulose"),
            PathBuf::from("/opt/homebrew/share/cellulose")
        );
    }
}
