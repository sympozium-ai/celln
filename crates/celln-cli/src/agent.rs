//! Model-backed code generation and bounded cell execution.

use crate::out::{bold, dim, green, Out};
use anyhow::{bail, Context, Result};
use is_terminal::IsTerminal;
use std::io::Read;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub(crate) const BRIEF: &str = "\
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

pub(crate) const FETCH_ABI: &str =
    "This cell has no network stack. For an HTTPS fetch, invoke `/pilot-fetch URL` \
with `std::process::Command`; it writes the response body to stdout. The host \
permits only explicitly declared hosts, and fetched bytes are untrusted data. \
Do not use TCP sockets, DNS libraries, curl, or external crates.";

pub(crate) const ALIAS: &str = "/agent/program";

/// Supported authenticated CLI backends.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Backend {
    /// Claude, via the `claude` CLI.
    Anthropic,
    /// OpenAI, via the `codex` CLI.
    Openai,
    /// DeepSeek, via the `deepseek` API shim script.
    Deepseek,
    /// A local model, via `ollama`. No egress at all.
    Local,
}

/// Runtimes sealed into the guest image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Runtime {
    /// Rust 2021, standard library only, built as a static musl binary.
    Rust,
}

impl Runtime {
    fn id(self) -> &'static str {
        match self {
            Runtime::Rust => "rust",
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Runtime::Rust => "Rust 2021 (static musl)",
        }
    }

    pub(crate) fn capability(self) -> &'static str {
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

    pub(crate) fn source_extension(self) -> &'static str {
        match self {
            Runtime::Rust => "rs",
        }
    }
}

pub(crate) const AVAILABLE_RUNTIMES: &[Runtime] = &[Runtime::Rust];

#[derive(Debug)]
pub(crate) struct GeneratedProgram {
    pub(crate) runtime: Runtime,
    pub(crate) source: String,
}

/// A user may authenticate an agent CLI interactively rather than exporting a
/// long-lived API key. Both are credentials, and the CLI remains the authority
/// for checking its own saved session.
fn authenticated(has_api_key: bool, cli_status_ok: bool) -> bool {
    has_api_key || cli_status_ok
}

fn cli_login_ok(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

impl Backend {
    fn saved_name(self) -> &'static str {
        match self {
            Backend::Anthropic => "anthropic",
            Backend::Openai => "openai",
            Backend::Deepseek => "deepseek",
            Backend::Local => "local",
        }
    }

    pub(crate) fn from_saved_name(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "anthropic" | "claude" => Some(Backend::Anthropic),
            "openai" | "codex" => Some(Backend::Openai),
            "deepseek" => Some(Backend::Deepseek),
            "local" | "ollama" => Some(Backend::Local),
            _ => None,
        }
    }

    /// The CLI this backend drives. Its presence is the availability check.
    pub(crate) fn program(self) -> &'static str {
        match self {
            Backend::Anthropic => "claude",
            Backend::Openai => "codex",
            Backend::Deepseek => "deepseek-api",
            Backend::Local => "ollama",
        }
    }

    /// Used when the user does not name one. `None` means "whatever that CLI
    /// is already configured to use" — the right default when the tool has its
    /// own config and account-specific model availability, which is exactly the
    /// case for `codex`. Overridable with `--model` in every case, because
    /// model names date fast.
    pub(crate) fn default_model(self) -> Option<&'static str> {
        match self {
            Backend::Anthropic => Some("claude-opus-5"),
            Backend::Openai => None,
            Backend::Deepseek => Some("deepseek-chat"),
            Backend::Local => Some("qwen2.5-coder"),
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Backend::Anthropic => "anthropic",
            Backend::Openai => "openai",
            Backend::Deepseek => "deepseek",
            Backend::Local => "local",
        }
    }

    pub(crate) fn available(self) -> bool {
        which(self.program()).is_some()
    }

    /// Check whether the credentials or daemon this backend needs are
    /// actually present. Availability means the CLI is on PATH; validation
    /// means it can actually do work.
    fn validate(self) -> Result<(), String> {
        match self {
            Backend::Anthropic => {
                if !authenticated(
                    std::env::var("ANTHROPIC_API_KEY").is_ok()
                        || std::env::var("CLAUDE_API_KEY").is_ok(),
                    cli_login_ok("claude", &["auth", "status"]),
                ) {
                    return Err(
                        "`claude` has no saved login and ANTHROPIC_API_KEY is not set — authenticate it or set a key".into(),
                    );
                }
                Ok(())
            }
            Backend::Openai => {
                if !authenticated(
                    std::env::var("OPENAI_API_KEY").is_ok(),
                    cli_login_ok("codex", &["login", "status"]),
                ) {
                    return Err(
                        "`codex` has no saved login and OPENAI_API_KEY is not set — authenticate it or set a key".into(),
                    );
                }
                Ok(())
            }
            Backend::Deepseek => {
                if std::env::var("DEEPSEEK_API_KEY").is_err() {
                    return Err(
                        "DEEPSEEK_API_KEY is not set — `deepseek-api` needs it to call api.deepseek.com".into(),
                    );
                }
                Ok(())
            }
            Backend::Local => {
                // ollama needs the daemon running. Quick check: does `ollama list`
                // exit successfully?
                let out = std::process::Command::new("ollama")
                    .args(["list"])
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status();
                match out {
                    Ok(s) if s.success() => Ok(()),
                    _ => Err("ollama daemon is not running — start it with `ollama serve`".into()),
                }
            }
        }
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
            Backend::Deepseek => {
                c.arg(prompt);
                if let Some(m) = model {
                    c.arg("--model").arg(m);
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
/// Mirrors `celln tools`: the question is always "what is available here".
pub fn agents(set_default: Option<Backend>, o: &Out) -> Result<u8> {
    if let Some(backend) = set_default {
        let path = crate::config::set_default_agent(backend.saved_name())?;
        o.event(
            "agent_default",
            serde_json::json!({"backend": backend.saved_name(), "config": path}),
            format!("✔ default agent: {} ({})", backend.label(), path.display()),
        );
        match backend.validate() {
            Ok(()) => {
                o.event(
                    "agent_validated",
                    serde_json::json!({"backend": backend.saved_name()}),
                    format!("✔ {} credentials verified", backend.label()),
                );
            }
            Err(msg) => {
                o.warn(format!("{}: {msg}", backend.label()));
            }
        }
    }
    let saved = crate::config::default_agent()?;
    for b in [
        Backend::Anthropic,
        Backend::Openai,
        Backend::Deepseek,
        Backend::Local,
    ] {
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

pub fn setup(
    preferred: Option<Backend>,
    root: &Path,
    tools: Option<&str>,
    no_tools: bool,
    o: &Out,
) -> Result<u8> {
    // Which model writes code has nothing to do with which tools a host can
    // lend, so a missing agent CLI must not skip the rest of setup. It used to
    // return here, which meant a node provisioned without one silently got no
    // tool images at all — the failure was reported as a warning about the
    // wrong thing entirely.
    let backend = match preferred {
        Some(backend) if backend.available() => Some(backend),
        Some(backend) => {
            o.warn(format!(
                "{} is not available — install and authenticate `{}` first",
                backend.label(),
                backend.program()
            ));
            None
        }
        None => {
            // Interactive: show available backends and let the user pick.
            // Non-interactive (piped): fall back to auto-discovery.
            if std::io::stdout().is_terminal() {
                interactive_backend_select(o)?
            } else {
                match discover_backend() {
                    Some(backend) => {
                        o.note(format!(
                            "  {} auto-discovered {} — run `celln setup` interactively to choose",
                            dim("·"),
                            backend.label()
                        ));
                        Some(backend)
                    }
                    None => {
                        o.warn("no agent CLI found — install and authenticate codex, claude, deepseek, or ollama, then rerun `celln setup`");
                        None
                    }
                }
            }
        }
    };

    if let Some(backend) = backend {
        let path = crate::config::set_default_agent(backend.saved_name())?;
        o.event(
            "agent_default",
            serde_json::json!({"backend": backend.saved_name(), "config": path}),
            format!("✔ default agent: {} ({})", backend.label(), path.display()),
        );

        // Validate credentials so the user finds out now, not on first use.
        match backend.validate() {
            Ok(()) => {
                o.event(
                    "agent_validated",
                    serde_json::json!({"backend": backend.saved_name()}),
                    format!("✔ {} credentials verified", backend.label()),
                );
            }
            Err(msg) => {
                o.warn(format!("{}: {msg}", backend.label()));
            }
        }
    }

    // Install runtime assets (scripts, pilot binaries) into ~/.celln/runtime/
    // so the binary is self-contained and doesn't need the source checkout.
    match install_runtime_assets() {
        Ok(dest) => {
            o.event(
                "runtime_assets",
                serde_json::json!({"destination": dest.display().to_string()}),
                format!("✔ runtime assets installed to {}", dest.display()),
            );
        }
        Err(e) => {
            o.warn(format!("could not install runtime assets: {e:#}"));
        }
    }

    if no_tools {
        o.note(format!(
            "  {} skipping tool images; `celln image catalogue` lists them",
            dim("·")
        ));
    } else {
        o.say("");
        o.say(bold("tool images"));
        match crate::image::pull_defaults(root, tools, o) {
            Ok(n) => o.note(format!("  {} {n} image(s) ready", dim("·"))),
            Err(e) => o.warn(format!("tool images: {e:#}")),
        }
    }

    // Still say so in the exit code: a host with tools but no agent CLI can
    // run a declared spec and cannot ask a model to write one.
    Ok(if backend.is_some() {
        crate::exit::OK
    } else {
        crate::exit::HOST_INCAPABLE
    })
}

/// List available backends interactively and prompt the user to pick one.
/// Returns `None` if no backends are available or the user cancels.
fn interactive_backend_select(o: &Out) -> Result<Option<Backend>> {
    let all = [
        Backend::Anthropic,
        Backend::Openai,
        Backend::Deepseek,
        Backend::Local,
    ];

    let available: Vec<Backend> = all.iter().copied().filter(|b| b.available()).collect();

    if available.is_empty() {
        o.say("no agent CLI found on this host.");
        o.say("");
        o.say("install one of these and rerun `celln setup`:");
        for b in &all {
            o.say(format!(
                "  {} — {} ({})",
                b.label(),
                b.default_model().unwrap_or("(cli default)"),
                b.program()
            ));
        }
        return Ok(None);
    }

    if available.len() == 1 {
        let b = available[0];
        o.say(format!(
            "only {} ({}) is available — selecting it automatically.",
            b.label(),
            b.program()
        ));
        return Ok(Some(b));
    }

    o.say("available agent backends:");
    o.say("");
    for (i, b) in available.iter().enumerate() {
        let model = b.default_model().unwrap_or("(cli default)");
        o.say(format!(
            "  [{}] {:<10}  {:<22}  ({})",
            i + 1,
            b.label(),
            model,
            b.program(),
        ));
    }
    o.say("");

    loop {
        // Print the prompt directly — no Out wrapper, because we need
        // the prompt to appear even when the terminal is being watched.
        eprint!("select default agent [1-{}]: ", available.len());
        let _ = std::io::stderr().flush();

        let mut input = String::new();
        if std::io::stdin().read_line(&mut input).is_err() {
            o.warn("could not read input — run `celln setup --agent <name>` instead");
            return Ok(None);
        }

        let trimmed = input.trim();
        if trimmed.is_empty() {
            o.say(format!(
                "  {} no selection — run `celln setup --agent <name>` to set one later",
                dim("·")
            ));
            return Ok(None);
        }

        match trimmed.parse::<usize>() {
            Ok(n) if n >= 1 && n <= available.len() => {
                return Ok(Some(available[n - 1]));
            }
            _ => {
                // Try matching by name
                if let Some(b) = Backend::from_saved_name(trimmed) {
                    if b.available() {
                        return Ok(Some(b));
                    }
                    o.say(format!(
                        "  {} {} is not installed — pick a number from the list",
                        dim("·"),
                        b.label()
                    ));
                    continue;
                }
                o.say(format!(
                    "  {} enter a number 1-{}, or press enter to skip",
                    dim("·"),
                    available.len()
                ));
            }
        }
    }
}

/// Copy the guest runtime assets (scripts, pilot) into `~/.celln/runtime/`.
/// This makes the installed binary self-contained — no env vars, no checkout
/// required. The source is found via the compile-time manifest directory.
fn install_runtime_assets() -> Result<PathBuf> {
    bootstrap_runtime().with_context(|| "installing runtime assets")
}

/// Core bootstrap logic, separated so it can be called lazily from runtime_root
/// (no Out reference) as well as from `celln setup`.
fn bootstrap_runtime() -> Result<PathBuf> {
    let dest = resolve_runtime_home()?;
    std::fs::create_dir_all(dest.join("scripts"))?;
    std::fs::create_dir_all(dest.join("guest/init"))?;
    std::fs::create_dir_all(dest.join("pilot"))?;

    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace = manifest
        .ancestors()
        .find(|d| d.join("scripts/mkinitramfs.sh").exists())
        .with_context(|| {
            "source checkout not found — run from the repo or set CELLN_RUNTIME_DIR"
        })?;

    // ── scripts ────────────────────────────────────────────────────
    for script in ["scripts/mkinitramfs.sh", "scripts/mktoolfs.sh"] {
        let src = workspace.join(script);
        let dst = dest.join(script);
        if src.exists() {
            std::fs::copy(&src, &dst).with_context(|| format!("copying {script}"))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = std::fs::metadata(&dst)?.permissions();
                perms.set_mode(0o755);
                std::fs::set_permissions(&dst, perms)?;
            }
        }
    }

    // ── guest init source ──────────────────────────────────────────
    let init_src = workspace.join("guest/init/init.c");
    if init_src.exists() {
        std::fs::copy(&init_src, dest.join("guest/init/init.c"))?;
    }

    // ── pilot binaries ─────────────────────────────────────────────
    // Try the musl target (as the initramfs script does), then the
    // host target as a fallback.
    let pilot_dirs = [
        workspace.join("target/x86_64-unknown-linux-musl/release"),
        workspace.join("target/release"),
        workspace.join("target/debug"),
    ];
    let mut found = false;
    for dir in &pilot_dirs {
        let pilot = dir.join("celln-pilot");
        let fetch = dir.join("pilot-fetch");
        if pilot.exists() && fetch.exists() {
            std::fs::copy(&pilot, dest.join("pilot/celln-pilot"))?;
            std::fs::copy(&fetch, dest.join("pilot/pilot-fetch"))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                for bin in ["pilot/celln-pilot", "pilot/pilot-fetch"] {
                    let mut perms = std::fs::metadata(dest.join(bin))?.permissions();
                    perms.set_mode(0o755);
                    std::fs::set_permissions(dest.join(bin), perms)?;
                }
            }
            found = true;
            break;
        }
    }
    if !found {
        // Try building them from the workspace
        eprintln!("  · building pilot binaries (one-time)...");
        let status = std::process::Command::new("cargo")
            .args([
                "build",
                "--release",
                "--target",
                "x86_64-unknown-linux-musl",
                "-p",
                "celln-pilot",
                "--bin",
                "celln-pilot",
                "--bin",
                "pilot-fetch",
            ])
            .current_dir(workspace)
            .status()
            .context("building pilot binaries")?;
        if !status.success() {
            anyhow::bail!("cargo build of pilot binaries failed");
        }
        let dir = workspace.join("target/x86_64-unknown-linux-musl/release");
        std::fs::copy(dir.join("celln-pilot"), dest.join("pilot/celln-pilot"))?;
        std::fs::copy(dir.join("pilot-fetch"), dest.join("pilot/pilot-fetch"))?;
    }

    Ok(dest)
}

fn resolve_runtime_home() -> Result<PathBuf> {
    let home = std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."));
    Ok(home.join(".celln/runtime"))
}

pub(crate) fn which(program: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|d| d.join(program))
            .find(|p| p.is_file())
    })
}

pub struct AgentRequest<'a> {
    pub task: &'a str,
    /// Persistent cell registry and store root (`--root` / `CELLN_ROOT`).
    pub state_root: &'a Path,
    pub requested_backend: Option<Backend>,
    pub model: Option<&'a str>,
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
            "{} needs `{}` on PATH — see `celln agents`",
            backend.label(),
            backend.program()
        ));
        return Ok(crate::exit::HOST_INCAPABLE);
    }
    let runtime_root = runtime_root()?;
    let work = tempdir()?;
    let work = work.path();
    // The cell has no ambient network. Do not make an agent spend
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

    // Compiling agent source never changes its provenance. The resulting
    // artifact is attested for exec-by-hash, but always executes in the agent
    // lane inside a real cell.
    let author = celln_manifest::Author::Agent;
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
            "agent_authored_input": true,
        }))?,
    )?;

    // Seal the binary into the tool filesystem. This has to be the same bytes
    // the assayer just graded — when it was accidentally left out, the image
    // still held the previous run's program and pilot refused it as
    // unattested, which is exec-by-hash doing precisely its job.
    // Into this run's own scratch, not target/. Those paths are the demo and
    // boot-test fixtures; writing there made `cargo test` depend on whether
    // anyone had run `celln agent` first, and would race two concurrent runs.
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
                "CELLN_MANIFEST",
                store.join("manifest.json").display().to_string(),
            ),
            ("CELLN_RUN_JSON", run_json.display().to_string()),
            (
                "CELLN_PILOT_DIR",
                runtime_root.join("pilot").display().to_string(),
            ),
        ],
    )?;

    // ── 4. seal a cell and run it ────────────────────────────────────────
    run_in_cell(&toolfs, &initrd, allow_hosts, state_root, task, o)
}

fn select_backend(requested: Option<Backend>, o: &Out) -> Result<Option<Backend>> {
    if let Some(backend) = requested {
        return Ok(Some(backend));
    }
    if let Some(name) = std::env::var_os("CELLN_AGENT").or_else(|| std::env::var_os("CELL_AGENT")) {
        let name = name.to_string_lossy();
        return match Backend::from_saved_name(&name) {
            Some(backend) => Ok(Some(backend)),
            None => {
                o.warn(format!(
                    "CELLN_AGENT={name:?} is not one of: openai, anthropic, deepseek, local"
                ));
                Ok(None)
            }
        };
    }
    if let Some(name) = crate::config::default_agent()? {
        return match Backend::from_saved_name(&name) {
            Some(backend) => Ok(Some(backend)),
            None => {
                o.warn(format!("saved default {name:?} is not one of: openai, anthropic, deepseek, local; run `celln setup`"));
                Ok(None)
            }
        };
    }
    match discover_backend() {
        Some(backend) => {
            o.note(format!(
                "  {} using {} — run `celln setup` to save it as your default",
                dim("·"),
                backend.label()
            ));
            Ok(Some(backend))
        }
        None => {
            o.warn("no agent CLI found — install and authenticate codex, claude, or ollama, then run `celln setup`");
            Ok(None)
        }
    }
}

pub(crate) fn discover_backend() -> Option<Backend> {
    [
        Backend::Openai,
        Backend::Anthropic,
        Backend::Deepseek,
        Backend::Local,
    ]
    .into_iter()
    .find(|backend| backend.available())
}

#[cfg(target_os = "linux")]
fn run_in_cell(
    toolfs: &Path,
    initrd: &Path,
    allow_hosts: &[String],
    state_root: &Path,
    task: &str,
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

    // Derive a readable description from the task.
    let name = if task.len() <= 30 {
        task.to_string()
    } else {
        let mut end = 30;
        while !task.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}…", &task[..end])
    };

    // Agent-created cells are just as real as spec-created cells. Record them
    // before the VMM owns the live fd so `celln ps -a` retains the policy
    // verdict after this short-lived process exits.
    let mut record = crate::cells::begin(
        state_root,
        &name,
        Path::new("<agent-generated>"),
        vec![ALIAS.to_string()],
    )
    .ok();
    // A dispatcher must obtain the actual registry identity before it reports
    // a running action upstream. Emitting it at creation keeps a future
    // transport from deriving or fabricating a cell ID after the VM exits.
    if let Some(record) = record.as_ref() {
        o.event(
            "cell_started",
            serde_json::json!({ "cellId": record.id, "description": record.description }),
            format!("  {} cell {} started", dim("·"), record.id),
        );
    }
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
    let h = celln_manifest::Hash::of(&payload);
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
        let Some(rest) = line.strip_prefix("CELLN:pilot_run_") else {
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
                "  {} this is a safe policy refusal, not a broken cell; `celln ps -a` records it as refused.\n  {} to inspect the generated code, rerun with `--show-source`.",
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
            let detail = r
                .console
                .lines()
                .find(|line| line.starts_with("pilot: exec "))
                .unwrap_or("no pilot execution diagnostic");
            o.warn(format!("the program produced no output — {detail}"));
            o.note(format!(
                "  {} guest console: {}",
                dim("·"),
                r.console
                    .lines()
                    .rev()
                    .take(12)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect::<Vec<_>>()
                    .join(" | ")
            ));
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
pub(crate) fn slice_output(console: &str) -> Option<String> {
    let start = console.find("CELLN:out-begin")?;
    let after = console[start..].find('\n')? + start + 1;
    let end = console[after..].find("CELLN:out-end")? + after;
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
pub(crate) fn ask_model(
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
                     The failure is inside the CLI, not in Celln — no program was \
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
        Backend::Openai | Backend::Deepseek | Backend::Local => {
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

/// The agent elects a runtime; Celln validates it against the sealed
/// capability set before it ever reaches the build or cell.
pub(crate) fn extract_program(reply: &str) -> Result<GeneratedProgram> {
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

pub(crate) fn sh(root: &Path, script: &str, args: &[String]) -> Result<()> {
    sh_env(root, script, args, &[])
}

pub(crate) fn sh_env(
    root: &Path,
    script: &str,
    args: &[String],
    env: &[(&str, String)],
) -> Result<()> {
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
/// while a packaged install places the same tree in `share/celln` beside the
/// executable's prefix. `CELLN_RUNTIME_DIR` is an explicit override for unusual
/// layouts and downstream packagers.
pub(crate) fn runtime_root() -> Result<PathBuf> {
    if let Some(p) =
        std::env::var_os("CELLN_RUNTIME_DIR").or_else(|| std::env::var_os("CELL_RUNTIME_DIR"))
    {
        let p = PathBuf::from(p);
        if p.join("scripts/mkinitramfs.sh").exists() {
            return Ok(p);
        }
        bail!(
            "CELLN_RUNTIME_DIR={} does not contain scripts/mkinitramfs.sh",
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
            let packaged = prefix.join("share/celln");
            if packaged.join("scripts/mkinitramfs.sh").exists() {
                return Ok(packaged);
            }
        }
    }
    // Compile-time fallback: when installed from a local checkout with
    // `cargo install --path`, the manifest directory points at the
    // crate source. Walk up from there to find the workspace root.
    {
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
        for dir in manifest.ancestors() {
            if dir.join("scripts/mkinitramfs.sh").exists() {
                return Ok(dir.to_path_buf());
            }
        }
    }
    // Self-bootstrapped: celln setup copies the runtime assets into
    // the cell state directory so the binary is self-contained. If the
    // directory exists but assets are missing, try a lazy bootstrap.
    {
        let home = std::env::var("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("."));
        let bootstrapped = home.join(".celln/runtime");
        if bootstrapped.join("scripts/mkinitramfs.sh").exists() {
            return Ok(bootstrapped);
        }
        // Lazy first-time bootstrap — the binary carries its own source
        // path via CARGO_MANIFEST_DIR. If that checkout still exists,
        // install assets transparently.
        if let Ok(dest) = bootstrap_runtime() {
            if dest.join("scripts/mkinitramfs.sh").exists() {
                return Ok(dest);
            }
        }
    }
    bail!(
        "guest assets are missing; reinstall celln, or set CELLN_RUNTIME_DIR to its asset directory"
    )
}

/// Scratch for one run: a toolfs image and an initramfs, so image-sized.
///
/// Returns a guard rather than a path because these used to be named by pid
/// and left behind. On a host where /tmp is a tmpfs — which is most of them —
/// that leaks the image size in RAM per run; it reached 13 GiB here before it
/// was noticed. Dropping the guard removes the directory.
pub(crate) fn tempdir() -> Result<tempfile::TempDir> {
    Ok(tempfile::Builder::new().prefix("celln-").tempdir()?)
}

/// A program a model wrote, and how to hand it to its interpreter.
pub(crate) struct WrittenProgram {
    pub(crate) flag: String,
    pub(crate) code: String,
}

const TOOL_BRIEF: &str = "\
Write a single %LANGUAGE% program that does the following:

%TASK%

Requirements:
- use only the %LANGUAGE% standard library
- write the result to stdout
- exit 0 on success
- the program runs sealed, with no network and no writable filesystem except /tmp

Reply with exactly one fenced code block containing the program, and no prose.
";

/// Pull the program out of a fenced block, tolerating a language tag and prose.
fn extract_fenced(reply: &str) -> Option<String> {
    let start = reply.find("```")?;
    let after = reply[start + 3..].find('\n')? + start + 4;
    let end = reply[after..].find("```")? + after;
    let body = reply[after..end].trim_end();
    (!body.trim().is_empty()).then(|| body.to_string())
}

/// Ask the configured model for a program the declared tool can interpret.
pub(crate) fn write_program(
    spec: &celln_spec::Spec,
    exec_alias: &str,
    task: &str,
    root: &Path,
    o: &Out,
) -> Result<WrittenProgram> {
    let tool = spec
        .tools
        .iter()
        .find(|t| t.alias == exec_alias)
        .with_context(|| format!("{exec_alias} is not a declared tool"))?;
    let image = tool
        .image
        .as_deref()
        .with_context(|| format!("{exec_alias} must come from an image to interpret model code"))?;
    let (_, provide) =
        crate::image::interpreter_for(image.split(&['@', ':'][..]).next().unwrap_or(image), root)?;
    let language = provide.language.clone().unwrap_or_else(|| "code".into());
    let flag = provide.code_flag.clone().unwrap_or_else(|| "-c".into());

    let backend = match select_backend(None, o)? {
        Some(b) => b,
        None => bail!("no agent CLI configured; run `celln setup`"),
    };
    let model = backend.default_model();
    o.event(
        "agent_brief",
        serde_json::json!({ "task": task, "language": language, "backend": backend.label() }),
        format!(
            "{} asking {} for {} to run as {}",
            bold("●"),
            backend.label(),
            language,
            exec_alias
        ),
    );
    let brief = TOOL_BRIEF
        .replace("%LANGUAGE%", &language)
        .replace("%TASK%", task);
    let started = Instant::now();
    let reply = ask_model_text(backend, model, &brief, 120)?;
    let code = extract_fenced(&reply)
        .with_context(|| format!("{} did not return a fenced program", backend.label()))?;
    o.note(format!(
        "  {} replied in {:.0}s, {} lines",
        dim("·"),
        started.elapsed().as_secs_f32(),
        code.lines().count()
    ));
    Ok(WrittenProgram { flag, code })
}

/// `celln agent --tool <name> "<task>"` — no spec file.
///
/// Builds the cell a spec would have described and runs it through the same
/// path, so an ad-hoc run reaches the same trust decisions as a declared one.
pub fn with_tool(
    task: &str,
    tool: &str,
    allow_hosts: &[String],
    root: &Path,
    o: &Out,
) -> Result<u8> {
    let (image, provide) = crate::image::interpreter_for(tool, root)?;
    if crate::image::image_is_materialised(&image, root) {
        // nothing to do
    } else {
        o.note(format!(
            "  {} {tool} is not materialised yet; pulling it once",
            dim("·")
        ));
        crate::image::pull(&image.ref_, root, o)?;
    }
    let spec = celln_spec::Spec {
        name: tool.to_string(),
        cell: celln_spec::Cell {
            memory: "512MiB".into(),
            require_tier: celln_spec::Tier::Verified,
            allow_hosts: allow_hosts.to_vec(),
        },
        tools: vec![celln_spec::Tool {
            alias: provide.alias.clone(),
            path: None,
            image: Some(image.name.clone()),
            exec: Some(provide.exec.clone()),
            builtin: None,
            interpreter: true,
        }],
        run: None,
        agent: Some(celln_spec::AgentTask {
            task: Some(task.to_string()),
            exec: provide.alias.clone(),
        }),
    };
    crate::run::run_spec(spec, root, Path::new("<agent --tool>"), false, None, o)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saved_cli_login_is_accepted_without_an_api_key() {
        assert!(authenticated(false, true));
        assert!(authenticated(true, false));
        assert!(!authenticated(false, false));
    }

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
        let exe = Path::new("/opt/homebrew/bin/celln");
        let prefix = exe.parent().and_then(Path::parent).unwrap();
        assert_eq!(
            prefix.join("share/celln"),
            PathBuf::from("/opt/homebrew/share/celln")
        );
    }
}
