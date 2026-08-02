//! `celln` command-line interface.

mod agent;
mod cells;
mod config;
mod host;
mod out;
mod run;

use anyhow::Result;
use clap::{Parser, Subcommand};
use out::{bold, dim, green, red, Out};
use std::path::PathBuf;
use std::process::ExitCode;

/// Stable process exit codes.
pub mod exit {
    pub const OK: u8 = 0;
    pub const ERROR: u8 = 1;
    pub const SPEC_INVALID: u8 = 2;
    pub const HOST_INCAPABLE: u8 = 3;
    pub const REFUSED: u8 = 4;
    pub const UNSUPPORTED: u8 = 5;
}

#[derive(Parser)]
#[command(
    name = "celln",
    version,
    about = "Run agents in hardware-isolated cells.",
    long_about = "Run agents in hardware-isolated cells, where every tool is attested \
                  memory the host lends in and can revoke.\n\n\
                  Start with `celln spec init > agent.toml`, then `celln spec check agent.toml`.",
    after_help = "Output is human-readable on a terminal and NDJSON when piped.\n\
                  Exit codes: 0 ok · 1 error · 2 spec invalid · 3 host cannot seal cells · 5 unsupported."
)]
struct Cli {
    /// Emit NDJSON regardless of whether stdout is a terminal.
    #[arg(long, global = true, conflicts_with = "no_json")]
    json: bool,
    /// Force human-readable output even when piped.
    #[arg(long, global = true)]
    no_json: bool,
    /// Suppress progress output. Errors still go to stderr.
    #[arg(short, long, global = true)]
    quiet: bool,
    /// Where cell state and the tool store live.
    #[arg(long, global = true, default_value = ".celln", env = "CELLN_ROOT")]
    root: PathBuf,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Report what this machine can run.
    Doctor,

    /// Work with cell specs.
    #[command(subcommand)]
    Spec(SpecCmd),

    /// Seal a cell from a spec and run its lifecycle.
    Run {
        /// Path to a cell spec.
        spec: PathBuf,
        /// Seal the cell but stop before running it.
        #[arg(long)]
        dry_run: bool,
    },

    /// List cells, like `docker ps`. Recent runs need `-a`.
    Ps {
        /// Include cells that have already finished.
        #[arg(short, long)]
        all: bool,
    },

    /// List the tools this host has attested.
    Tools,

    /// Prove the isolation properties on this machine.
    Verify,

    /// Have a model write a program, then run it sealed in a cell.
    ///
    /// This is for computations, not questions. It asks a model for a
    /// single-file Rust program, attests the binary, and runs it in a cell —
    /// so it is worth doing when there is code you would rather not run
    /// unsealed. For "what is the capital of France", ask the model directly;
    /// a cell has nothing to protect you from when no code runs.
    Agent {
        /// What the program should DO — a computation, not a question.
        #[arg(required = true, num_args = 1..)]
        task: Vec<String>,

        /// Print the source the model wrote.
        #[arg(long)]
        show_source: bool,

        /// Seconds to wait for the model before giving up.
        ///
        /// The happy path is seconds; this is the ceiling before we stop the
        /// CLI and ask it what went wrong.
        #[arg(long, default_value = "90")]
        timeout: u64,

        /// Which model writes it. Overrides CELLN_AGENT and the saved default.
        #[arg(long, value_enum)]
        agent: Option<agent::Backend>,

        /// Override the backend's default model.
        #[arg(long)]
        model: Option<String>,

        /// Run the generated program in the tool lane.
        ///
        /// Off by default, and the default is the correct one: code a model
        /// wrote is agent-authored however it was built, so it belongs in the
        /// agent lane. This exists only so the substrate stays demonstrable
        /// while the agent lane is being built.
        #[arg(long)]
        trust_agent_code: bool,

        /// Exact HTTPS host the cell may fetch through pilot (repeatable).
        /// Without this, the cell remains hermetic.
        #[arg(long = "allow-host")]
        allow_hosts: Vec<String>,
    },

    /// Ask the selected agent a question on the host; no cell is needed.
    Ask {
        /// The question to ask.
        #[arg(required = true, num_args = 1..)]
        question: Vec<String>,

        /// Which agent answers. Overrides CELLN_AGENT and the saved default.
        #[arg(long, value_enum)]
        agent: Option<agent::Backend>,

        /// Override the backend's default model.
        #[arg(long)]
        model: Option<String>,

        /// Seconds to wait for an answer before giving up.
        #[arg(long, default_value = "90")]
        timeout: u64,
    },

    /// Find agent CLIs and manage the saved default.
    Agents {
        /// Save the backend `celln agent` uses unless overridden.
        #[arg(long, value_enum)]
        set_default: Option<agent::Backend>,
    },

    /// Discover an agent CLI and save it as the default.
    Setup {
        /// Select this backend instead of auto-discovering one.
        #[arg(long, value_enum)]
        agent: Option<agent::Backend>,
    },

    /// Walk the five-beat proof loop. Works without KVM.
    Demo,
}

#[derive(Subcommand)]
enum SpecCmd {
    /// Print a starter spec. Redirect it into a file.
    Init,
    /// Validate a spec and show what would happen.
    Check {
        /// Path to a cell spec.
        spec: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let json = if cli.json {
        Some(true)
    } else if cli.no_json {
        Some(false)
    } else {
        None
    };
    let o = Out::new(json, cli.quiet);

    let code = match dispatch(&cli, &o) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("{}: {e:#}", red("error"));
            exit::ERROR
        }
    };
    ExitCode::from(code)
}

fn dispatch(cli: &Cli, o: &Out) -> Result<u8> {
    match &cli.cmd {
        Cmd::Doctor => Ok(doctor(o)),
        Cmd::Spec(SpecCmd::Init) => {
            // Straight to stdout, unstyled, so `celln spec init > agent.toml`
            // produces a file and not a screenshot of one.
            print!("{}", nous_spec::TEMPLATE);
            Ok(exit::OK)
        }
        Cmd::Spec(SpecCmd::Check { spec }) => run::check(spec, o),
        Cmd::Run { spec, dry_run } => run::run(spec, &cli.root, *dry_run, o),
        Cmd::Ps { all } => run::ps(&cli.root, *all, o),
        Cmd::Tools => run::tools(&cli.root, o),
        Cmd::Verify => run::verify(o),
        Cmd::Demo => run::demo(o),
        Cmd::Agent {
            task,
            agent,
            model,
            trust_agent_code,
            show_source,
            timeout,
            allow_hosts,
        } => agent::agent(
            agent::AgentRequest {
                task: &task.join(" "),
                state_root: &cli.root,
                requested_backend: *agent,
                model: model.as_deref(),
                trust_agent_code: *trust_agent_code,
                show_source: *show_source,
                timeout: *timeout,
                allow_hosts,
            },
            o,
        ),
        Cmd::Ask {
            question,
            agent,
            model,
            timeout,
        } => agent::ask(&question.join(" "), *agent, model.as_deref(), *timeout, o),
        Cmd::Agents { set_default } => agent::agents(*set_default, o),
        Cmd::Setup { agent: preferred } => agent::setup(*preferred, o),
    }
}

fn doctor(o: &Out) -> u8 {
    let h = host::Host::probe();

    if o.is_json() {
        for c in &h.caps {
            o.event(
                "capability",
                serde_json::json!({"name": c.name, "ok": c.ok, "detail": c.detail, "fix": c.fix}),
                "",
            );
        }
        o.event(
            "summary",
            serde_json::json!({"can_seal_cells": h.can_seal()}),
            "",
        );
    } else {
        o.say(bold("host"));
        for c in &h.caps {
            let mark = if c.ok { green("✔") } else { red("✘") };
            o.say(format!("  {mark} {:<14} {}", c.name, c.detail));
            if !c.ok {
                o.say(format!("    {}", dim(&format!("→ {}", c.fix))));
            }
        }
        o.say("");
        if h.can_seal() {
            o.say(format!(
                "{} this machine can seal real, hardware-isolated cells.",
                green("✔")
            ));
            o.say(dim(
                "  try: celln spec init > agent.toml && celln run agent.toml",
            ));
        } else {
            o.say(format!(
                "{} no hardware isolation here — `celln demo` and `celln spec check` still work.",
                red("✘")
            ));
        }
    }

    if h.can_seal() {
        exit::OK
    } else {
        exit::HOST_INCAPABLE
    }
}
