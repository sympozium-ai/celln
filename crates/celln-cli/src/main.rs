//! `celln` command-line interface.

mod agent;
mod cells;
mod config;
mod dispatch;
mod dispatcher;
mod host;
mod image;
mod node;
mod out;
mod router;
mod run;

use anyhow::{Context, Result};
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
    #[arg(long, global = true, env = "CELLN_ROOT")]
    root: Option<PathBuf>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Report what this machine can run.
    Doctor,

    /// Report node eligibility or admit a transport-neutral execution request.
    #[command(subcommand)]
    Node(NodeCmd),

    /// Serve authenticated hermetic-agent actions on this KVM-capable node.
    Dispatcher {
        /// Socket address to bind, for example 127.0.0.1:8787.
        #[arg(long, default_value = "127.0.0.1:8787")]
        listen: String,
        /// File containing the bearer token accepted from the control plane.
        #[arg(long)]
        token_file: PathBuf,
        /// This node's identity and capacity, used to admit
        /// `celln.dev/v1alpha1` ExecutionRequests posted to `/v1/executions`.
        #[command(flatten)]
        probe: NodeProbeArgs,
    },

    /// Route actions across dispatcher backends. Picks a healthy node per
    /// request and forwards; tracks action → node for status polling.
    Route {
        /// Socket address to bind, for example 0.0.0.0:8787.
        #[arg(long, default_value = "0.0.0.0:8787")]
        listen: String,

        /// Dispatcher backend URLs, comma-separated.
        /// Example: http://node1:8787,http://node2:8787
        #[arg(long, value_delimiter = ',')]
        backends: Vec<String>,

        /// DNS name of a headless Service whose A records are dispatcher
        /// backends. Combined with --backends. Example:
        /// celln-dispatcher.celln-system.svc.cluster.local.
        #[arg(long)]
        backends_srv: Option<String>,

        /// Routing strategy: round-robin (deterministic, default) or random.
        #[arg(long, default_value = "round-robin")]
        mode: router::RoutingMode,

        /// File containing the bearer token forwarded to dispatcher backends.
        #[arg(long)]
        token_file: Option<PathBuf>,
    },

    /// Work with cell specs.
    #[command(subcommand)]
    Spec(SpecCmd),

    /// Seal a cell from a reviewed, model-free [run] spec.
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

    /// Materialise OCI images into sealed tool filesystems.
    #[command(subcommand)]
    Image(ImageCmd),

    /// Prove the isolation properties on this machine.
    Verify,

    /// Have a provider write a program, then run it sealed in a cell.
    ///
    /// Use an inline prompt, or name a .toml spec that supplies the policy.
    /// Without `--tool`, the provider writes a single-file Rust program;
    /// with one, it writes that tool's program or arguments. For a question
    /// that runs no code, ask the provider directly rather than creating a cell.
    Agent {
        /// A prompt, or one .toml agent spec to run.
        ///
        /// With a spec, use `--prompt` to override `[agent].prompt`:
        /// `celln agent cell.toml --prompt "…"`.
        #[arg(num_args = 0..)]
        input: Vec<String>,

        /// What the provider should make the cell do. When a .toml spec is
        /// supplied this overrides `[agent].prompt`; otherwise it is the
        /// inline prompt. `--task` remains a legacy alias.
        #[arg(long, alias = "task")]
        prompt: Option<String>,

        /// Print the source the model wrote.
        #[arg(long)]
        show_source: bool,

        /// Seconds to wait for the model before giving up.
        ///
        /// The happy path is seconds; this is the ceiling before we stop the
        /// CLI and ask it what went wrong.
        #[arg(long, default_value = "90")]
        timeout: u64,

        /// Which provider writes it. Overrides CELLN_PROVIDER and the saved
        /// default.
        #[arg(
            long = "provider",
            alias = "agent",
            value_enum,
            value_name = "PROVIDER"
        )]
        agent: Option<agent::Backend>,

        /// Override the backend's default model.
        #[arg(long)]
        model: Option<String>,

        /// Exact HTTPS host the cell may fetch through pilot (repeatable).
        /// Without this, the cell remains hermetic.
        #[arg(long = "allow-host")]
        allow_hosts: Vec<String>,

        /// Run the model's program with a catalogue tool instead of forging a
        /// Rust binary, e.g. `--tool python`. The model writes that tool's
        /// language, and the result is agent-authored input, so it runs in the
        /// agent lane.
        #[arg(long)]
        tool: Option<String>,
    },

    /// Find inference providers and manage the saved default.
    ///
    /// These are the model backends celln can ask to write a program. They are
    /// not agents, and not the agent lane: `celln agent` names what runs in a
    /// cell, while a provider is only who writes it.
    #[command(alias = "agents")]
    Providers {
        /// Save the provider `celln agent` uses unless overridden.
        #[arg(long, value_enum, value_name = "PROVIDER")]
        set_default: Option<agent::Backend>,
    },

    /// Discover an agent CLI and materialise the default tool images.
    Setup {
        /// Select this provider instead of auto-discovering one.
        #[arg(
            long = "provider",
            alias = "agent",
            value_enum,
            value_name = "PROVIDER"
        )]
        agent: Option<agent::Backend>,

        /// Only these catalogue images, comma-separated. Default: those the
        /// catalogue marks as defaults.
        #[arg(long)]
        tools: Option<String>,

        /// Skip materialising tool images.
        #[arg(long)]
        no_tools: bool,
    },
}

#[derive(Subcommand)]
enum ImageCmd {
    /// Pull a digest-pinned image and build its sealed filesystem.
    ///
    /// Done ahead of time on purpose: a cell maps bytes that already exist,
    /// so nothing about spawning a cell waits on a registry.
    Pull {
        /// An immutable reference, for example
        /// `python@sha256:229a2c…`. Tags are refused.
        reference: String,
    },
    /// List materialised images.
    List,
    /// Add an image to this host's catalogue.
    ///
    /// Resolves the tag to a digest, materialises it, and works out what it
    /// provides, so a tool becomes available by name without editing anything.
    Add {
        /// An image reference, e.g. `node:22-slim`. A tag is resolved to the
        /// digest it points at right now and pinned.
        reference: String,
        /// Catalogue name. Defaults to the image's own name.
        #[arg(long)]
        name: Option<String>,
        /// Expose a specific executable: `/usr/bin/node=/usr/local/bin/node`.
        /// Repeatable. Without it, binaries named after the image are used.
        #[arg(long = "tool")]
        tools: Vec<String>,
        /// Also materialise it on `celln setup`.
        #[arg(long)]
        default: bool,
    },
    /// Remove a locally added catalogue entry.
    Remove { name: String },
    /// Show the built-in catalogue and what is materialised.
    Catalogue,
    /// Print a runnable spec for a catalogue image. Redirect it into a file.
    Spec {
        /// Catalogue image name, e.g. `python`.
        name: String,
    },
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

#[derive(Subcommand)]
enum NodeCmd {
    /// Report hardware, mote/tool-store readiness, and bounded capacity.
    Probe {
        #[command(flatten)]
        probe: NodeProbeArgs,
    },
    /// Validate and admit one execution request against this node's reported capacity.
    Admit {
        request: PathBuf,
        #[command(flatten)]
        probe: NodeProbeArgs,
    },
    /// Resolve the exact immutable bundle required for a one-shot dispatch.
    Resolve {
        request: PathBuf,
        #[arg(long, env = "CELLN_MOTE_STORE", default_value = "/var/lib/celln/motes")]
        mote_store: PathBuf,
        #[arg(long, env = "CELLN_TOOL_STORE", default_value = "/var/lib/celln/tools")]
        tool_store: PathBuf,
    },
}

#[derive(clap::Args, Clone)]
struct NodeProbeArgs {
    #[arg(long, env = "CELLN_NODE_NAME", default_value = "local")]
    node_name: String,
    #[arg(long, env = "CELLN_MOTE_STORE", default_value = "/var/lib/celln/motes")]
    mote_store: PathBuf,
    #[arg(long, env = "CELLN_TOOL_STORE", default_value = "/var/lib/celln/tools")]
    tool_store: PathBuf,
    #[arg(long, env = "CELLN_MAX_CELLS", default_value = "1")]
    max_cells: u32,
    #[arg(long, env = "CELLN_MEMORY_BYTES", default_value = "268435456")]
    memory_bytes: u64,
    #[arg(long, env = "CELLN_EGRESS_SLOTS", default_value = "0")]
    egress_slots: u32,
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

fn resolve_root(explicit: &Option<PathBuf>) -> PathBuf {
    if let Some(p) = explicit {
        return p.clone();
    }
    std::env::var("HOME")
        .map(|h| PathBuf::from(h).join(".celln"))
        .unwrap_or_else(|_| PathBuf::from(".celln"))
}

fn dispatch(cli: &Cli, o: &Out) -> Result<u8> {
    let root = resolve_root(&cli.root);
    match &cli.cmd {
        Cmd::Doctor => Ok(doctor(o)),
        Cmd::Dispatcher {
            listen,
            token_file,
            probe,
        } => dispatcher::serve(listen, token_file, root, probe),
        Cmd::Route {
            listen,
            backends,
            backends_srv,
            mode,
            token_file,
        } => router::serve(
            listen,
            backends.to_vec(),
            backends_srv.as_deref(),
            *mode,
            token_file.as_deref(),
        ),
        Cmd::Node(NodeCmd::Probe { probe }) => node::probe(probe, &root),
        Cmd::Node(NodeCmd::Admit { request, probe }) => node::admit_file(request, probe, &root),
        Cmd::Node(NodeCmd::Resolve {
            request,
            mote_store,
            tool_store,
        }) => node::resolve_file(request, mote_store, tool_store),
        Cmd::Spec(SpecCmd::Init) => {
            // Straight to stdout, unstyled, so `celln spec init > agent.toml`
            // produces a file and not a screenshot of one.
            print!("{}", celln_spec::TEMPLATE);
            Ok(exit::OK)
        }
        Cmd::Spec(SpecCmd::Check { spec }) => run::check(spec, o),
        Cmd::Run { spec, dry_run } => run::run(spec, &root, *dry_run, o),
        Cmd::Ps { all } => run::ps(&root, *all, o),
        Cmd::Image(ImageCmd::Pull { reference }) => image::pull(reference, &root, o),
        Cmd::Image(ImageCmd::List) => image::list(&root, o),
        Cmd::Image(ImageCmd::Add {
            reference,
            name,
            tools,
            default,
        }) => image::add(reference, name.as_deref(), tools, *default, &root, o),
        Cmd::Image(ImageCmd::Remove { name }) => image::remove(name, &root, o),
        Cmd::Image(ImageCmd::Catalogue) => image::catalogue_list(&root, o),
        Cmd::Image(ImageCmd::Spec { name }) => image::scaffold(name, &root, o),
        Cmd::Verify => run::verify(o),
        Cmd::Agent {
            input,
            prompt,
            agent,
            model,
            show_source,
            timeout,
            allow_hosts,
            tool,
        } => {
            let spec =
                (input.len() == 1 && input[0].ends_with(".toml")).then(|| PathBuf::from(&input[0]));
            if let Some(spec) = spec {
                if tool.is_some()
                    || !allow_hosts.is_empty()
                    || *show_source
                    || agent.is_some()
                    || model.is_some()
                {
                    anyhow::bail!(
                        "a spec already declares its tools and policy; use only `celln agent SPEC [--prompt …]`"
                    );
                }
                return run::agent(&spec, &root, prompt.as_deref(), o);
            }
            if prompt.is_some() && !input.is_empty() {
                anyhow::bail!("pass the prompt either positionally or with --prompt, not both");
            }
            let inline_prompt = (!input.is_empty()).then(|| input.join(" "));
            let prompt = prompt
                .as_deref()
                .or(inline_prompt.as_deref())
                .context("an agent needs a prompt, or a .toml spec")?;
            if let Some(tool) = tool {
                agent::with_tool(prompt, tool, allow_hosts, &root, o)
            } else {
                agent::agent(
                    agent::AgentRequest {
                        task: prompt,
                        state_root: &root,
                        requested_backend: *agent,
                        model: model.as_deref(),
                        show_source: *show_source,
                        timeout: *timeout,
                        allow_hosts,
                    },
                    o,
                )
            }
        }
        Cmd::Providers { set_default } => agent::providers(*set_default, o),
        Cmd::Setup {
            agent: preferred,
            tools,
            no_tools,
        } => agent::setup(*preferred, &root, tools.as_deref(), *no_tools, o),
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
            // Sealing a cell and running something in it are different claims.
            // Suggesting `celln run` without pilot sends people at a command
            // that boots a cell and executes nothing.
            if h.get("guest-pilot") {
                o.say(dim(
                    "  try: celln spec init > agent.toml && celln run agent.toml",
                ));
            } else {
                o.say(format!(
                    "{} but nothing can run inside one until pilot is available — see guest-pilot above.",
                    red("✘")
                ));
            }
        } else {
            o.say(format!(
                "{} no hardware isolation here — `celln spec check` still works.",
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

#[cfg(test)]
mod cli_tests {
    use super::*;

    #[test]
    fn an_agent_spec_accepts_prompt_and_legacy_task() {
        for flag in ["--prompt", "--task"] {
            let cli = Cli::try_parse_from(["celln", "agent", "cell.toml", flag, "fizz buzz"])
                .expect("agent spec parses");
            match cli.cmd {
                Cmd::Agent { input, prompt, .. } => {
                    assert_eq!(input, ["cell.toml"]);
                    assert_eq!(prompt.as_deref(), Some("fizz buzz"));
                }
                _ => panic!("expected agent command"),
            }
        }
    }

    #[test]
    fn pruned_commands_are_not_parsed() {
        for command in ["demo", "tools"] {
            assert!(Cli::try_parse_from(["celln", command]).is_err());
        }
    }
}
