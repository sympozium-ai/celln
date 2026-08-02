//! `assay` CLI — a thin front end over the [`assay::Assayer`] library so the
//! store and tiered resolution can be driven from shell scripts and the Makefile
//! demo. State lives under `--root` (default `./.nous`).
//!
//! Named for what it does: an assay office determines what a piece of metal
//! actually is and stamps it with a grade. This does the same for bytes — hash
//! them, grade them, record who wrote them — and, importantly, claims no more
//! than that. It does not build anything.

use anyhow::Result;
use clap::{Parser, Subcommand};
use assay::Assayer;
use nous_manifest::Hash;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "assay", version, about = "Grade and admit artifacts into a Nouscell manifest")]
struct Cli {
    /// Store root.
    #[arg(long, default_value = ".nous")]
    root: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Initialise an empty store.
    Init,
    /// Admit a tool at the Forged tier: `admit /usr/bin/python ./python [--interpreter]`.
    Admit {
        alias: String,
        file: PathBuf,
        #[arg(long)]
        interpreter: bool,
        /// The source these bytes were built from was written by an agent.
        /// Forging still applies; tool-lane authority does not.
        #[arg(long)]
        agent_authored: bool,
    },
    /// Resolve a tool by alias, admitting upstream bytes from a file if cold.
    Resolve {
        alias: String,
        file: PathBuf,
        #[arg(long)]
        interpreter: bool,
    },
    /// Run one queued background rebuild (Verified -> Forged).
    Rebuild,
    /// Revoke a hash fleet-wide.
    Revoke { hash: String },
    /// Print manifest status.
    Status,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut assayer = Assayer::open(&cli.root)?;

    match cli.cmd {
        Cmd::Init => {
            println!("initialised store at {}", cli.root.display());
        }
        Cmd::Admit {
            alias,
            file,
            interpreter,
            agent_authored,
        } => {
            let author = if agent_authored {
                nous_manifest::Author::Agent
            } else {
                nous_manifest::Author::Host
            };
            let bytes = std::fs::read(&file)?;
            let h = assayer.admit_forged_authored(&alias, &bytes, interpreter, author)?;
            println!("admitted {alias}\n  {h}\n  tier=forged author={author}");
            // The tier is a claim about how these bytes were produced. In this
            // POC nothing rebuilt them, so say so where the claim is made
            // rather than only in a document nobody has open.
            eprintln!(
                "note: the hermetic build plane is simulated — Forged is asserted here, not earned"
            );
        }
        Cmd::Resolve {
            alias,
            file,
            interpreter,
        } => {
            let bytes = std::fs::read(&file)?;
            let r = assayer.resolve(&alias, &bytes, interpreter)?;
            let kind = if r.warm {
                "WARM (page-map)"
            } else {
                "COLD (verified+queued)"
            };
            println!(
                "resolved {alias}\n  {}\n  tier={}  {}{}",
                r.hash,
                r.tier,
                kind,
                if r.upgrade_queued {
                    "  [forged rebuild queued]"
                } else {
                    ""
                }
            );
        }
        Cmd::Rebuild => match assayer.run_one_rebuild() {
            Some(h) => println!(
                "rebuilt -> forged: {h}\n  pending={}",
                assayer.pending_rebuilds()
            ),
            None => println!("no pending rebuilds"),
        },
        Cmd::Revoke { hash } => {
            assayer.revoke(&Hash(hash.clone()));
            println!("revoked {hash} (halts in all running cells)");
        }
        Cmd::Status => {
            let m = assayer.manifest();
            println!(
                "manifest: {} entries  signed={}  pending_rebuilds={}",
                m.len(),
                m.verify_standin(),
                assayer.pending_rebuilds()
            );
        }
    }
    Ok(())
}
