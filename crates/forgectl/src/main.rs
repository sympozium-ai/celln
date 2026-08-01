//! `forgectl` CLI — a thin front end over the [`forgectl::Forge`] library so the
//! store and tiered resolution can be driven from shell scripts and the Makefile
//! demo. State lives under `--root` (default `./.nous`).

use anyhow::Result;
use clap::{Parser, Subcommand};
use forgectl::Forge;
use nous_manifest::Hash;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "forgectl", version, about = "Nouscell fleet daemon (POC CLI)")]
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
    /// Pre-forge (Tier 1) a tool from a file: `preforge /usr/bin/python ./python [--interpreter]`.
    Preforge {
        alias: String,
        file: PathBuf,
        #[arg(long)]
        interpreter: bool,
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
    let mut forge = Forge::open(&cli.root)?;

    match cli.cmd {
        Cmd::Init => {
            println!("initialised store at {}", cli.root.display());
        }
        Cmd::Preforge {
            alias,
            file,
            interpreter,
        } => {
            let bytes = std::fs::read(&file)?;
            let h = forge.preforge(&alias, &bytes, interpreter)?;
            println!("forged {alias}\n  {h}\n  tier=forged");
        }
        Cmd::Resolve {
            alias,
            file,
            interpreter,
        } => {
            let bytes = std::fs::read(&file)?;
            let r = forge.resolve(&alias, &bytes, interpreter)?;
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
        Cmd::Rebuild => match forge.run_one_rebuild() {
            Some(h) => println!(
                "rebuilt -> forged: {h}\n  pending={}",
                forge.pending_rebuilds()
            ),
            None => println!("no pending rebuilds"),
        },
        Cmd::Revoke { hash } => {
            forge.revoke(&Hash(hash.clone()));
            println!("revoked {hash} (halts in all running cells)");
        }
        Cmd::Status => {
            let m = forge.manifest();
            println!(
                "manifest: {} entries  signed={}  pending_rebuilds={}",
                m.len(),
                m.verify_standin(),
                forge.pending_rebuilds()
            );
        }
    }
    Ok(())
}
