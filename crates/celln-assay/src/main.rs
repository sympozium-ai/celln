//! `assay` CLI — a thin front end over the [`assay::Assayer`] library so the
//! store and tiered resolution can be driven from shell scripts and the Makefile
//! demo. State lives under `--root` (default `./.nous`).
//!
//! Named for what it does: an assay office determines what a piece of metal
//! actually is and stamps it with a grade. This does the same for bytes — hash
//! them, grade them, record who wrote them — and, importantly, claims no more
//! than that. It does not build anything.

use anyhow::Result;
use assay::Assayer;
use clap::{Parser, Subcommand};
use nous_manifest::Hash;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "assay",
    version,
    about = "Grade and admit artifacts into a Nouscell manifest"
)]
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
    /// Admit bytes we hold but did not build, at Verified.
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
    /// Build from source and admit at Forged — but only if it reproduces.
    ///
    /// The tier is earned here rather than asserted: the source is compiled
    /// twice in different directories and the bytes compared. A build that
    /// does not reproduce is still admitted, at Verified.
    Forge {
        alias: String,
        /// A single Rust source file.
        source: PathBuf,
        #[arg(long)]
        interpreter: bool,
        /// The source was written by an agent, not the host operator.
        #[arg(long)]
        agent_authored: bool,
    },
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
            let _ = author;
            let bytes = std::fs::read(&file)?;
            let h = assayer.admit_verified(&alias, &bytes, interpreter)?;
            println!("admitted {alias}\n  {h}\n  tier=verified author=host");
            // Verified, not Forged, and the difference is the whole point: we
            // have these bytes and hashed them, but nothing rebuilt them. Use
            // `assay forge` when the source is available and the tier should
            // be earned.
            eprintln!("note: not rebuilt — use `assay forge <alias> <source.rs>` to earn Forged");
        }
        Cmd::Forge {
            alias,
            source,
            interpreter,
            agent_authored,
        } => {
            let author = if agent_authored {
                nous_manifest::Author::Agent
            } else {
                nous_manifest::Author::Host
            };
            let src = std::fs::read(&source)?;
            let scratch = std::env::temp_dir().join(format!("assay-forge-{}", std::process::id()));
            let (bytes, proof) = forge::build_and_verify(&src, &scratch)?;
            let _ = std::fs::remove_dir_all(&scratch);
            let h = assayer.admit_forged_authored(&alias, &bytes, interpreter, author, &proof)?;
            let entry = assayer.manifest().get(&h).expect("just admitted");
            println!(
                "forged {alias}\n  {h}\n  tier={} author={} reproduced={}",
                entry.tier, entry.author, proof.reproduced
            );
            match &entry.recipe {
                Some(r) => println!("  recipe {r}\n  {}", proof.toolchain),
                None => {
                    eprintln!("note: the rebuild did not reproduce — graded Verified, not Forged")
                }
            }
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
