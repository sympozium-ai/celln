//! `assay` CLI — a thin front end over the [`assay::Assayer`] library so the
//! store and tiered resolution can be driven from shell scripts and the Makefile
//! demo. State lives under `--root` (default `./.celln`).
//!
//! Named for what it does: an assay office determines what a piece of metal
//! actually is and stamps it with a grade. This does the same for bytes — hash
//! them, grade them, record who wrote them — and, importantly, claims no more
//! than that. It does not build anything.

use anyhow::Result;
use assay::Assayer;
use celln_manifest::Hash;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "assay",
    version,
    about = "Grade and admit artifacts into a Celln manifest"
)]
struct Cli {
    /// Store root.
    #[arg(long, default_value = ".celln")]
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
    /// Explain how to earn Forged; retained so old scripts fail honestly.
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
                celln_manifest::Author::Agent
            } else {
                celln_manifest::Author::Host
            };
            let bytes = std::fs::read(&file)?;
            let h = assayer.admit_verified_authored(&alias, &bytes, interpreter, author)?;
            let entry = assayer.manifest().get(&h).expect("just admitted");
            println!(
                "admitted {alias}\n  {h}\n  tier={} author={}",
                entry.tier, entry.author
            );
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
                celln_manifest::Author::Agent
            } else {
                celln_manifest::Author::Host
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
                "COLD (verified)"
            };
            println!(
                "resolved {alias}\n  {}\n  tier={}  {}",
                r.hash, r.tier, kind
            );
        }
        Cmd::Rebuild => anyhow::bail!(
            "no background rebuild queue exists; use `assay forge <alias> <source.rs>` to earn Forged"
        ),
        Cmd::Revoke { hash } => {
            assayer.revoke(&Hash(hash.clone()));
            println!("revoked {hash} (halts in all running cells)");
        }
        Cmd::Status => {
            let m = assayer.manifest();
            println!("manifest: {} entries  signed={}", m.len(), m.verify_standin());
        }
    }
    Ok(())
}
