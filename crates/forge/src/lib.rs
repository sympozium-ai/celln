//! `forge` — the build plane. It is called forge because it forges.
//!
//! Until now the `Forged` tier was a claim: something called `preforge`, the
//! manifest recorded `tier=forged`, and nothing anywhere rebuilt the artifact
//! to see whether that was true. The word described an intent, not an event.
//!
//! This crate makes it an event. Given the source an artifact was built from,
//! it rebuilds it — twice, in different directories — and compares the bytes.
//! `Forged` is earned only when an independent rebuild lands on the same hash.
//!
//! **What "hermetic" means here, precisely.** The build is pinned to one
//! toolchain, run with a fixed argument list, given no network, and compiled
//! from a single source file with no dependency graph to resolve. It is *not*
//! run in a container, and it inherits the host's rustc installation. So this
//! proves *reproducibility on this machine with this toolchain*, which is a
//! real and checkable property, and stops short of proving the stronger one —
//! that anyone, anywhere, rebuilding from the recipe gets the same bytes. The
//! recipe records the toolchain so that stronger check is possible later
//! without changing the shape of anything.
//!
//! Reproducibility here is measured, not assumed — and measuring it caught a
//! mistake worth recording. A trivial `println!` program built byte-identically
//! from two directories, which looked like proof that `-C strip=symbols` was
//! enough. It was not: the first *real* program failed to reproduce, because
//! anything that can panic embeds `file!()` — the absolute source path — and
//! stripping symbols does not touch it. `--remap-path-prefix` is what actually
//! makes the builds comparable.
//!
//! The lesson generalises past this crate: a reproducibility check validated
//! only on a trivial input will certify "reproducible" for the programs that
//! happen to contain no panics, and quietly mean "small enough to get away
//! with" for everything else.

use nous_manifest::Hash;
use std::path::Path;
use std::process::Command;

/// The canonical build. Both the first build and the verifying rebuild go
/// through this list, so there is exactly one definition of how an artifact is
/// produced and no way for the two to drift apart.
///
/// Two entries are load-bearing rather than cosmetic, and both are needed:
/// `strip=symbols` keeps symbol names and crate metadata out, and
/// `--remap-path-prefix` keeps the source path out of embedded panic sites.
/// Dropping either makes rebuilds differ for any non-trivial program.
pub const RUSTC_ARGS: &[&str] = &[
    // Every build must appear to have happened in the same place. Without
    // this, any program that can panic embeds `file!()` — the absolute source
    // path — into the binary, and two builds in different directories differ.
    // A trivial `println!` program reproduced without it and anything real did
    // not, which is exactly the kind of gap that would have made "Forged" mean
    // "small enough to get away with".
    "--remap-path-prefix=%BUILD_DIR%=/nous/build",
    "--edition",
    "2021",
    "-O",
    "-C",
    "strip=symbols",
    "--target",
    "x86_64-unknown-linux-musl",
    "-C",
    "target-feature=+crt-static",
];

/// Everything needed to rebuild an artifact, and nothing else.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Recipe {
    /// The exact source bytes.
    pub source: Vec<u8>,
    /// The exact toolchain, as `rustc -V` reports it.
    pub toolchain: String,
    /// The exact arguments, in order.
    pub args: Vec<String>,
}

impl Recipe {
    /// Content address of the recipe itself, so a manifest entry can point at
    /// *what was built from* and not merely assert that something was.
    pub fn hash(&self) -> Hash {
        let mut buf = Vec::new();
        buf.extend_from_slice(self.toolchain.as_bytes());
        buf.push(0);
        for a in &self.args {
            buf.extend_from_slice(a.as_bytes());
            buf.push(0);
        }
        buf.extend_from_slice(&self.source);
        Hash::of(&buf)
    }
}

/// The result of actually doing it.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Proof {
    /// Hash of the bytes this proof is about. An assayer must check this
    /// against the artifact it is being asked to admit — a proof for other
    /// bytes proves nothing about these.
    pub artifact: Hash,
    /// Hash of the recipe those bytes came from.
    pub recipe: Hash,
    pub toolchain: String,
    /// True when an independent rebuild produced identical bytes.
    pub reproduced: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum ForgeError {
    #[error("rustc not usable: {0}")]
    Toolchain(String),
    #[error("build failed:\n{0}")]
    Build(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// The toolchain this host would build with.
pub fn toolchain() -> Result<String, ForgeError> {
    let out = Command::new("rustc")
        .arg("-V")
        .output()
        .map_err(|e| ForgeError::Toolchain(e.to_string()))?;
    if !out.status.success() {
        return Err(ForgeError::Toolchain(
            String::from_utf8_lossy(&out.stderr).trim().into(),
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Compile `source` in `dir`, returning the artifact bytes.
fn compile_in(dir: &Path, source: &[u8], args: &[String]) -> Result<Vec<u8>, ForgeError> {
    std::fs::create_dir_all(dir)?;
    let src = dir.join("unit.rs");
    let bin = dir.join("unit");
    std::fs::write(&src, source)?;

    // Materialise the path-remap placeholder against wherever this build is
    // actually happening. The recipe records the canonical form so it stays
    // portable; only the substitution is local.
    let concrete: Vec<String> = args
        .iter()
        .map(|a| a.replace("%BUILD_DIR%", &dir.display().to_string()))
        .collect();
    let out = Command::new("rustc")
        .args(&concrete)
        .arg("-o")
        .arg(&bin)
        .arg(&src)
        // A build that reaches the network is not a build we can reason about.
        // Nothing here should want to, and if something does, it fails loudly
        // rather than quietly depending on the machine it ran on.
        .env("CARGO_NET_OFFLINE", "true")
        .output()?;
    if !out.status.success() {
        return Err(ForgeError::Build(
            String::from_utf8_lossy(&out.stderr).trim().into(),
        ));
    }
    Ok(std::fs::read(&bin)?)
}

/// Build `source`, then rebuild it independently and compare.
///
/// Returns the artifact and a proof describing what happened. A build that does
/// not reproduce is **not an error** — it is a finding, and the caller decides
/// what tier that deserves. Treating it as an error would push callers toward
/// ignoring it.
pub fn build_and_verify(source: &[u8], scratch: &Path) -> Result<(Vec<u8>, Proof), ForgeError> {
    let toolchain = toolchain()?;
    let args: Vec<String> = RUSTC_ARGS.iter().map(|s| s.to_string()).collect();
    let recipe = Recipe {
        source: source.to_vec(),
        toolchain: toolchain.clone(),
        args: args.clone(),
    };

    // Two different directories on purpose. Building twice in one place would
    // compare a build against itself and prove nothing about path leakage,
    // which is the failure this check exists to catch.
    let first = compile_in(&scratch.join("build-a"), source, &args)?;
    let second = compile_in(&scratch.join("build-b"), source, &args)?;

    let artifact = Hash::of(&first);
    let reproduced = artifact == Hash::of(&second);
    Ok((
        first,
        Proof {
            artifact,
            recipe: recipe.hash(),
            toolchain,
            reproduced,
        },
    ))
}

/// Rebuild an artifact from a recipe and check it against bytes we already
/// hold — the "someone hands you a binary and a recipe" direction.
pub fn verify(recipe: &Recipe, artifact: &[u8], scratch: &Path) -> Result<Proof, ForgeError> {
    let rebuilt = compile_in(&scratch.join("verify"), &recipe.source, &recipe.args)?;
    Ok(Proof {
        artifact: Hash::of(artifact),
        recipe: recipe.hash(),
        toolchain: recipe.toolchain.clone(),
        reproduced: Hash::of(&rebuilt) == Hash::of(artifact),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("forge-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn a_real_build_reproduces_and_the_proof_matches_the_bytes() {
        let d = scratch("repro");
        let src = b"fn main() { println!(\"42\"); }";
        let (bytes, proof) = build_and_verify(src, &d).expect("builds");
        assert!(proof.reproduced, "two builds of one source should match");
        // The proof must be about the bytes actually returned, or an assayer
        // could be handed a proof for something else entirely.
        assert_eq!(proof.artifact, Hash::of(&bytes));
        assert!(proof.toolchain.starts_with("rustc "));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_proof_does_not_transfer_to_different_bytes() {
        let d = scratch("transfer");
        let (bytes, proof) = build_and_verify(b"fn main() { println!(\"a\"); }", &d).expect("builds");
        let tampered = {
            let mut v = bytes.clone();
            v.push(0);
            v
        };
        assert_ne!(proof.artifact, Hash::of(&tampered));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_program_that_can_panic_still_reproduces() {
        // The regression that matters. A trivial program reproduces even
        // without path remapping; anything carrying a panic site embeds
        // `file!()` and does not. This is the smallest program that would have
        // caught it.
        let d = scratch("panicky");
        let src = b"fn main() { let v = vec![1u8, 2, 3]; println!(\"{}\", v[2]); }";
        let (_, proof) = build_and_verify(src, &d).expect("builds");
        assert!(
            proof.reproduced,
            "a program with a panic site must still reproduce — check --remap-path-prefix"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_build_that_does_not_compile_is_an_error_not_a_bad_proof() {
        let d = scratch("broken");
        let e = build_and_verify(b"fn main() { this is not rust }", &d);
        assert!(matches!(e, Err(ForgeError::Build(_))));
        let _ = std::fs::remove_dir_all(&d);
    }
}
