//! Reproducible local Rust builds for the `Forged` tier.

use nous_manifest::Hash;
use std::path::Path;
use std::process::Command;

/// Canonical arguments shared by both independent builds.
pub const RUSTC_ARGS: &[&str] = &[
    // Prevent absolute source paths in panic metadata from changing the binary.
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

/// Inputs needed to rebuild an artifact.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Recipe {
    pub source: Vec<u8>,
    pub toolchain: String,
    pub args: Vec<String>,
}

impl Recipe {
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

/// Result of an independent rebuild comparison.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Proof {
    pub artifact: Hash,
    pub recipe: Hash,
    pub toolchain: String,
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

fn compile_in(dir: &Path, source: &[u8], args: &[String]) -> Result<Vec<u8>, ForgeError> {
    std::fs::create_dir_all(dir)?;
    let src = dir.join("unit.rs");
    let bin = dir.join("unit");
    std::fs::write(&src, source)?;

    // Recipes remain portable; only this build's path is substituted locally.
    let concrete: Vec<String> = args
        .iter()
        .map(|a| a.replace("%BUILD_DIR%", &dir.display().to_string()))
        .collect();
    let out = Command::new("rustc")
        .args(&concrete)
        .arg("-o")
        .arg(&bin)
        .arg(&src)
        .env("CARGO_NET_OFFLINE", "true")
        .output()?;
    if !out.status.success() {
        return Err(ForgeError::Build(
            String::from_utf8_lossy(&out.stderr).trim().into(),
        ));
    }
    Ok(std::fs::read(&bin)?)
}

/// Build twice in independent directories and compare the artifacts.
pub fn build_and_verify(source: &[u8], scratch: &Path) -> Result<(Vec<u8>, Proof), ForgeError> {
    let toolchain = toolchain()?;
    let args: Vec<String> = RUSTC_ARGS.iter().map(|s| s.to_string()).collect();
    let recipe = Recipe {
        source: source.to_vec(),
        toolchain: toolchain.clone(),
        args: args.clone(),
    };

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

/// Rebuild a recipe and compare it with existing bytes.
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
        let (bytes, proof) =
            build_and_verify(b"fn main() { println!(\"a\"); }", &d).expect("builds");
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
