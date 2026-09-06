//! Offline publisher tooling. Private keys never enter a dispatcher request.
use anyhow::{Context, Result};
use celln_manifest::closure::{Closure, SignedClosure};
use std::{collections::BTreeSet, io::Read, path::Path};

pub fn sign(descriptor: &Path, key: &Path) -> Result<u8> {
    let closure: Closure = serde_json::from_slice(&read(descriptor)?)?;
    let mut seed = zeroize::Zeroizing::new([0u8; 32]);
    let mut source = std::fs::File::open(key).context("opening private seed file")?;
    source
        .read_exact(&mut *seed)
        .context("private seed must contain exactly 32 raw bytes")?;
    let mut extra = [0];
    anyhow::ensure!(
        source.read(&mut extra)? == 0,
        "private seed must contain exactly 32 raw bytes"
    );
    let signed = closure.sign(&seed).map_err(anyhow::Error::msg);
    println!("{}", serde_json::to_string_pretty(&signed?)?);
    Ok(0)
}

fn read(path: &Path) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(262145)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(bytes.len() <= 262144, "closure descriptor too large");
    Ok(bytes)
}

pub fn admit(descriptor: &Path, root: &Path) -> Result<u8> {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Policy {
        api_version: String,
        publishers: BTreeSet<String>,
        revoked: BTreeSet<String>,
    }
    let bytes = read(descriptor)?;
    let signed: SignedClosure = serde_json::from_slice(&bytes)?;
    let policy: Policy = serde_json::from_slice(&read(&root.join("trusted-closures.json"))?)?;
    anyhow::ensure!(
        policy.api_version == "celln.dev/closure-policy-v1",
        "unsupported closure policy"
    );
    signed
        .verify(&policy.publishers)
        .map_err(anyhow::Error::msg)?;
    let identity = celln_manifest::Hash::of(&bytes);
    anyhow::ensure!(
        !policy.revoked.contains(&identity.0)
            && !policy.revoked.contains(&signed.closure.toolfs)
            && signed
                .closure
                .members
                .values()
                .all(|m| !policy.revoked.contains(&m.hash)),
        "closure revoked"
    );
    let hash = celln_store::Store::open(root.join("closures"))?.put(&bytes)?;
    println!(
        "{}",
        serde_json::json!({"closure": hash.0,"publisher": signed.publisher})
    );
    Ok(0)
}
