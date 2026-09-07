//! Shared, bounded host-policy verification. No admission-store writes.
use celln_manifest::{closure::SignedClosure, Hash};
use serde::Deserialize;
use std::{collections::BTreeSet, io::Read, path::Path};

pub const MAX_DESCRIPTOR_BYTES: usize = 262144;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Policy {
    api_version: String,
    publishers: BTreeSet<String>,
    revoked: BTreeSet<String>,
}

pub struct Verified {
    pub signed: SignedClosure,
    pub identity: Hash,
    pub policy_hash: Hash,
}

pub fn read_bounded(path: &Path) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(|_| "closure descriptor or policy unavailable")?
        .take((MAX_DESCRIPTOR_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "closure descriptor or policy unreadable")?;
    if bytes.len() > MAX_DESCRIPTOR_BYTES {
        return Err("closure descriptor or policy exceeds 256 KiB".into());
    }
    Ok(bytes)
}

pub fn verify(bytes: &[u8], root: &Path) -> Result<Verified, String> {
    if bytes.len() > MAX_DESCRIPTOR_BYTES {
        return Err("closure descriptor exceeds 256 KiB".into());
    }
    let policy_bytes = read_bounded(&root.join("trusted-closures.json"))?;
    let policy: Policy =
        serde_json::from_slice(&policy_bytes).map_err(|_| "invalid closure trust policy")?;
    if policy.api_version != "celln.dev/closure-policy-v1" {
        return Err("unsupported closure policy".into());
    }
    let signed: SignedClosure =
        serde_json::from_slice(bytes).map_err(|_| "invalid signed closure")?;
    signed.verify(&policy.publishers)?;
    let identity = Hash::of(bytes);
    if policy.revoked.contains(&identity.0)
        || policy.revoked.contains(&signed.closure.toolfs)
        || signed
            .closure
            .members
            .values()
            .any(|m| policy.revoked.contains(&m.hash))
    {
        return Err("closure or dependency revoked".into());
    }
    Ok(Verified {
        signed,
        identity,
        policy_hash: Hash::of(&policy_bytes),
    })
}
