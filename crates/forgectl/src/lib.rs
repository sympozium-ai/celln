//! `forgectl` — the fleet daemon, POC core.
//!
//! Owns the content-addressed [`Store`] and the signed [`Manifest`]. Implements
//! the piece that makes launch never-slow: **tiered resolution**. A request for
//! a tool resolves warm → Verified (seconds) → Forged (async, background), and
//! the tier actually served is recorded.
//!
//! The hermetic build farm is out of scope for the POC, so "forging" here is
//! simulated: we mark an artifact as upgradeable and expose `upgrade_to_forged`
//! to model the background rebuild landing. No KVM, fully tested.

use nous_manifest::{Entry, Hash, Manifest, Tier};
use nous_store::Store;
use std::collections::VecDeque;
use std::path::{Path, PathBuf};

pub struct Forge {
    store: Store,
    manifest: Manifest,
    manifest_path: PathBuf,
    /// Simulated background rebuild queue (hashes awaiting Forged upgrade).
    rebuild_queue: VecDeque<Hash>,
}

/// The outcome of resolving a tool request — what the caller would map into a
/// cell right now, and whether a better tier is being produced behind it.
#[derive(Debug, PartialEq, Eq)]
pub struct Resolved {
    pub hash: Hash,
    pub tier: Tier,
    /// True when this was already present (warm) — a page-map, not a build.
    pub warm: bool,
    /// True when a Forged rebuild was queued behind this response.
    pub upgrade_queued: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum ForgeError {
    #[error(transparent)]
    Store(#[from] nous_store::StoreError),
}

impl Forge {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, ForgeError> {
        let root = root.as_ref();
        let store = Store::open(root)?;
        let manifest_path = root.join("manifest.json");
        let manifest = if manifest_path.exists() {
            let bytes = std::fs::read(&manifest_path).map_err(nous_store::StoreError::Io)?;
            serde_json::from_slice(&bytes).unwrap_or_default()
        } else {
            Manifest::new()
        };
        Ok(Forge {
            store,
            manifest,
            manifest_path,
            rebuild_queue: VecDeque::new(),
        })
    }

    /// Persist the manifest to disk so warm hits survive across processes.
    fn persist(&self) -> Result<(), ForgeError> {
        let bytes = serde_json::to_vec_pretty(&self.manifest).expect("manifest serializes");
        std::fs::write(&self.manifest_path, bytes).map_err(nous_store::StoreError::Io)?;
        Ok(())
    }

    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// Pre-forge an artifact (Tier 1). Models shipped inventory + completed
    /// background builds. Stores the bytes and admits a Forged manifest entry.
    pub fn preforge(
        &mut self,
        alias: &str,
        bytes: &[u8],
        interpreter: bool,
    ) -> Result<Hash, ForgeError> {
        let hash = self.store.put(bytes)?;
        self.manifest.admit(Entry {
            alias: alias.into(),
            hash: hash.clone(),
            tier: Tier::Forged,
            interpreter,
        });
        self.manifest.sign_standin();
        let _ = self.persist();
        Ok(hash)
    }

    /// Resolve a tool request by alias.
    ///
    /// * If it's already attested (warm), return it as a page-map — no build.
    /// * Otherwise admit `upstream_bytes` at **Verified** (scan+sign; seconds in
    ///   reality) and queue a background **Forged** rebuild. Serve fast now.
    pub fn resolve(
        &mut self,
        alias: &str,
        upstream_bytes: &[u8],
        interpreter: bool,
    ) -> Result<Resolved, ForgeError> {
        // Warm path: alias already attested and not revoked.
        if let Some(entry) = self.manifest.resolve_alias(alias) {
            if !self.manifest.is_revoked(&entry.hash) {
                return Ok(Resolved {
                    hash: entry.hash.clone(),
                    tier: entry.tier,
                    warm: true,
                    upgrade_queued: false,
                });
            }
        }

        // Cold path: admit at Verified, queue Forged rebuild behind the traffic.
        let hash = self.store.put(upstream_bytes)?;
        self.manifest.admit(Entry {
            alias: alias.into(),
            hash: hash.clone(),
            tier: Tier::Verified,
            interpreter,
        });
        self.manifest.sign_standin();
        let _ = self.persist();
        self.rebuild_queue.push_back(hash.clone());

        Ok(Resolved {
            hash,
            tier: Tier::Verified,
            warm: false,
            upgrade_queued: true,
        })
    }

    /// Run unsealed: no attestation, admitted at Tier 3 so it never carries
    /// tool-lane authority. The never-blocked onboarding path.
    pub fn admit_unsealed(
        &mut self,
        alias: &str,
        bytes: &[u8],
        interpreter: bool,
    ) -> Result<Hash, ForgeError> {
        let hash = self.store.put(bytes)?;
        self.manifest.admit(Entry {
            alias: alias.into(),
            hash: hash.clone(),
            tier: Tier::Unsealed,
            interpreter,
        });
        self.manifest.sign_standin();
        let _ = self.persist();
        Ok(hash)
    }

    /// Simulate one background rebuild completing: pop the queue and upgrade that
    /// artifact's tier to Forged. Future cells silently get the better tier.
    pub fn run_one_rebuild(&mut self) -> Option<Hash> {
        let hash = self.rebuild_queue.pop_front()?;
        if let Some(entry) = self.manifest.get(&hash).cloned() {
            self.manifest.admit(Entry {
                tier: Tier::Forged,
                ..entry
            });
            self.manifest.sign_standin();
            let _ = self.persist();
        }
        Some(hash)
    }

    pub fn pending_rebuilds(&self) -> usize {
        self.rebuild_queue.len()
    }

    /// Revoke a hash fleet-wide.
    pub fn revoke(&mut self, hash: &Hash) {
        self.manifest.revoke(hash);
        self.manifest.sign_standin();
        let _ = self.persist();
    }

    /// Fetch attested bytes for mapping (integrity-checked by the store).
    pub fn fetch(&self, hash: &Hash) -> Result<Vec<u8>, ForgeError> {
        Ok(self.store.get(hash)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn warm_hit_is_a_pagemap_not_a_build() {
        let dir = tempdir().unwrap();
        let mut forge = Forge::open(dir.path()).unwrap();
        forge
            .preforge("/usr/bin/python", b"python-bytes", true)
            .unwrap();

        let r = forge
            .resolve("/usr/bin/python", b"python-bytes", true)
            .unwrap();
        assert!(r.warm);
        assert_eq!(r.tier, Tier::Forged);
        assert!(!r.upgrade_queued);
    }

    #[test]
    fn cold_serves_verified_and_queues_forged() {
        let dir = tempdir().unwrap();
        let mut forge = Forge::open(dir.path()).unwrap();

        let r = forge
            .resolve("/usr/lib/leftpad", b"leftpad-bytes", false)
            .unwrap();
        assert!(!r.warm);
        assert_eq!(
            r.tier,
            Tier::Verified,
            "cold path serves Verified in seconds"
        );
        assert!(r.upgrade_queued);
        assert_eq!(forge.pending_rebuilds(), 1);

        // background rebuild lands -> future resolves are Forged
        forge.run_one_rebuild();
        assert_eq!(forge.pending_rebuilds(), 0);
        let r2 = forge
            .resolve("/usr/lib/leftpad", b"leftpad-bytes", false)
            .unwrap();
        assert!(r2.warm);
        assert_eq!(
            r2.tier,
            Tier::Forged,
            "trust ratcheted up behind the traffic"
        );
    }

    #[test]
    fn revoked_hash_is_not_served_warm() {
        let dir = tempdir().unwrap();
        let mut forge = Forge::open(dir.path()).unwrap();
        let h = forge.preforge("/usr/bin/curl", b"curl", false).unwrap();
        forge.revoke(&h);
        // resolving again must not return the revoked warm entry; it re-admits
        // fresh bytes at Verified instead.
        let r = forge.resolve("/usr/bin/curl", b"curl", false).unwrap();
        assert!(!r.warm);
    }

    #[test]
    fn manifest_stays_signed_after_mutations() {
        let dir = tempdir().unwrap();
        let mut forge = Forge::open(dir.path()).unwrap();
        forge.preforge("/usr/bin/python", b"py", true).unwrap();
        assert!(forge.manifest().verify_standin());
        forge.resolve("/x", b"xbytes", false).unwrap();
        assert!(forge.manifest().verify_standin());
    }
}
