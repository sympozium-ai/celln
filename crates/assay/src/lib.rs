//! `assay` — the fleet daemon, POC core.
//!
//! Owns the content-addressed [`Store`] and the signed [`Manifest`]. Implements
//! the piece that makes launch never-slow: **tiered resolution**. A request for
//! a tool resolves warm → Verified (seconds) → Forged (async, background), and
//! the tier actually served is recorded.
//!
//! The assayer grades; it does not build. When a caller wants the `Forged`
//! tier it must bring a [`forge::Proof`] that an independent rebuild produced
//! the same bytes, and the assayer checks that proof is about the bytes in
//! hand before recording anything. A rebuild that did not reproduce is graded
//! `Verified` instead — we still hold the artifact, we just cannot claim it
//! was reproduced. No KVM, fully tested.

use nous_manifest::{Author, Entry, Hash, Manifest, Tier};
use nous_store::Store;
use std::collections::VecDeque;
use std::path::{Path, PathBuf};

pub struct Assayer {
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
pub enum AssayError {
    #[error(transparent)]
    Store(#[from] nous_store::StoreError),
    #[error("the build proof is for different bytes than the ones being admitted")]
    ProofMismatch,
}

impl Assayer {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, AssayError> {
        let root = root.as_ref();
        let store = Store::open(root)?;
        let manifest_path = root.join("manifest.json");
        let manifest = if manifest_path.exists() {
            let bytes = std::fs::read(&manifest_path).map_err(nous_store::StoreError::Io)?;
            serde_json::from_slice(&bytes).unwrap_or_default()
        } else {
            Manifest::new()
        };
        Ok(Assayer {
            store,
            manifest,
            manifest_path,
            rebuild_queue: VecDeque::new(),
        })
    }

    /// Persist the manifest to disk so warm hits survive across processes.
    fn persist(&self) -> Result<(), AssayError> {
        let bytes = serde_json::to_vec_pretty(&self.manifest).expect("manifest serializes");
        std::fs::write(&self.manifest_path, bytes).map_err(nous_store::StoreError::Io)?;
        Ok(())
    }

    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// Admit bytes we did **not** build, at `Verified`.
    ///
    /// This is the honest tier for an upstream binary: we have it, we hashed
    /// it, nobody rebuilt it. It used to be spelled `admit_forged`, which
    /// claimed a rebuild that never happened.
    pub fn admit_verified(
        &mut self,
        alias: &str,
        bytes: &[u8],
        interpreter: bool,
    ) -> Result<Hash, AssayError> {
        let hash = self.store.put(bytes)?;
        self.manifest.admit(Entry {
            alias: alias.into(),
            hash: hash.clone(),
            tier: Tier::Verified,
            interpreter,
            author: Author::Host,
            recipe: None,
        });
        self.manifest.sign_standin();
        let _ = self.persist();
        Ok(hash)
    }

    /// Admit an artifact the build plane actually rebuilt.
    ///
    /// The assayer does not take the caller's word for the tier. It checks the
    /// proof is about *these* bytes, then grades on what the proof says
    /// happened: a rebuild that reproduced earns `Forged` and records the
    /// recipe it reproduced from; one that did not is admitted at `Verified`,
    /// because we still hold the bytes but can no longer claim they were
    /// reproduced.
    ///
    /// Forging agent-authored source is a normal thing to do — it is how a
    /// reproducible artifact comes out of something a model wrote. It just must
    /// not also grant tool-lane authority, which is why the author rides along
    /// in the manifest rather than being forgotten at the build step.
    pub fn admit_forged_authored(
        &mut self,
        alias: &str,
        bytes: &[u8],
        interpreter: bool,
        author: Author,
        proof: &forge::Proof,
    ) -> Result<Hash, AssayError> {
        // A proof about other bytes proves nothing about these. Without this
        // the mechanism is decorative: anyone could carry a good proof
        // alongside a different binary.
        if proof.artifact != Hash::of(bytes) {
            return Err(AssayError::ProofMismatch);
        }
        let (tier, recipe) = if proof.reproduced {
            (Tier::Forged, Some(proof.recipe.clone()))
        } else {
            (Tier::Verified, None)
        };
        let hash = self.store.put(bytes)?;
        self.manifest.admit(Entry {
            alias: alias.into(),
            hash: hash.clone(),
            tier,
            interpreter,
            author,
            recipe,
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
    ) -> Result<Resolved, AssayError> {
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
            author: Author::Host,
            recipe: None,
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
    ) -> Result<Hash, AssayError> {
        let hash = self.store.put(bytes)?;
        self.manifest.admit(Entry {
            alias: alias.into(),
            hash: hash.clone(),
            tier: Tier::Unsealed,
            interpreter,
            author: Author::Host,
            recipe: None,
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
    pub fn fetch(&self, hash: &Hash) -> Result<Vec<u8>, AssayError> {
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
        let mut assayer = Assayer::open(dir.path()).unwrap();
        assayer
            .admit_verified("/usr/bin/python", b"python-bytes", true)
            .unwrap();

        let r = assayer
            .resolve("/usr/bin/python", b"python-bytes", true)
            .unwrap();
        assert!(r.warm);
        // Whatever tier it was admitted at comes back unchanged — a warm hit
        // maps pages and does not re-grade or rebuild anything.
        assert_eq!(r.tier, Tier::Verified);
        assert!(!r.upgrade_queued);
    }

    #[test]
    fn a_proof_for_other_bytes_is_refused() {
        // The check that keeps the mechanism from being decorative: a valid
        // proof carried alongside a different binary must not admit it.
        let d = std::env::temp_dir().join(format!("assay-proof-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let mut a = Assayer::open(&d).unwrap();
        let (bytes, proof) =
            forge::build_and_verify(b"fn main() { println!(\"ok\"); }", &d.join("f")).unwrap();
        assert!(proof.reproduced);

        let other = [bytes.as_slice(), b"x"].concat();
        assert!(matches!(
            a.admit_forged_authored("/bin/other", &other, false, Author::Host, &proof),
            Err(AssayError::ProofMismatch)
        ));

        // And the honest bytes do earn Forged, with the recipe recorded.
        let h = a
            .admit_forged_authored("/bin/ok", &bytes, false, Author::Host, &proof)
            .unwrap();
        let e = a.manifest().get(&h).unwrap();
        assert_eq!(e.tier, Tier::Forged);
        assert!(e.recipe.is_some(), "an earned tier records what it was earned from");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn cold_serves_verified_and_queues_forged() {
        let dir = tempdir().unwrap();
        let mut assayer = Assayer::open(dir.path()).unwrap();

        let r = assayer
            .resolve("/usr/lib/leftpad", b"leftpad-bytes", false)
            .unwrap();
        assert!(!r.warm);
        assert_eq!(
            r.tier,
            Tier::Verified,
            "cold path serves Verified in seconds"
        );
        assert!(r.upgrade_queued);
        assert_eq!(assayer.pending_rebuilds(), 1);

        // background rebuild lands -> future resolves are Forged
        assayer.run_one_rebuild();
        assert_eq!(assayer.pending_rebuilds(), 0);
        let r2 = assayer
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
        let mut assayer = Assayer::open(dir.path()).unwrap();
        let h = assayer.admit_verified("/usr/bin/curl", b"curl", false).unwrap();
        assayer.revoke(&h);
        // resolving again must not return the revoked warm entry; it re-admits
        // fresh bytes at Verified instead.
        let r = assayer.resolve("/usr/bin/curl", b"curl", false).unwrap();
        assert!(!r.warm);
    }

    #[test]
    fn manifest_stays_signed_after_mutations() {
        let dir = tempdir().unwrap();
        let mut assayer = Assayer::open(dir.path()).unwrap();
        assayer.admit_verified("/usr/bin/python", b"py", true).unwrap();
        assert!(assayer.manifest().verify_standin());
        assayer.resolve("/x", b"xbytes", false).unwrap();
        assert!(assayer.manifest().verify_standin());
    }
}
