//! Content-addressed tool store and tiered resolution.

use celln_manifest::{Author, Entry, Hash, Manifest, Tier};
use celln_store::Store;
use std::collections::VecDeque;
use std::path::{Path, PathBuf};

pub struct Assayer {
    store: Store,
    manifest: Manifest,
    manifest_path: PathBuf,
    rebuild_queue: VecDeque<Hash>,
}

/// Resolved tool and any deferred upgrade.
#[derive(Debug, PartialEq, Eq)]
pub struct Resolved {
    pub hash: Hash,
    pub tier: Tier,
    pub warm: bool,
    pub upgrade_queued: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum AssayError {
    #[error(transparent)]
    Store(#[from] celln_store::StoreError),
    #[error("the build proof is for different bytes than the ones being admitted")]
    ProofMismatch,
}

impl Assayer {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, AssayError> {
        let root = root.as_ref();
        let store = Store::open(root)?;
        let manifest_path = root.join("manifest.json");
        let manifest = if manifest_path.exists() {
            let bytes = std::fs::read(&manifest_path).map_err(celln_store::StoreError::Io)?;
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

    fn persist(&self) -> Result<(), AssayError> {
        let bytes = serde_json::to_vec_pretty(&self.manifest).expect("manifest serializes");
        std::fs::write(&self.manifest_path, bytes).map_err(celln_store::StoreError::Io)?;
        Ok(())
    }

    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// Admit externally built bytes at `Verified`.
    pub fn admit_verified(
        &mut self,
        alias: &str,
        bytes: &[u8],
        interpreter: bool,
    ) -> Result<Hash, AssayError> {
        self.admit_verified_authored(alias, bytes, interpreter, Author::Host)
    }

    /// Admit externally built bytes at `Verified`, preserving who authored
    /// their source. Agent authorship is execution-relevant provenance: it
    /// keeps the artifact out of the tool lane even though the bytes are
    /// hash-pinned and verified.
    pub fn admit_verified_authored(
        &mut self,
        alias: &str,
        bytes: &[u8],
        interpreter: bool,
        author: Author,
    ) -> Result<Hash, AssayError> {
        let hash = self.store.put(bytes)?;
        self.manifest.admit(Entry {
            alias: alias.into(),
            hash: hash.clone(),
            tier: Tier::Verified,
            interpreter,
            author,
            recipe: None,
        });
        self.manifest.sign_standin();
        let _ = self.persist();
        Ok(hash)
    }

    /// Admit a rebuilt artifact after validating its proof.
    pub fn admit_forged_authored(
        &mut self,
        alias: &str,
        bytes: &[u8],
        interpreter: bool,
        author: Author,
        proof: &forge::Proof,
    ) -> Result<Hash, AssayError> {
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

    /// Resolve warm tools directly; queue a rebuild for cold tools.
    pub fn resolve(
        &mut self,
        alias: &str,
        upstream_bytes: &[u8],
        interpreter: bool,
    ) -> Result<Resolved, AssayError> {
        // A warm hit has to be a hit on the content, not on the name. Two
        // images can legitimately claim the same alias - /bin/sh is dash in
        // one and busybox in another - and serving the first by alias would
        // attest bytes that are not the ones about to run, which pilot then
        // refuses in-cell as unattested.
        let want = Hash::of(upstream_bytes);

        // Interpreter-ness is sticky and only ever tightens. It decides whether
        // the laundering ban fires, so a stored entry that predates the caller
        // must not be able to say "not an interpreter" over a caller that says
        // it is: that would run agent-authored input in the tool lane with full
        // authority. Once anything declares a tool an interpreter, it stays one.
        let mut interpreter = interpreter;
        if let Some(entry) = self.manifest.resolve_alias(alias) {
            if entry.hash == want && !self.manifest.is_revoked(&entry.hash) {
                interpreter |= entry.interpreter;
                if entry.interpreter == interpreter {
                    return Ok(Resolved {
                        hash: entry.hash.clone(),
                        tier: entry.tier,
                        warm: true,
                        upgrade_queued: false,
                    });
                }
                // The caller tightened it; re-admit before anything runs.
            }
        }

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
    ///
    /// Nothing in the production `celln run`/`celln agent` path calls this —
    /// `rebuild_queue` is populated by [`Self::resolve`] but is only ever
    /// drained by demo/test code (`celln-pilot`'s `demo`/`demo_kvm`, and the
    /// tests below), and lives on an `Assayer` that is opened fresh and
    /// dropped every CLI invocation, so nothing persists between them either.
    /// There is currently no real background worker: a cold tool served at
    /// `Verified` does not upgrade to `Forged` on its own. Do not surface
    /// `upgrade_queued`/`pending_rebuilds` to a user as a promise that one is
    /// coming unless a real worker actually drains this queue.
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
        assert!(
            e.recipe.is_some(),
            "an earned tier records what it was earned from"
        );
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
    fn an_alias_reused_by_different_bytes_is_not_served_warm() {
        // /bin/sh is dash in one image and busybox in another. Serving the
        // first warm would attest bytes that are not the ones about to run.
        let dir = tempdir().unwrap();
        let mut a = Assayer::open(dir.path()).unwrap();
        a.admit_verified("/bin/sh", b"dash-bytes", true).unwrap();

        let r = a.resolve("/bin/sh", b"busybox-bytes", true).unwrap();
        assert!(!r.warm, "different bytes must not be a warm hit");
        assert_eq!(r.hash, Hash::of(b"busybox-bytes"));

        // The same bytes still are.
        let again = a.resolve("/bin/sh", b"busybox-bytes", true).unwrap();
        assert!(again.warm);
        assert_eq!(again.hash, Hash::of(b"busybox-bytes"));
    }

    #[test]
    fn declaring_a_tool_an_interpreter_beats_a_stored_entry_that_did_not() {
        // The laundering ban turns on this flag. A warm hit used to return the
        // stored entry and discard the caller's declaration, so a spec that
        // correctly marked python an interpreter ran agent-authored input in
        // the *tool* lane, with full authority, because some earlier spec had
        // admitted the same bytes as a plain binary.
        let dir = tempdir().unwrap();
        let mut a = Assayer::open(dir.path()).unwrap();

        let r = a.resolve("/usr/bin/python", b"py", false).unwrap();
        assert!(!r.warm);
        assert!(!a.manifest().get(&r.hash).unwrap().interpreter);

        // Same bytes, now declared an interpreter: it must tighten, not serve
        // the stale entry.
        let r = a.resolve("/usr/bin/python", b"py", true).unwrap();
        assert!(!r.warm, "tightening must re-admit, not hit warm");
        assert!(
            a.manifest().get(&r.hash).unwrap().interpreter,
            "an interpreter declaration has to survive into the manifest"
        );

        // And it is sticky: declaring false afterwards must not loosen it.
        let r = a.resolve("/usr/bin/python", b"py", false).unwrap();
        assert!(r.warm);
        assert!(
            a.manifest().get(&r.hash).unwrap().interpreter,
            "interpreter-ness only ever tightens"
        );
    }

    #[test]
    fn revoked_hash_is_not_served_warm() {
        let dir = tempdir().unwrap();
        let mut assayer = Assayer::open(dir.path()).unwrap();
        let h = assayer
            .admit_verified("/usr/bin/curl", b"curl", false)
            .unwrap();
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
        assayer
            .admit_verified("/usr/bin/python", b"py", true)
            .unwrap();
        assert!(assayer.manifest().verify_standin());
        assayer.resolve("/x", b"xbytes", false).unwrap();
        assert!(assayer.manifest().verify_standin());
    }
}
