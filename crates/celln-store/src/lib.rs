//! The content-addressed store — the on-disk half of `assay`, where the
//! "distro" actually lives. Blobs are keyed by their BLAKE3 hash, so:
//!
//!   * storing the same bytes twice dedups to one object (the density story), and
//!   * a read is integrity-checked for free: if the bytes don't hash back to the
//!     key, the object is corrupt and the read fails.
//!
//! No KVM here — this is plain filesystem work and is fully tested.

use celln_manifest::Hash;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("object not found: {0}")]
    NotFound(Hash),
    #[error("integrity failure for {expected}: bytes on disk hash to {actual}")]
    Integrity { expected: Hash, actual: Hash },
    #[error("hash {0} is not in the expected blake3:<hex> form")]
    BadHash(String),
}

/// A content-addressed blob store rooted at a directory.
///
/// Layout: `root/objects/<aa>/<full-hex>` — a two-char fan-out so a single
/// directory never holds millions of entries.
pub struct Store {
    objects: PathBuf,
}

impl Store {
    /// Open (creating if needed) a store rooted at `root`.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, StoreError> {
        let objects = root.as_ref().join("objects");
        fs::create_dir_all(&objects)?;
        Ok(Store { objects })
    }

    /// The hex half of a `blake3:<hex>` hash, checked to be exactly 64 lower-
    /// or upper-case hex characters.
    ///
    /// This check is what stands between a hash and a filesystem path
    /// (`path_for` joins it under `objects/`): `PathBuf::join` replaces the
    /// whole path when a joined component is itself absolute, so an
    /// unvalidated `Hash` such as `blake3:/etc/passwd` would otherwise resolve
    /// outside the store root entirely. `Hash` is a public newtype any caller
    /// can construct directly (not only via `Hash::of`), so this validation
    /// has to live here rather than in every caller.
    fn hex_of(hash: &Hash) -> Result<&str, StoreError> {
        let hex = hash
            .0
            .strip_prefix("blake3:")
            .ok_or_else(|| StoreError::BadHash(hash.0.clone()))?;
        if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(StoreError::BadHash(hash.0.clone()));
        }
        Ok(hex)
    }

    fn path_for(&self, hash: &Hash) -> Result<PathBuf, StoreError> {
        let hex = Self::hex_of(hash)?;
        let (fanout, _) = hex.split_at(2.min(hex.len()));
        Ok(self.objects.join(fanout).join(hex))
    }

    /// Store bytes, returning their content hash. Idempotent: storing identical
    /// bytes again is a no-op that returns the same hash (dedup).
    pub fn put(&self, bytes: &[u8]) -> Result<Hash, StoreError> {
        let hash = Hash::of(bytes);
        let path = self.path_for(&hash)?;
        if path.exists() {
            return Ok(hash); // dedup — already present
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        // write-to-temp then rename, so a reader never sees a half-written object
        let tmp = path.with_extension("tmp");
        fs::write(&tmp, bytes)?;
        fs::rename(&tmp, &path)?;
        Ok(hash)
    }

    /// Fetch bytes by hash, verifying integrity on the way out.
    pub fn get(&self, hash: &Hash) -> Result<Vec<u8>, StoreError> {
        let path = self.path_for(hash)?;
        if !path.exists() {
            return Err(StoreError::NotFound(hash.clone()));
        }
        let bytes = fs::read(&path)?;
        let actual = Hash::of(&bytes);
        if &actual != hash {
            return Err(StoreError::Integrity {
                expected: hash.clone(),
                actual,
            });
        }
        Ok(bytes)
    }

    pub fn has(&self, hash: &Hash) -> bool {
        self.path_for(hash).map(|p| p.exists()).unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn put_get_roundtrip() {
        let dir = tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let h = store.put(b"print(1+1)").unwrap();
        assert!(store.has(&h));
        assert_eq!(store.get(&h).unwrap(), b"print(1+1)");
    }

    #[test]
    fn put_dedups() {
        let dir = tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let a = store.put(b"same").unwrap();
        let b = store.put(b"same").unwrap();
        assert_eq!(a, b); // one object serves both — the density mechanism
    }

    #[test]
    fn missing_object_is_not_found() {
        let dir = tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let ghost = Hash::of(b"never stored");
        assert!(matches!(store.get(&ghost), Err(StoreError::NotFound(_))));
    }

    #[test]
    fn corruption_is_caught_on_read() {
        let dir = tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let h = store.put(b"trusted tool bytes").unwrap();
        // tamper with the object on disk
        let path = store.path_for(&h).unwrap();
        fs::write(&path, b"trojaned bytes").unwrap();
        assert!(matches!(store.get(&h), Err(StoreError::Integrity { .. })));
    }

    #[test]
    fn a_hash_with_a_path_traversal_component_is_rejected_before_touching_disk() {
        let dir = tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        // `Hash` is a public newtype: nothing stops a caller from building one
        // outside `Hash::of`, e.g. from untrusted request JSON.
        let escaping = Hash("blake3:/etc/passwd".to_owned());
        assert!(matches!(store.get(&escaping), Err(StoreError::BadHash(_))));
        assert!(!store.has(&escaping));
    }

    #[test]
    fn a_hash_with_a_traversal_segment_is_rejected() {
        let dir = tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let escaping = Hash("blake3:../../../../etc/passwd".to_owned());
        assert!(matches!(store.get(&escaping), Err(StoreError::BadHash(_))));
    }

    #[test]
    fn a_short_or_non_hex_hash_is_rejected() {
        let dir = tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        assert!(matches!(
            store.get(&Hash("blake3:deadbeef".to_owned())),
            Err(StoreError::BadHash(_))
        ));
        let not_hex = Hash(format!("blake3:{}", "z".repeat(64)));
        assert!(matches!(store.get(&not_hex), Err(StoreError::BadHash(_))));
    }
}
