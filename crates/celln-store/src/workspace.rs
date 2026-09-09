//! Bounded run-owned artifact data, not a host filesystem or execution grant.
//! The owner retains this object across disposable turns. Broker admission must
//! independently authorize each operation and bind its caller to the live child.
//! This in-memory index does not claim process-crash durability.
use celln_manifest::Hash;
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub files: usize,
    pub file_bytes: usize,
    pub total_bytes: usize,
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("invalid workspace limits or artifact name")]
    Invalid,
    #[error("workspace belongs to another parent")]
    WrongParent,
    #[error("workspace revision changed; reconcile original write")]
    StaleRevision,
    #[error("workspace quota exceeded")]
    Quota,
    #[error("artifact not found")]
    NotFound,
}

pub struct Workspace {
    parent: Hash,
    limits: Limits,
    revision: u64,
    bytes: usize,
    artifacts: BTreeMap<String, Vec<u8>>,
}

impl Workspace {
    pub fn new(parent: Hash, limits: Limits) -> Result<Self, Error> {
        if limits.files == 0
            || limits.files > 256
            || limits.file_bytes == 0
            || limits.file_bytes > 65536
            || limits.total_bytes < limits.file_bytes
            || limits.total_bytes > 1048576
        {
            return Err(Error::Invalid);
        }
        Ok(Self {
            parent,
            limits,
            revision: 0,
            bytes: 0,
            artifacts: BTreeMap::new(),
        })
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }

    fn check(&self, parent: &Hash, name: &str) -> Result<(), Error> {
        if *parent != self.parent {
            return Err(Error::WrongParent);
        }
        // Logical UTF-8 names are deliberately narrower than filesystem paths.
        // No normalization aliases, absolute paths, backslashes or dot segments.
        if name.is_empty()
            || name.len() > 256
            || name.split('/').any(|part| {
                part.is_empty()
                    || part == "."
                    || part == ".."
                    || part.len() > 64
                    || !part
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))
            })
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }

    pub fn read(&self, parent: &Hash, name: &str) -> Result<&[u8], Error> {
        self.check(parent, name)?;
        self.artifacts
            .get(name)
            .map(Vec::as_slice)
            .ok_or(Error::NotFound)
    }

    /// Atomic replacement with explicit optimistic concurrency. A lost reply
    /// cannot silently repeat a write against a changed workspace. Reads permit
    /// reconciliation; no operation changes the parent identity or grants exec.
    pub fn write(
        &mut self,
        parent: &Hash,
        expected_revision: u64,
        name: &str,
        data: &[u8],
    ) -> Result<u64, Error> {
        self.check(parent, name)?;
        if expected_revision != self.revision {
            return Err(Error::StaleRevision);
        }
        let old = self.artifacts.get(name);
        let new_bytes = self.bytes - old.map_or(0, Vec::len);
        let new_bytes = new_bytes.checked_add(data.len()).ok_or(Error::Quota)?;
        if data.len() > self.limits.file_bytes
            || new_bytes > self.limits.total_bytes
            || (old.is_none() && self.artifacts.len() >= self.limits.files)
        {
            return Err(Error::Quota);
        }
        let revision = self.revision.checked_add(1).ok_or(Error::Quota)?;
        self.artifacts.insert(name.into(), data.to_vec());
        self.bytes = new_bytes;
        self.revision = revision;
        Ok(revision)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn workspace() -> (Hash, Workspace) {
        let parent = Hash::of(b"parent");
        let workspace = Workspace::new(
            parent.clone(),
            Limits {
                files: 2,
                file_bytes: 8,
                total_bytes: 12,
            },
        )
        .unwrap();
        (parent, workspace)
    }

    #[test]
    fn retains_data_across_borrowers_and_refuses_cross_parent_or_stale_writes() {
        let (parent, mut workspace) = workspace();
        assert_eq!(workspace.write(&parent, 0, "notes/a.txt", b"violet"), Ok(1));
        assert_eq!(
            workspace.read(&parent, "notes/a.txt"),
            Ok(b"violet".as_slice())
        );
        let other = Hash::of(b"other");
        assert_eq!(
            workspace.read(&other, "notes/a.txt"),
            Err(Error::WrongParent)
        );
        assert_eq!(
            workspace.write(&other, 1, "notes/a.txt", b"orange"),
            Err(Error::WrongParent)
        );
        assert_eq!(
            workspace.write(&parent, 0, "notes/a.txt", b"orange"),
            Err(Error::StaleRevision)
        );
        assert_eq!(workspace.revision(), 1);
        assert_eq!(
            workspace.read(&parent, "notes/a.txt"),
            Ok(b"violet".as_slice())
        );
    }

    #[test]
    fn quota_failure_is_atomic_and_replacements_account_for_old_bytes() {
        let (parent, mut workspace) = workspace();
        workspace.write(&parent, 0, "a", b"12345678").unwrap();
        assert_eq!(
            workspace.write(&parent, 1, "b", b"12345"),
            Err(Error::Quota)
        );
        assert_eq!(workspace.revision(), 1);
        workspace.write(&parent, 1, "a", b"12").unwrap();
        workspace.write(&parent, 2, "b", b"12345678").unwrap();
        assert_eq!(workspace.write(&parent, 3, "c", b""), Err(Error::Quota));
        assert_eq!(
            workspace.write(&parent, 3, "a", b"123456789"),
            Err(Error::Quota)
        );
        assert_eq!(workspace.read(&parent, "a"), Ok(b"12".as_slice()));
    }

    #[test]
    fn artifact_names_never_resolve_to_host_paths() {
        let (parent, mut workspace) = workspace();
        for name in [
            "",
            "/etc/passwd",
            "../secret",
            "a/../b",
            "a//b",
            "a/",
            "./a",
            "a\\b",
            "a\0b",
            "%2e%2e/a",
            "a:stream",
        ] {
            assert_eq!(
                workspace.write(&parent, 0, name, b"x"),
                Err(Error::Invalid),
                "{name:?}"
            );
        }
        assert_eq!(workspace.revision(), 0);
        assert!(Workspace::new(
            parent,
            Limits {
                files: 257,
                file_bytes: 1,
                total_bytes: 1
            }
        )
        .is_err());
    }
}
