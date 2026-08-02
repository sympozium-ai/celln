//! The VM boundary, behind a trait so the rest of warden is testable without KVM.
//!
//! [`MockVmm`] records operations in memory and runs anywhere. The real KVM
//! backend ([`kvm::KvmVmm`], feature `kvm`) drives a genuine microVM via
//! `/dev/kvm`: CoW fork from a warm template, stage-2 read-only tool sealing,
//! live unmap revocation, dissolve freeze. See `vmm/kvm.rs` for exactly which
//! properties are hardware-enforced in the M1 slice and which are still ahead.

use celln_manifest::Hash;

#[derive(Debug, thiserror::Error)]
pub enum VmmError {
    #[error("vmm operation unsupported in this build/host: {0}")]
    Unsupported(String),
    #[error("vmm backend error: {0}")]
    Backend(String),
}

/// The operations warden needs from a VM backend. Intentionally tiny — the
/// whole point is that the interesting policy lives in warden, not the backend.
pub trait Vmm {
    /// Fork a live VM from a warm mote snapshot (the copy-on-write "seal").
    fn fork_from_snapshot(&mut self, snapshot: &str) -> Result<(), VmmError>;

    /// Map a tool page-set — the attested `bytes` for `hash` — into the guest
    /// as read+execute, never write, enforced below the guest kernel. In the
    /// mock this just records intent.
    fn map_pages_ro_exec(&mut self, hash: &Hash, bytes: &[u8]) -> Result<(), VmmError>;

    /// Unmap a page-set (how revocation reaches a running cell).
    fn unmap(&mut self, hash: &Hash) -> Result<(), VmmError>;

    /// Freeze the cell read-only for artifact harvest (P3 dissolve).
    fn freeze_readonly(&mut self) -> Result<(), VmmError>;
}

/// In-memory VMM for development and tests. Records the sealed set so tests can
/// assert on it.
#[cfg(feature = "mock")]
#[derive(Default)]
pub struct MockVmm {
    pub snapshot: Option<String>,
    pub mapped: Vec<Hash>,
    pub frozen: bool,
}

#[cfg(feature = "mock")]
impl MockVmm {
    pub fn new() -> Self {
        MockVmm::default()
    }

    pub fn is_mapped(&self, hash: &Hash) -> bool {
        self.mapped.contains(hash)
    }
}

#[cfg(feature = "mock")]
impl Vmm for MockVmm {
    fn fork_from_snapshot(&mut self, snapshot: &str) -> Result<(), VmmError> {
        self.snapshot = Some(snapshot.to_string());
        Ok(())
    }

    fn map_pages_ro_exec(&mut self, hash: &Hash, _bytes: &[u8]) -> Result<(), VmmError> {
        if !self.mapped.contains(hash) {
            self.mapped.push(hash.clone());
        }
        Ok(())
    }

    fn unmap(&mut self, hash: &Hash) -> Result<(), VmmError> {
        self.mapped.retain(|h| h != hash);
        Ok(())
    }

    fn freeze_readonly(&mut self) -> Result<(), VmmError> {
        self.frozen = true;
        Ok(())
    }
}

/// Real KVM backend — feature `kvm`, Linux with `/dev/kvm`.
#[cfg(feature = "kvm")]
pub mod kvm;

/// Booting a stock Linux kernel in a microVM — the vehicle for the
/// VFS↔memslot join. Feature `kvm`.
#[cfg(feature = "kvm")]
pub mod boot;

#[cfg(all(test, feature = "mock"))]
mod tests {
    use super::*;

    #[test]
    fn mock_records_lifecycle() {
        let mut v = MockVmm::new();
        v.fork_from_snapshot("mote:bare+python").unwrap();
        assert_eq!(v.snapshot.as_deref(), Some("mote:bare+python"));
        let h = Hash::of(b"python");
        v.map_pages_ro_exec(&h, b"python").unwrap();
        assert!(v.is_mapped(&h));
        v.unmap(&h).unwrap();
        assert!(!v.is_mapped(&h));
        v.freeze_readonly().unwrap();
        assert!(v.frozen);
    }
}
