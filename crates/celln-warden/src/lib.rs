//! `warden` — the per-cell VMM.
//!
//! One warden wraps and drives exactly one microVM (one cell): 1 warden : 1
//! microVM : 1 cell. It is the control wrapper for that VM. It holds the sealed
//! page maps and — crucially — enforces the **authority ratchet** host-side, so
//! a compromised cell cannot reopen its own rights.
//!
//! The actual VM boundary is behind the [`Vmm`] trait. The POC ships a
//! [`vmm::MockVmm`] that runs anywhere (no KVM); the real KVM backend is a
//! feature-gated stub, because it needs bare metal.

pub mod egress;
pub mod ratchet;
pub mod vmm;

pub use ratchet::{Phase, Ratchet, Verb};
pub use vmm::{Vmm, VmmError};

use celln_manifest::Hash;

/// A live cell: a warden bound to one VMM instance, tracking its ratchet phase.
pub struct Cell<V: Vmm> {
    id: String,
    vmm: V,
    ratchet: Ratchet,
}

#[derive(Debug, thiserror::Error)]
pub enum CellError {
    #[error(transparent)]
    Vmm(#[from] VmmError),
    #[error("verb {verb:?} denied in phase {phase:?}")]
    VerbDenied { verb: Verb, phase: Phase },
}

impl<V: Vmm> Cell<V> {
    /// Seal a mote into a live cell: fork the VM from a warm snapshot and enter
    /// phase P1 (Materialise).
    pub fn seal(id: impl Into<String>, mut vmm: V, mote_snapshot: &str) -> Result<Self, CellError> {
        vmm.fork_from_snapshot(mote_snapshot)?;
        Ok(Cell {
            id: id.into(),
            vmm,
            ratchet: Ratchet::new(),
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn phase(&self) -> Phase {
        self.ratchet.phase()
    }

    /// Map an attested tool page-set (`bytes` fetched for `hash` from the
    /// store) into the cell. Gated by the ratchet: only permitted while
    /// materialisation rights are open.
    pub fn map_tool(&mut self, hash: &Hash, bytes: &[u8]) -> Result<(), CellError> {
        self.ratchet
            .check(Verb::Materialise)
            .map_err(|phase| CellError::VerbDenied {
                verb: Verb::Materialise,
                phase,
            })?;
        self.vmm.map_pages_ro_exec(hash, bytes)?;
        Ok(())
    }

    /// Revoke a mapped tool from this (possibly running) cell. Never
    /// phase-gated: revocation removes authority, it doesn't grant any.
    pub fn revoke_tool(&mut self, hash: &Hash) -> Result<(), CellError> {
        self.vmm.unmap(hash)?;
        Ok(())
    }

    /// Backend access for the proof harness and diagnostics. Policy still goes
    /// through the gated verbs above — this is how tests and demos observe what
    /// the hardware actually did.
    pub fn vmm(&self) -> &V {
        &self.vmm
    }

    /// Mutable backend access (see [`Cell::vmm`]).
    pub fn vmm_mut(&mut self) -> &mut V {
        &mut self.vmm
    }

    /// Report that the cell just performed its first agent-lane exec. This is the
    /// kernel-observable event that ratchets P1 -> P2 and permanently closes
    /// materialisation for this lineage.
    pub fn on_first_tainted_exec(&mut self) {
        self.ratchet.advance_to_work();
    }

    /// Complete the task: disable exec, enter P3 (Dissolve).
    pub fn dissolve(&mut self) -> Result<(), CellError> {
        self.ratchet.advance_to_dissolve();
        self.vmm.freeze_readonly()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use celln_manifest::Hash;
    use vmm::MockVmm;

    #[test]
    fn seal_maps_then_ratchets_shut() {
        let mut cell = Cell::seal("cell-1", MockVmm::new(), "mote:bare+python").unwrap();
        assert_eq!(cell.phase(), Phase::Materialise);

        // materialisation works in P1
        let py = Hash::of(b"python");
        cell.map_tool(&py, b"python").unwrap();

        // first tainted exec ratchets to P2 and closes materialisation forever
        cell.on_first_tainted_exec();
        assert_eq!(cell.phase(), Phase::Work);
        let np = Hash::of(b"numpy");
        let err = cell.map_tool(&np, b"numpy").unwrap_err();
        assert!(matches!(
            err,
            CellError::VerbDenied {
                verb: Verb::Materialise,
                ..
            }
        ));

        // dissolve
        cell.dissolve().unwrap();
        assert_eq!(cell.phase(), Phase::Dissolve);
    }
}
