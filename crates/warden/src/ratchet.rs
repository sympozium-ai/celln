//! The authority ratchet.
//!
//! A cell's rights only ever shrink. Phases advance one way:
//!
//! ```text
//! P1 Materialise ──first tainted exec──▶ P2 Work ──task complete──▶ P3 Dissolve
//! ```
//!
//! The point of enforcing this in warden (host side) rather than pilot (in the
//! cell) is that a fully compromised cell cannot roll the ratchet back. This
//! module is pure logic and fully tested.

/// Lifecycle phase of a cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Phase {
    /// P1: workspace hydrating; tool loans and host verbs open; no untrusted
    /// code has run yet.
    Materialise,
    /// P2: first tainted exec has happened; materialisation permanently revoked
    /// for this lineage.
    Work,
    /// P3: task complete; exec disabled; read-only harvest, then struck.
    Dissolve,
}

/// Host verbs whose availability depends on the phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verb {
    /// Map new attested tools into the cell.
    Materialise,
    /// Reach the host egress proxy / fetch.
    HostFetch,
    /// Execute any code.
    Exec,
    /// Read the workspace (always allowed until struck).
    ReadWorkspace,
}

pub struct Ratchet {
    phase: Phase,
}

impl Ratchet {
    pub fn new() -> Self {
        Ratchet {
            phase: Phase::Materialise,
        }
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }

    /// Advance to Work on the first tainted exec. Monotonic: never goes back,
    /// and never skips backwards from Dissolve.
    pub fn advance_to_work(&mut self) {
        if self.phase == Phase::Materialise {
            self.phase = Phase::Work;
        }
    }

    /// Advance to Dissolve on task completion. Reachable from any earlier phase.
    pub fn advance_to_dissolve(&mut self) {
        self.phase = Phase::Dissolve;
    }

    /// Is `verb` permitted in the current phase? Returns `Ok(())` if permitted,
    /// or `Err(current_phase)` if denied.
    pub fn check(&self, verb: Verb) -> Result<(), Phase> {
        let allowed = match (self.phase, verb) {
            // Materialise: everything open.
            (Phase::Materialise, _) => true,
            // Work: no new tools, but fetch/exec/read still available.
            (Phase::Work, Verb::Materialise) => false,
            (Phase::Work, _) => true,
            // Dissolve: only reads.
            (Phase::Dissolve, Verb::ReadWorkspace) => true,
            (Phase::Dissolve, _) => false,
        };
        if allowed {
            Ok(())
        } else {
            Err(self.phase)
        }
    }
}

impl Default for Ratchet {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn materialise_allows_everything() {
        let r = Ratchet::new();
        for v in [
            Verb::Materialise,
            Verb::HostFetch,
            Verb::Exec,
            Verb::ReadWorkspace,
        ] {
            assert!(r.check(v).is_ok());
        }
    }

    #[test]
    fn work_closes_materialisation_only() {
        let mut r = Ratchet::new();
        r.advance_to_work();
        assert_eq!(r.check(Verb::Materialise), Err(Phase::Work));
        assert!(r.check(Verb::HostFetch).is_ok());
        assert!(r.check(Verb::Exec).is_ok());
    }

    #[test]
    fn dissolve_allows_only_reads() {
        let mut r = Ratchet::new();
        r.advance_to_dissolve();
        assert!(r.check(Verb::ReadWorkspace).is_ok());
        assert_eq!(r.check(Verb::Exec), Err(Phase::Dissolve));
        assert_eq!(r.check(Verb::Materialise), Err(Phase::Dissolve));
    }

    #[test]
    fn ratchet_never_reverses() {
        let mut r = Ratchet::new();
        r.advance_to_work();
        // a compromised cell "asking" to go back to Materialise cannot: there is
        // simply no method to do so, and re-advancing is a no-op.
        r.advance_to_work();
        assert_eq!(r.phase(), Phase::Work);
        r.advance_to_dissolve();
        r.advance_to_work(); // must not resurrect
        assert_eq!(r.phase(), Phase::Dissolve);
    }
}
