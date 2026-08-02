//! `pilot` — the in-cell supervisor (POC slice).
//!
//! In a real cell this is PID 1 and owns the tool-call ABI, the shell parser,
//! and the toolplane. The POC implements the security-critical decision it makes
//! on every exec:
//!
//!   1. **exec-by-hash** — refuse anything not attested in the manifest;
//!   2. **lane resolution** — apply the laundering ban to pick tool vs data lane;
//!   3. **explain** — emit a structured, machine-readable record for any denial,
//!      because the error surface is an agent steering channel.

use nous_manifest::{ExecDenied, Hash, Input, Lane, Manifest};
use serde::Serialize;

/// The result of asking pilot to run something.
#[derive(Debug, PartialEq, Eq)]
pub enum ExecOutcome {
    /// Permitted, running in the given lane.
    Run { hash: Hash, lane: Lane },
    /// Refused, with a structured explanation.
    Denied(Explain),
}

/// A structured denial record — the `explain` verb's output. Serializes to the
/// JSON an agent reads to correct itself.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Explain {
    pub denied: String,
    pub reason: String,
    pub instead: String,
}

impl Explain {
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("explain serializes")
    }
}

/// Resolve and gate one exec request.
///
/// `target` is the content hash being executed; `input` describes what it is
/// being fed (a file or an inline string, tool- or data-lane), so the laundering
/// ban can apply.
pub fn exec(manifest: &Manifest, target: &Hash, input: Input) -> ExecOutcome {
    match manifest.permit_exec(target) {
        Ok(entry) => {
            let lane = nous_manifest::resolve_exec_lane(entry, input);
            ExecOutcome::Run {
                hash: target.clone(),
                lane,
            }
        }
        Err(ExecDenied::Unattested(h)) => ExecOutcome::Denied(Explain {
            denied: format!("exec {h}"),
            reason: "hash is not attested in the manifest (exec-by-hash)".into(),
            instead: "request the tool via assay so it is forged/verified and attested".into(),
        }),
        Err(ExecDenied::Revoked(h)) => ExecOutcome::Denied(Explain {
            denied: format!("exec {h}"),
            reason: "hash was revoked fleet-wide".into(),
            instead: "use a non-revoked alternative; the revoked tool will not run in any cell"
                .into(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nous_manifest::{Entry, Tier};

    fn manifest_with(alias: &str, body: &[u8], interp: bool) -> (Manifest, Hash) {
        let mut m = Manifest::new();
        let h = Hash::of(body);
        m.admit(Entry {
            alias: alias.into(),
            hash: h.clone(),
            tier: Tier::Forged,
            interpreter: interp,
            author: nous_manifest::Author::Host,
        });
        (m, h)
    }

    #[test]
    fn attested_tool_runs_in_tool_lane() {
        let (m, h) = manifest_with("/usr/bin/ls", b"ls", false);
        match exec(&m, &h, Input::None) {
            ExecOutcome::Run { lane, .. } => assert_eq!(lane, Lane::Tool),
            other => panic!("expected Run, got {other:?}"),
        }
    }

    #[test]
    fn interpreter_on_tainted_input_is_demoted() {
        let (m, h) = manifest_with("/usr/bin/python", b"python", true);
        // python evil.py
        match exec(&m, &h, Input::File(Lane::Data)) {
            ExecOutcome::Run { lane, .. } => assert_eq!(lane, Lane::Data, "demoted"),
            other => panic!("expected Run, got {other:?}"),
        }
        // python -c "<tainted>"
        match exec(&m, &h, Input::ArgString(Lane::Data)) {
            ExecOutcome::Run { lane, .. } => assert_eq!(lane, Lane::Data),
            other => panic!("expected Run, got {other:?}"),
        }
    }

    #[test]
    fn unattested_is_denied_with_explanation() {
        let (m, _) = manifest_with("/usr/bin/ls", b"ls", false);
        let ghost = Hash::of(b"agent-wrote-this");
        match exec(&m, &ghost, Input::None) {
            ExecOutcome::Denied(e) => {
                assert!(e.reason.contains("not attested"));
                assert!(e.to_json().contains("\"instead\""));
            }
            other => panic!("expected Denied, got {other:?}"),
        }
    }

    #[test]
    fn revoked_is_denied() {
        let (mut m, h) = manifest_with("/usr/bin/curl", b"curl", false);
        m.revoke(&h);
        match exec(&m, &h, Input::None) {
            ExecOutcome::Denied(e) => assert!(e.reason.contains("revoked")),
            other => panic!("expected Denied, got {other:?}"),
        }
    }
}
