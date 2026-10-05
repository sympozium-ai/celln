//! Versioned preflight, never proof of execution or authority for a named bundle.
use crate::node::NodeEligibility;
use serde::{Deserialize, Serialize};

pub(crate) const VERSION: &str = "celln.dev/capabilities-v1alpha1";

/// Signed `tools[].limits.https` on the scoped (mediated) path, enforced by
/// the fleet's own broker egress (`dispatch_scoped_https.rs`).
pub(crate) const SCOPED_HTTPS_CONTRACT: &str = "celln.scoped-https/v1";

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DispatcherCapabilities {
    pub api_version: String,
    pub binary_version: String,
    pub preflight_only: bool,
    pub node: NodeEligibility,
    pub request_versions: Vec<String>,
    pub harness_contracts: Vec<String>,
    pub persistent_sessions: bool,
    pub artifact_readiness: String,
    /// Additive negotiation; absence on older binaries means unsupported.
    #[serde(default)]
    pub scoped_artifact_contracts: Vec<String>,
    /// Additive negotiation for signed web tool limits on the scoped path.
    #[serde(default)]
    pub scoped_https_contracts: Vec<String>,
}

impl DispatcherCapabilities {
    pub fn new(node: NodeEligibility) -> Self {
        Self {
            api_version: VERSION.into(),
            binary_version: env!("CARGO_PKG_VERSION").into(),
            preflight_only: true,
            node,
            request_versions: vec![
                "celln.dev/v1alpha1".into(),
                "celln.dev/v1alpha2".into(),
                "celln.dev/v1alpha3".into(),
            ],
            harness_contracts: vec![
                "celln.reference-functions/v1".into(),
                "celln.json-tools/v1".into(),
            ],
            persistent_sessions: false,
            artifact_readiness: "not_checked".into(),
            // v2 adds list/append/search/delete and one-shot runs; v1 (exact
            // read/write, enduring only) keeps its behaviour unchanged.
            scoped_artifact_contracts: vec![
                "celln.scoped-artifacts/v1".into(),
                "celln.scoped-artifacts/v2".into(),
            ],
            scoped_https_contracts: vec![SCOPED_HTTPS_CONTRACT.into()],
        }
    }

    pub fn compatible(&self) -> bool {
        self.api_version == VERSION
            && self.preflight_only
            && self
                .request_versions
                .iter()
                .any(|v| v == "celln.dev/v1alpha1")
            && self.artifact_readiness == "not_checked"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scoped_artifacts_are_additive_preflight_not_installed_authority() {
        let node = NodeEligibility {
            node_name: "fixture".into(),
            kvm: false,
            cpu_virtualization: false,
            guest_kernel: false,
            mote_store: false,
            tool_store: false,
            live_cells: 0,
            max_cells: 0,
            memory_bytes: 0,
            egress_slots: 0,
        };
        let report = DispatcherCapabilities::new(node);
        let mut value = serde_json::to_value(&report).unwrap();
        assert_eq!(
            value["scopedArtifactContracts"],
            serde_json::json!(["celln.scoped-artifacts/v1", "celln.scoped-artifacts/v2"])
        );
        assert_eq!(
            value["scopedHttpsContracts"],
            serde_json::json!(["celln.scoped-https/v1"])
        );
        assert!(report.preflight_only);
        assert!(!report.node.eligible());
        value
            .as_object_mut()
            .unwrap()
            .remove("scopedArtifactContracts");
        value
            .as_object_mut()
            .unwrap()
            .remove("scopedHttpsContracts");
        let legacy: DispatcherCapabilities = serde_json::from_value(value).unwrap();
        assert!(legacy.scoped_artifact_contracts.is_empty());
        assert!(legacy.scoped_https_contracts.is_empty());
        assert!(legacy.compatible());
    }
}
