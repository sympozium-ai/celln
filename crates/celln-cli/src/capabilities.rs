//! Versioned preflight, never proof of execution or authority for a named bundle.
use crate::node::NodeEligibility;
use serde::{Deserialize, Serialize};

pub(crate) const VERSION: &str = "celln.dev/capabilities-v1alpha1";

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
            scoped_artifact_contracts: vec!["celln.scoped-artifacts/v1".into()],
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
            serde_json::json!(["celln.scoped-artifacts/v1"])
        );
        assert!(report.preflight_only);
        assert!(!report.node.eligible());
        value
            .as_object_mut()
            .unwrap()
            .remove("scopedArtifactContracts");
        let legacy: DispatcherCapabilities = serde_json::from_value(value).unwrap();
        assert!(legacy.scoped_artifact_contracts.is_empty());
        assert!(legacy.compatible());
    }
}
