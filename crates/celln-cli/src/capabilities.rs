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
