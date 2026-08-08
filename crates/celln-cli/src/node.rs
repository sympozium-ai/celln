//! Kubernetes node-plane admission for the transport-neutral execution contract.
//!
//! This is intentionally an admission seam, not a CRI runtime. Kubernetes places
//! a request on a node based on the report below; `warden` remains the process
//! that turns a mote into one sealed cell.

use crate::exit;
use crate::host::Host;
use crate::NodeProbeArgs;
use anyhow::{Context, Result};
use celln_spec::{ExecutionProblem, ExecutionRequest};
use serde::Serialize;
use std::path::Path;

#[derive(Debug, Clone, Serialize)]
pub struct NodeEligibility {
    pub node_name: String,
    pub kvm: bool,
    pub cpu_virtualization: bool,
    pub guest_kernel: bool,
    pub mote_store: bool,
    pub tool_store: bool,
    pub max_cells: u32,
    pub memory_bytes: u64,
    pub egress_slots: u32,
}

impl NodeEligibility {
    pub(crate) fn from_probe(args: &NodeProbeArgs) -> Self {
        let host = Host::probe();
        Self {
            node_name: args.node_name.clone(),
            kvm: host.get("kvm"),
            cpu_virtualization: host.get("cpu-virt"),
            guest_kernel: host.get("guest-kernel"),
            mote_store: has_entries(&args.mote_store),
            tool_store: has_entries(&args.tool_store),
            max_cells: args.max_cells,
            memory_bytes: args.memory_bytes,
            egress_slots: args.egress_slots,
        }
    }

    fn eligible(&self) -> bool {
        self.kvm
            && self.cpu_virtualization
            && self.guest_kernel
            && self.mote_store
            && self.tool_store
            && self.max_cells > 0
            && self.memory_bytes > 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RefusalCode {
    InvalidRequest,
    Unsupported,
    NoEligibleNode,
}

#[derive(Debug, Serialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum Admission {
    Accepted {
        request_id: String,
        node: NodeEligibility,
    },
    Refused {
        request_id: String,
        node: NodeEligibility,
        reason: RefusalCode,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        problems: Vec<ExecutionProblem>,
    },
}

pub fn probe(args: &NodeProbeArgs) -> Result<u8> {
    print_json(&NodeEligibility::from_probe(args))
}

pub fn admit_file(path: &Path, args: &NodeProbeArgs) -> Result<u8> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading execution request {}", path.display()))?;
    let request: ExecutionRequest = serde_json::from_str(&text)
        .with_context(|| format!("parsing execution request {}", path.display()))?;
    let node = NodeEligibility::from_probe(args);
    let result = admit(&request, &node);
    let code = match result {
        Admission::Accepted { .. } => exit::OK,
        Admission::Refused {
            reason: RefusalCode::Unsupported,
            ..
        } => exit::UNSUPPORTED,
        Admission::Refused { .. } => exit::REFUSED,
    };
    print_json(&result)?;
    Ok(code)
}

/// Resolve a dispatch bundle after the caller has performed admission. This is
/// intentionally a separate command: resolution proves that the requested
/// bytes exist and hash correctly, while admission only reports node capacity.
pub fn resolve_file(request_path: &Path, mote_store: &Path, tool_store: &Path) -> Result<u8> {
    let text = std::fs::read_to_string(request_path)
        .with_context(|| format!("reading execution request {}", request_path.display()))?;
    let request: ExecutionRequest = serde_json::from_str(&text)
        .with_context(|| format!("parsing execution request {}", request_path.display()))?;
    let resolved = crate::dispatch::resolve_bundle(&request, mote_store, tool_store)
        .map_err(anyhow::Error::msg)?;
    print_json(&resolved)
}

pub fn admit(request: &ExecutionRequest, node: &NodeEligibility) -> Admission {
    let problems = request.problems();
    if !problems.is_empty() {
        return Admission::Refused {
            request_id: request.id.clone(),
            node: node.clone(),
            reason: RefusalCode::InvalidRequest,
            problems,
        };
    }
    if request.execution.require_hardware_isolation && (!node.kvm || !node.cpu_virtualization) {
        return Admission::Refused {
            request_id: request.id.clone(),
            node: node.clone(),
            reason: RefusalCode::Unsupported,
            problems: Vec::new(),
        };
    }
    if !node.eligible() || request.capabilities.memory_bytes > node.memory_bytes {
        return Admission::Refused {
            request_id: request.id.clone(),
            node: node.clone(),
            reason: RefusalCode::NoEligibleNode,
            problems: Vec::new(),
        };
    }
    Admission::Accepted {
        request_id: request.id.clone(),
        node: node.clone(),
    }
}

fn has_entries(path: &Path) -> bool {
    std::fs::read_dir(path)
        .ok()
        .and_then(|mut entries| entries.next())
        .is_some()
}

fn print_json(value: &impl Serialize) -> Result<u8> {
    println!(
        "{}",
        serde_json::to_string(value).expect("node response serializes")
    );
    Ok(exit::OK)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hardware_requirement_refuses_a_node_without_kvm() {
        let request: ExecutionRequest = serde_json::from_str(
            r#"{
                "apiVersion": "celln.dev/v1alpha1",
                "id": "run-42",
                "workload": { "id": "review", "caller": "sympozium:default/run-42" },
                "mote": { "hash": "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
                "tools": [],
                "capabilities": { "workspace": "none", "timeoutMs": 1000, "memoryBytes": 1, "outputBytes": 1 },
                "execution": { "lane": "agent", "requireHardwareIsolation": true }
            }"#,
        )
        .expect("request parses");
        let node = NodeEligibility {
            node_name: "kind-control-plane".into(),
            kvm: false,
            cpu_virtualization: true,
            guest_kernel: false,
            mote_store: true,
            tool_store: true,
            max_cells: 1,
            memory_bytes: 1,
            egress_slots: 0,
        };

        assert!(matches!(
            admit(&request, &node),
            Admission::Refused {
                reason: RefusalCode::Unsupported,
                ..
            }
        ));
    }

    #[test]
    fn admission_refuses_a_node_without_a_bootable_guest_kernel() {
        let request: ExecutionRequest = serde_json::from_str(
            r#"{
                "apiVersion": "celln.dev/v1alpha1",
                "id": "run-43",
                "workload": { "id": "review", "caller": "sympozium:default/run-43" },
                "mote": { "hash": "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
                "tools": [],
                "capabilities": { "workspace": "none", "timeoutMs": 1000, "memoryBytes": 1, "outputBytes": 1 },
                "execution": { "lane": "agent", "requireHardwareIsolation": true }
            }"#,
        )
        .expect("request parses");
        let node = NodeEligibility {
            node_name: "kind-control-plane".into(),
            kvm: true,
            cpu_virtualization: true,
            guest_kernel: false,
            mote_store: true,
            tool_store: true,
            max_cells: 1,
            memory_bytes: 1,
            egress_slots: 0,
        };

        assert!(matches!(
            admit(&request, &node),
            Admission::Refused {
                reason: RefusalCode::NoEligibleNode,
                ..
            }
        ));
    }
}
