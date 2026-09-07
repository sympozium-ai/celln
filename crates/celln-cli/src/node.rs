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
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeEligibility {
    pub node_name: String,
    pub kvm: bool,
    pub cpu_virtualization: bool,
    pub guest_kernel: bool,
    pub mote_store: bool,
    pub tool_store: bool,
    pub live_cells: u32,
    pub max_cells: u32,
    pub memory_bytes: u64,
    pub egress_slots: u32,
}

impl NodeEligibility {
    pub(crate) fn from_probe(args: &NodeProbeArgs, live_cells: u32) -> Self {
        let host = Host::probe();
        Self {
            node_name: args.node_name.clone(),
            kvm: host.get("kvm"),
            cpu_virtualization: host.get("cpu-virt"),
            guest_kernel: guest_kernel_ready(),
            mote_store: has_entries(&args.mote_store),
            tool_store: has_entries(&args.tool_store),
            live_cells,
            max_cells: args.max_cells,
            // A standalone probe cannot recover declarations from legacy
            // live records. The dispatcher starts at zero and applies its
            // authoritative in-process reservations below this layer.
            memory_bytes: if live_cells == 0 {
                args.memory_bytes
            } else {
                0
            },
            egress_slots: if live_cells == 0 {
                args.egress_slots
            } else {
                0
            },
        }
    }

    pub(crate) fn eligible(&self) -> bool {
        self.kvm
            && self.cpu_virtualization
            && self.guest_kernel
            && self.mote_store
            && self.tool_store
            && self.live_cells < self.max_cells
            && self.memory_bytes > 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RefusalCode {
    InvalidRequest,
    Unsupported,
    NoEligibleNode,
    AtCapacity,
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

pub fn probe(args: &NodeProbeArgs, root: &Path) -> Result<u8> {
    print_json(&NodeEligibility::from_probe(
        args,
        crate::cells::live_count(root),
    ))
}

pub fn admit_file(path: &Path, args: &NodeProbeArgs, root: &Path) -> Result<u8> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading execution request {}", path.display()))?;
    let request: ExecutionRequest = serde_json::from_str(&text)
        .with_context(|| format!("parsing execution request {}", path.display()))?;
    let node = NodeEligibility::from_probe(args, crate::cells::live_count(root));
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
    if crate::dispatch::check_supported_authority(request).is_err()
        || request.execution.require_hardware_isolation && (!node.kvm || !node.cpu_virtualization)
    {
        return Admission::Refused {
            request_id: request.id.clone(),
            node: node.clone(),
            reason: RefusalCode::Unsupported,
            problems: Vec::new(),
        };
    }
    if node.live_cells >= node.max_cells
        || request.capabilities.memory_bytes > node.memory_bytes
        || (!request.capabilities.egress.is_empty() && node.egress_slots == 0)
    {
        return Admission::Refused {
            request_id: request.id.clone(),
            node: node.clone(),
            reason: RefusalCode::AtCapacity,
            problems: Vec::new(),
        };
    }
    if !node.eligible() {
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
    // Readiness is access to the configured store, not a claim that every
    // requested identity is present or trusted. Empty stores are valid for
    // forge requests; per-object integrity is checked during resolution.
    path.is_dir() && std::fs::read_dir(path).is_ok()
}

fn guest_kernel_ready() -> bool {
    #[cfg(target_os = "linux")]
    {
        warden::vmm::boot::BootConfig::host_kernel().is_some_and(|path| {
            warden::vmm::boot::BootConfig::modules_dir_for(&path).is_some()
                && warden::vmm::boot::kernel_is_loadable(&path)
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
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
    fn bounded_workspace_modes_are_admitted_on_an_eligible_node() {
        let mut request: ExecutionRequest =
            serde_json::from_str(include_str!("../../../examples/execution/forge-task.json"))
                .unwrap();
        let node = NodeEligibility {
            node_name: "test".into(),
            kvm: true,
            cpu_virtualization: true,
            guest_kernel: true,
            mote_store: true,
            tool_store: true,
            live_cells: 0,
            max_cells: 1,
            memory_bytes: 268435456,
            egress_slots: 0,
        };
        assert!(matches!(admit(&request, &node), Admission::Accepted { .. }));
        request.capabilities.workspace = celln_spec::WorkspaceAccess::ReadOnly;
        assert!(matches!(admit(&request, &node), Admission::Accepted { .. }));
        request.capabilities.workspace = celln_spec::WorkspaceAccess::ReadWrite;
        assert!(matches!(admit(&request, &node), Admission::Accepted { .. }));
    }

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
            live_cells: 0,
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
            live_cells: 0,
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

    #[test]
    fn admission_refuses_a_node_at_its_cell_limit() {
        let request: ExecutionRequest = serde_json::from_str(
            r#"{
                "apiVersion": "celln.dev/v1alpha1",
                "id": "run-at-capacity",
                "workload": { "id": "review", "caller": "sympozium:default/run-at-capacity" },
                "mote": { "hash": "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
                "tools": [],
                "capabilities": { "workspace": "none", "timeoutMs": 1000, "memoryBytes": 1, "outputBytes": 1 },
                "execution": { "lane": "agent", "requireHardwareIsolation": true }
            }"#,
        )
        .expect("request parses");
        let node = NodeEligibility {
            node_name: "full-node".into(),
            kvm: true,
            cpu_virtualization: true,
            guest_kernel: true,
            mote_store: true,
            tool_store: true,
            live_cells: 2,
            max_cells: 2,
            memory_bytes: 1,
            egress_slots: 0,
        };

        assert!(matches!(
            admit(&request, &node),
            Admission::Refused {
                reason: RefusalCode::AtCapacity,
                ..
            }
        ));
    }
}
