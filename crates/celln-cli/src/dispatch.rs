//! One-shot, verified Celln dispatch.
//!
//! This is deliberately a native Celln execution path, not a Kubernetes Job
//! wrapper. Kubernetes may transport the request later; this module resolves
//! the declared immutable bundle, creates the cell, and returns a receipt.

use celln_manifest::Hash;
use celln_spec::ExecutionRequest;
use celln_store::Store;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// The serializable substrate descriptor stored under `ExecutionRequest.mote`.
/// Each referenced object is resolved by content hash before the VMM is given
/// any bytes. The in-guest pilot remains responsible for confirming that the
/// selected program hash is executable from the sealed tool filesystem.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MoteBundle {
    #[serde(rename = "apiVersion")]
    api_version: String,
    kernel: String,
    initrd: String,
    toolfs: String,
    invocation: BundleInvocation,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BundleInvocation {
    alias: String,
    tool_hash: String,
}

/// Fully resolved bytes/identities the runtime can hand to its KVM launcher.
/// This boundary makes store reads observable and prevents node admission from
/// being mistaken for artifact resolution.
#[derive(Debug, Serialize)]
pub struct ResolvedBundle {
    pub bundle_hash: String,
    pub program_hash: String,
    pub kernel_hash: String,
    pub initrd_hash: String,
    pub toolfs_hash: String,
}

pub fn resolve_bundle(
    request: &ExecutionRequest,
    mote_root: &Path,
    tool_root: &Path,
) -> Result<ResolvedBundle, String> {
    let invocation = request
        .invocation
        .as_ref()
        .ok_or_else(|| "dispatch requires invocation".to_owned())?;
    let mote_hash = Hash(request.mote.hash.clone());
    let mote_store = Store::open(mote_root).map_err(|error| error.to_string())?;
    let bytes = mote_store
        .get(&mote_hash)
        .map_err(|error| error.to_string())?;
    let bundle: MoteBundle = serde_json::from_slice(&bytes)
        .map_err(|error| format!("mote bundle is not valid JSON: {error}"))?;
    if bundle.api_version != "celln.dev/v1alpha1" {
        return Err("mote bundle has an unsupported apiVersion".to_owned());
    }
    if bundle.invocation.alias != invocation.alias {
        return Err("mote bundle invocation alias does not match request".to_owned());
    }
    let requested_tool = request
        .tools
        .iter()
        .find(|tool| tool.alias == invocation.alias)
        .ok_or_else(|| "request invocation is not a declared tool".to_owned())?;
    if requested_tool.hash != bundle.invocation.tool_hash {
        return Err("mote bundle program hash does not match request".to_owned());
    }
    let tool_store = Store::open(tool_root).map_err(|error| error.to_string())?;
    tool_store
        .get(&Hash(requested_tool.hash.clone()))
        .map_err(|error| format!("declared program cannot be resolved: {error}"))?;
    for hash in [&bundle.kernel, &bundle.initrd, &bundle.toolfs] {
        mote_store
            .get(&Hash(hash.clone()))
            .map_err(|error| format!("mote bundle object cannot be resolved: {error}"))?;
    }

    Ok(ResolvedBundle {
        bundle_hash: request.mote.hash.clone(),
        program_hash: requested_tool.hash.clone(),
        kernel_hash: bundle.kernel,
        initrd_hash: bundle.initrd,
        toolfs_hash: bundle.toolfs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use celln_spec::ExecutionRequest;
    use celln_store::Store;
    use serde_json::json;
    use tempfile::tempdir;

    #[test]
    fn resolved_bundle_binds_the_requested_invocation_to_the_declared_tool() {
        let motes = tempdir().expect("mote store");
        let tools = tempdir().expect("tool store");
        let tool_store = Store::open(tools.path()).expect("open tool store");
        let tool_hash = tool_store.put(b"static-program").expect("store program");
        let mote_store = Store::open(motes.path()).expect("open mote store");
        let kernel_hash = mote_store.put(b"kernel").expect("store kernel");
        let initrd_hash = mote_store.put(b"initrd").expect("store initrd");
        let toolfs_hash = mote_store.put(b"toolfs").expect("store toolfs");
        let bundle = json!({
            "apiVersion": "celln.dev/v1alpha1",
            "kernel": kernel_hash.0,
            "initrd": initrd_hash.0,
            "toolfs": toolfs_hash.0,
            "invocation": { "alias": "/tools/program", "toolHash": tool_hash.0 }
        });
        let mote_hash = mote_store
            .put(&serde_json::to_vec(&bundle).expect("bundle serializes"))
            .expect("store bundle");
        let request: ExecutionRequest = serde_json::from_value(json!({
            "apiVersion": "celln.dev/v1alpha1",
            "id": "one-shot-1",
            "workload": { "id": "one-shot", "caller": "sympozium:default/one-shot-1" },
            "mote": { "hash": mote_hash.0 },
            "tools": [{ "alias": "/tools/program", "hash": tool_hash.0 }],
            "invocation": { "alias": "/tools/program", "args": [] },
            "capabilities": { "workspace": "none", "timeoutMs": 1000, "memoryBytes": 268435456, "outputBytes": 1024 },
            "execution": { "lane": "agent", "requireHardwareIsolation": true }
        }))
        .expect("request parses");

        let resolved =
            resolve_bundle(&request, motes.path(), tools.path()).expect("bundle resolves");
        assert_eq!(resolved.program_hash, tool_hash.0);
        assert_eq!(resolved.bundle_hash, mote_hash.0);
        assert_eq!(resolved.kernel_hash, kernel_hash.0);
        assert_eq!(resolved.initrd_hash, initrd_hash.0);
        assert_eq!(resolved.toolfs_hash, toolfs_hash.0);
    }
}
