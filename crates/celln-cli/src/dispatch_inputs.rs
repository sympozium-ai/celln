//! Explicit, bounded immutable data delivery. A content hash is identity,
//! not permission: the host policy must approve it before a store read.

use celln_manifest::Hash;
use celln_spec::{ExecutionRequest, WorkspaceAccess};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const MAX_INPUT_BYTES: u64 = 65536;

#[derive(Debug, Serialize)]
pub struct ResolvedInput {
    pub name: String,
    pub hash: String,
    pub data: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Policy {
    api_version: String,
    hashes: Vec<String>,
}

pub fn validate(request: &ExecutionRequest) -> Result<(), String> {
    if !request.inputs.is_empty() && request.capabilities.workspace == WorkspaceAccess::None {
        return Err("inputs require read-only or read-write workspace authority".into());
    }
    let total = request
        .inputs
        .iter()
        .try_fold(0u64, |n, input| n.checked_add(input.bytes));
    if total.map_or(true, |n| n > MAX_INPUT_BYTES) || request.inputs.len() > 16 {
        return Err("input budget exceeded: at most 16 inputs and 65536 bytes total".into());
    }
    Ok(())
}

pub fn resolve(request: &ExecutionRequest, root: &Path) -> Result<Vec<ResolvedInput>, String> {
    celln_control::check().map_err(|e| e.to_string())?;
    validate(request)?;
    if request.inputs.is_empty() {
        return Ok(Vec::new());
    }
    if !request.problems().is_empty() {
        return Err("invalid input execution request".into());
    }
    let policy: Policy = serde_json::from_slice(
        &std::fs::read(root.join("trusted-inputs.json"))
            .map_err(|_| "input trust policy is unavailable".to_owned())?,
    )
    .map_err(|_| "input trust policy is invalid".to_owned())?;
    if policy.api_version != "celln.dev/v1alpha1"
        || request
            .inputs
            .iter()
            .any(|i| !policy.hashes.contains(&i.hash))
    {
        return Err("input is not authorized by host policy".into());
    }
    let store = celln_store::Store::open(root.join("inputs")).map_err(|e| e.to_string())?;
    request
        .inputs
        .iter()
        .map(|input| {
            celln_control::check().map_err(|e| e.to_string())?;
            let data = store
                .get_bounded(&Hash(input.hash.clone()), input.bytes as usize)
                .map_err(|e| e.to_string())?;
            if data.len() as u64 != input.bytes {
                return Err("input byte count does not match declaration".into());
            }
            Ok(ResolvedInput {
                name: input.name.clone(),
                hash: input.hash.clone(),
                data,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use celln_spec::ExecutionInput;
    use serde_json::json;

    fn request() -> ExecutionRequest {
        let mut request: ExecutionRequest =
            serde_json::from_str(include_str!("../../../examples/execution/forge-task.json"))
                .unwrap();
        request.capabilities.workspace = WorkspaceAccess::ReadOnly;
        request.inputs.push(ExecutionInput {
            name: "data".into(),
            hash: Hash::of(b"data").0,
            media_type: "text/plain".into(),
            bytes: 4,
        });
        request
    }

    fn policy(root: &Path, hashes: &[String]) {
        std::fs::write(
            root.join("trusted-inputs.json"),
            serde_json::to_vec(&json!({
                "apiVersion": "celln.dev/v1alpha1", "hashes": hashes,
            }))
            .unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn identity_is_not_authorization_and_exact_bytes_are_required() {
        let dir = tempfile::tempdir().unwrap();
        let store = celln_store::Store::open(dir.path().join("inputs")).unwrap();
        let hash = store.put(b"data").unwrap();
        let mut req = request();
        assert!(resolve(&req, dir.path())
            .unwrap_err()
            .contains("unavailable"));
        policy(dir.path(), &[]);
        assert!(resolve(&req, dir.path())
            .unwrap_err()
            .contains("not authorized"));
        policy(dir.path(), &[hash.0]);
        let input = resolve(&req, dir.path()).unwrap().remove(0);
        assert_eq!(input.data, b"data");
        assert_eq!(input.name, "data");
        req.inputs[0].bytes = 3;
        assert!(resolve(&req, dir.path()).unwrap_err().contains("exceeds"));
        req.inputs[0].bytes = 5;
        assert!(resolve(&req, dir.path())
            .unwrap_err()
            .contains("byte count"));
        req.inputs[0].bytes = 4;
        // A later policy withdrawal must be observed, including on warm dispatch.
        policy(dir.path(), &[]);
        assert!(resolve(&req, dir.path())
            .unwrap_err()
            .contains("not authorized"));
    }

    #[test]
    fn missing_corrupt_and_invalid_inputs_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let mut req = request();
        policy(dir.path(), &[req.inputs[0].hash.clone()]);
        assert!(resolve(&req, dir.path()).unwrap_err().contains("not found"));
        let store = celln_store::Store::open(dir.path().join("inputs")).unwrap();
        store.put(b"data").unwrap();
        let hex = req.inputs[0].hash.strip_prefix("blake3:").unwrap();
        let object = dir.path().join("inputs/objects").join(&hex[..2]).join(hex);
        std::fs::write(object, b"evil").unwrap();
        assert!(resolve(&req, dir.path()).unwrap_err().contains("integrity"));
        for name in [".", "..", "../escape", "/absolute"] {
            req.inputs[0].name = name.into();
            assert!(resolve(&req, dir.path())
                .unwrap_err()
                .contains("invalid input"));
        }
    }

    #[test]
    fn budgets_and_workspace_are_checked_without_opening_a_store() {
        let dir = tempfile::tempdir().unwrap();
        let absent = dir.path().join("absent");
        let mut req = request();
        req.capabilities.workspace = WorkspaceAccess::None;
        assert!(resolve(&req, &absent)
            .unwrap_err()
            .contains("inputs require"));
        req.capabilities.workspace = WorkspaceAccess::ReadWrite;
        req.inputs[0].bytes = MAX_INPUT_BYTES + 1;
        assert!(resolve(&req, &absent).unwrap_err().contains("input budget"));
        req.inputs = vec![req.inputs[0].clone(); 17];
        for input in &mut req.inputs {
            input.bytes = 0;
        }
        assert!(resolve(&req, &absent).unwrap_err().contains("input budget"));
        req.inputs.clear();
        assert!(resolve(&req, &absent).unwrap().is_empty());
        assert!(!absent.exists());
    }
}
