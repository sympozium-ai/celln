use super::*;
use std::collections::BTreeSet;

/// Experimental text/two-integer-function adapter. Runtime identity is the
/// enclosing request's single executable and signed precomposed closure.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HarnessBinding {
    pub contract_version: String,
    pub model_grant: ImmutableRef,
    pub model: String,
    pub task: String,
    pub borrowed_tools: Vec<BorrowedTool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BorrowedTool {
    pub name: String,
    pub path: String,
    pub hash: String,
    pub description: String,
}

fn path(value: &str) -> bool {
    value.starts_with('/')
        && value.len() <= 256
        && value[1..].split('/').all(|p| {
            !p.is_empty()
                && p != "."
                && p != ".."
                && p.bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"-_.+".contains(&c))
        })
}

pub(super) fn valid(request: &ExecutionRequest) -> bool {
    let Some(h) = &request.harness else {
        return request.api_version != "celln.dev/v1alpha2";
    };
    let mut names = BTreeSet::new();
    let mut paths = BTreeSet::new();
    request.api_version == "celln.dev/v1alpha2"
        && h.contract_version == "celln.reference-functions/v1"
        && is_immutable_hash(&h.model_grant.hash)
        && !h.model.is_empty()
        && h.model.len() <= 128
        && !h.task.trim().is_empty()
        && h.task.len() <= 2048
        && !h.task.contains('\0')
        && request.mote.is_some()
        && request.forge.is_none()
        && request.inputs.is_empty()
        && request.tools.len() == 1
        && request.tools[0].closure.is_some()
        && request
            .invocation
            .as_ref()
            .is_some_and(|i| i.args.is_empty())
        && request.execution.lane == RequestedLane::Agent
        && request.execution.require_hardware_isolation
        && request.capabilities.workspace == WorkspaceAccess::None
        && request.capabilities.egress.len() == 1
        && h.borrowed_tools.len() == 2
        && h.borrowed_tools.iter().all(|t| {
            !t.name.is_empty()
                && t.name.len() <= 64
                && t.name
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
                && names.insert(&t.name)
                && paths.insert(&t.path)
                && path(&t.path)
                && is_immutable_hash(&t.hash)
                && !t.description.is_empty()
                && t.description.len() <= 512
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn wire() -> serde_json::Value {
        let hash = format!("blake3:{}", "a".repeat(64));
        json!({"apiVersion":"celln.dev/v1alpha2","id":"r","workload":{"id":"r","caller":"controller:test"},
            "mote":{"hash":hash},"tools":[{"alias":"/harness","hash":hash,"closure":{"hash":hash}}],"invocation":{"alias":"/harness"},
            "capabilities":{"workspace":"none","egress":["https://api.deepseek.com"],"timeoutMs":180000,"memoryBytes":268435456,"outputBytes":65536},"execution":{"lane":"agent","requireHardwareIsolation":true},
            "harness":{"contractVersion":"celln.reference-functions/v1","modelGrant":{"hash":hash},"model":"deepseek-chat","task":"use both tools","borrowedTools":[{"name":"add","path":"/add","hash":hash,"description":"add"},{"name":"multiply","path":"/multiply","hash":hash,"description":"multiply"}]}})
    }
    #[test]
    fn versioned_binding_is_strict_and_bounded() {
        let value = wire();
        assert!(serde_json::from_value::<ExecutionRequest>(value.clone())
            .unwrap()
            .problems()
            .is_empty());
        for (pointer, replacement) in [
            ("/apiVersion", json!("celln.dev/v1alpha1")),
            ("/harness/contractVersion", json!("arbitrary-oci")),
            ("/harness/modelGrant/hash", json!("../secret")),
            ("/harness/task", json!("x".repeat(2049))),
            ("/harness/borrowedTools/1/path", json!("/add")),
            ("/harness/borrowedTools/1/name", json!("add")),
            ("/harness/borrowedTools/1/path", json!("/../secret")),
            ("/capabilities/workspace", json!("read-write")),
            ("/capabilities/egress", json!([])),
            ("/execution/lane", json!("tool")),
        ] {
            let mut bad = value.clone();
            *bad.pointer_mut(pointer).unwrap() = replacement;
            assert!(
                !serde_json::from_value::<ExecutionRequest>(bad)
                    .unwrap()
                    .problems()
                    .is_empty(),
                "{pointer}"
            );
        }
        let mut missing = value.clone();
        missing.as_object_mut().unwrap().remove("harness");
        assert!(!serde_json::from_value::<ExecutionRequest>(missing)
            .unwrap()
            .problems()
            .is_empty());
        let mut injected = value;
        injected["harness"]["credentialFile"] = json!("/etc/secret");
        assert!(serde_json::from_value::<ExecutionRequest>(injected).is_err());
    }
}
