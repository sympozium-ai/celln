use super::*;
use std::collections::BTreeSet;

/// Explicitly versioned native adapters. Runtime identity is the
/// enclosing request's single executable and signed precomposed closure.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HarnessBinding {
    pub contract_version: String,
    pub model_grant: ImmutableRef,
    pub model: String,
    pub task: String,
    pub borrowed_tools: Vec<BorrowedTool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub json: Option<JsonHarnessOptions>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BorrowedTool {
    pub name: String,
    pub path: String,
    pub hash: String,
    pub description: String,
    #[serde(rename = "jsonStdio", default, skip_serializing_if = "Option::is_none")]
    pub json_stdio: Option<JsonToolIo>,
}

/// Exact host-granted persona and loop ceilings for the JSON adapter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JsonHarnessOptions {
    pub system: String,
    pub max_turns: usize,
    pub max_calls: usize,
}

/// Schema bytes are content-addressed data, never uploaded executable authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JsonToolIo {
    pub abi: String,
    pub input_schema: String,
    pub output_schema: String,
    pub input_bytes: usize,
    pub output_bytes: usize,
    pub timeout_ms: u64,
}

fn valid_contract(version: &str, h: &HarnessBinding) -> bool {
    match (version, h.contract_version.as_str()) {
        ("celln.dev/v1alpha2", "celln.reference-functions/v1") => {
            h.json.is_none()
                && h.borrowed_tools.len() == 2
                && h.borrowed_tools.iter().all(|t| t.json_stdio.is_none())
        }
        ("celln.dev/v1alpha3", "celln.json-tools/v1") => {
            h.json.as_ref().is_some_and(|j| {
                j.system.len() <= 2048
                    && !j.system.contains('\0')
                    && (1..=6).contains(&j.max_turns)
                    && j.max_calls <= 16
            }) && h.borrowed_tools.len() <= 16
                && h.borrowed_tools.iter().all(|t| {
                    t.path != "/pilot-fetch"
                        && t.json_stdio.as_ref().is_some_and(|j| {
                            j.abi == "celln.json-stdio/v1"
                                && is_immutable_hash(&j.input_schema)
                                && is_immutable_hash(&j.output_schema)
                                && (1..=65536).contains(&j.input_bytes)
                                && (1..=65536).contains(&j.output_bytes)
                                && (1..=30000).contains(&j.timeout_ms)
                        })
                })
        }
        _ => false,
    }
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
        return request.api_version == "celln.dev/v1alpha1";
    };
    let mut names = BTreeSet::new();
    let mut paths = BTreeSet::new();
    valid_contract(&request.api_version, h)
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

    #[test]
    fn json_contract_cannot_be_confused_with_reference_or_argv() {
        let mut value = wire();
        value["apiVersion"] = json!("celln.dev/v1alpha3");
        value["harness"]["contractVersion"] = json!("celln.json-tools/v1");
        value["harness"]["json"] = json!({"system":"Approved persona","maxTurns":3,"maxCalls":2});
        let hash = format!("blake3:{}", "a".repeat(64));
        for tool in value["harness"]["borrowedTools"].as_array_mut().unwrap() {
            tool["jsonStdio"] = json!({"abi":"celln.json-stdio/v1","inputSchema":hash,"outputSchema":hash,
                "inputBytes":1024,"outputBytes":1024,"timeoutMs":1000});
        }
        let valid = |v| {
            serde_json::from_value::<ExecutionRequest>(v)
                .unwrap()
                .problems()
                .is_empty()
        };
        assert!(valid(value.clone()));
        for (pointer, replacement) in [
            ("/apiVersion", json!("celln.dev/v1alpha2")),
            (
                "/harness/contractVersion",
                json!("celln.reference-functions/v1"),
            ),
            ("/harness/json", json!(null)),
            ("/harness/json/maxTurns", json!(0)),
            ("/harness/json/maxTurns", json!(7)),
            ("/harness/json/maxCalls", json!(17)),
            ("/harness/json/system", json!("x".repeat(2049))),
            ("/harness/borrowedTools/0/jsonStdio", json!(null)),
            (
                "/harness/borrowedTools/0/jsonStdio/abi",
                json!("celln.argv/v1"),
            ),
            (
                "/harness/borrowedTools/0/jsonStdio/inputSchema",
                json!("/etc/secret"),
            ),
            (
                "/harness/borrowedTools/0/jsonStdio/outputSchema",
                json!("mutable-tag"),
            ),
            ("/harness/borrowedTools/0/jsonStdio/inputBytes", json!(0)),
            (
                "/harness/borrowedTools/0/jsonStdio/outputBytes",
                json!(65537),
            ),
            ("/harness/borrowedTools/0/jsonStdio/timeoutMs", json!(30001)),
        ] {
            let mut bad = value.clone();
            *bad.pointer_mut(pointer).unwrap() = replacement;
            assert!(!valid(bad), "{pointer}");
        }
        let mut reference = wire();
        reference["harness"]["borrowedTools"][0]["jsonStdio"] =
            value["harness"]["borrowedTools"][0]["jsonStdio"].clone();
        assert!(!valid(reference));
        value["harness"]["borrowedTools"] = json!([]);
        assert!(valid(value.clone()), "an empty selection grants no tools");
        value.as_object_mut().unwrap().remove("harness");
        assert!(!valid(value));
    }
}
