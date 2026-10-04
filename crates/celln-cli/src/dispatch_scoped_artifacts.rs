//! Scoped artifact authority derived exclusively from admitted signed tools.
//! No mount, host path, standing profile, or additional bearer is introduced.
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Limits {
    operation: Operation,
    max_operations: usize,
    max_files: usize,
    max_file_bytes: usize,
    max_total_bytes: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum Operation {
    Read,
    Write,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Policy {
    read: bool,
    write: bool,
    operations: usize,
    files: usize,
    file_bytes: usize,
    total_bytes: usize,
}

impl Policy {
    pub(super) fn owner(
        &self,
        incarnation: celln_manifest::Hash,
    ) -> Result<warden::workspace_broker::Owner, String> {
        warden::workspace_broker::Owner::new(
            incarnation,
            celln_store::workspace::Limits {
                files: self.files,
                file_bytes: self.file_bytes,
                total_bytes: self.total_bytes,
            },
        )
    }

    pub(super) fn begin(
        &self,
        owner: &mut warden::workspace_broker::Owner,
        turn: &warden::parent_lease::ReservedTurn,
        control: celln_control::Control,
    ) -> Result<
        (
            warden::workspace_broker::Lease,
            warden::workspace_broker::Grant,
        ),
        String,
    > {
        owner.begin_artifacts(turn, self.read, self.write, self.operations, control)
    }
}

fn limits(value: &Value) -> Result<Limits, String> {
    let limits: Limits =
        serde_json::from_value(value.clone()).map_err(|_| "AUTH_PROTOCOL_UNSUPPORTED")?;
    if !(1..=64).contains(&limits.max_operations)
        || !(1..=256).contains(&limits.max_files)
        || !(1..=4096).contains(&limits.max_file_bytes)
        || limits.max_total_bytes < limits.max_file_bytes
        || limits.max_total_bytes > 1048576
    {
        return Err("AUTH_LIMIT_OUT_OF_RANGE".into());
    }
    Ok(limits)
}

/// Called at prepare and again after credential verification, before an owner
/// exists. The existing v1 decision already signs these fields. Material may
/// attenuate neither away nor beyond the signed decision unnoticed.
pub(super) fn derive(execution: &Value, decision: &Value) -> Result<Option<Policy>, String> {
    let materials = execution["tools"]
        .as_array()
        .ok_or("AUTH_PROTOCOL_UNSUPPORTED")?;
    let tools = decision["tools"]
        .as_array()
        .ok_or("AUTH_PROTOCOL_UNSUPPORTED")?;
    if materials.len() != tools.len() {
        return Err("AUTH_REQUEST_BINDING_MISMATCH".into());
    }
    let mut policy: Option<Policy> = None;
    for (material, tool) in materials.iter().zip(tools) {
        let signed = &tool["limits"]["artifacts"];
        let declared = &material["spec"]["limits"]["artifacts"];
        if signed.is_null() && declared.is_null() {
            continue;
        }
        if decision["lifecycle"] == "one-shot"
            || decision["route"]["provider"] == "none"
            || tool["limits"]["workspace"] != "none"
            || material["spec"]["limits"]["workspace"] != "none"
            || !tool["limits"]["https"].is_null()
            || !material["spec"]["limits"]["https"].is_null()
        {
            return Err("AUTH_PROTOCOL_UNSUPPORTED".into());
        }
        let signed = limits(signed)?;
        let declared = limits(declared)?;
        let effects = match signed.operation {
            Operation::Read => "none",
            Operation::Write => "external-side-effects",
        };
        if tool["limits"]["effects"] != effects || material["spec"]["limits"]["effects"] != effects
        {
            return Err("AUTH_PROTOCOL_UNSUPPORTED".into());
        }
        if signed.operation != declared.operation
            || signed.max_operations > declared.max_operations
            || signed.max_files > declared.max_files
            || signed.max_file_bytes > declared.max_file_bytes
            || signed.max_total_bytes > declared.max_total_bytes
        {
            return Err("AUTH_REQUEST_BINDING_MISMATCH".into());
        }
        let current = policy.get_or_insert(Policy {
            read: false,
            write: false,
            operations: signed.max_operations,
            files: signed.max_files,
            file_bytes: signed.max_file_bytes,
            total_bytes: signed.max_total_bytes,
        });
        current.read |= signed.operation == Operation::Read;
        current.write |= signed.operation == Operation::Write;
        // One cell is one authority domain. Intersect all selected artifact
        // ceilings, never sum per-tool allowances or trust a guest tool name.
        current.operations = current.operations.min(signed.max_operations);
        current.files = current.files.min(signed.max_files);
        current.file_bytes = current.file_bytes.min(signed.max_file_bytes);
        current.total_bytes = current.total_bytes.min(signed.max_total_bytes);
    }
    Ok(policy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture() -> (Value, Value) {
        let artifacts = json!({"operation":"write","maxOperations":4,"maxFiles":8,"maxFileBytes":4096,"maxTotalBytes":16384});
        let limits = json!({"workspace":"none","effects":"external-side-effects","artifacts":artifacts,"https":null});
        (
            json!({"tools":[{"spec":{"limits":limits}}]}),
            json!({"lifecycle":"enduring-initial","route":{"provider":"fixture"},"tools":[{"limits":limits}]}),
        )
    }

    #[test]
    fn shared_contract_vectors() {
        let vectors: Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/scoped-artifacts/v1.json"
        ))
        .unwrap();
        assert_eq!(vectors["apiVersion"], "celln.scoped-artifacts/v1");
        for vector in vectors["vectors"].as_array().unwrap() {
            let (mut execution, mut decision) = fixture();
            execution["tools"][0]["spec"]["limits"]["artifacts"] = vectors["declared"].clone();
            let mut signed = vectors["declared"].clone();
            for (key, value) in vector["patch"].as_object().unwrap() {
                signed[key] = value.clone();
            }
            decision["tools"][0]["limits"]["artifacts"] = signed;
            assert_eq!(
                derive(&execution, &decision).is_ok(),
                vector["accepted"].as_bool().unwrap(),
                "{}",
                vector["name"]
            );
        }
    }

    #[test]
    fn signed_limits_are_required_and_never_widened() {
        let (execution, decision) = fixture();
        let policy = derive(&execution, &decision).unwrap().unwrap();
        assert!(!policy.read && policy.write);
        assert_eq!(policy.operations, 4);
        for value in [Value::Null, json!({}), json!({"operation":"symlink"})] {
            let mut changed = decision.clone();
            changed["tools"][0]["limits"]["artifacts"] = value;
            assert!(derive(&execution, &changed).is_err());
        }
        for field in ["maxOperations", "maxFiles", "maxFileBytes", "maxTotalBytes"] {
            let mut changed = decision.clone();
            changed["tools"][0]["limits"]["artifacts"][field] = json!(0);
            assert!(derive(&execution, &changed).is_err());
            changed["tools"][0]["limits"]["artifacts"][field] = json!(99999999);
            assert!(derive(&execution, &changed).is_err());
        }
        let mut widened = decision.clone();
        widened["tools"][0]["limits"]["artifacts"]["maxOperations"] = json!(5);
        assert!(derive(&execution, &widened).is_err());
        widened["tools"][0]["limits"]["artifacts"]["maxOperations"] = json!(2);
        assert_eq!(derive(&execution, &widened).unwrap().unwrap().operations, 2);
    }

    #[test]
    fn unsupported_paths_stay_closed() {
        let (execution, decision) = fixture();
        for (pointer, value) in [
            ("/lifecycle", json!("one-shot")),
            ("/route/provider", json!("none")),
            ("/tools/0/limits/workspace", json!("read-write")),
            ("/tools/0/limits/https", json!({})),
            ("/tools/0/limits/effects", json!("none")),
            ("/tools/0/limits/artifacts/operation", json!("read")),
        ] {
            let mut changed = decision.clone();
            *changed.pointer_mut(pointer).unwrap() = value;
            assert!(derive(&execution, &changed).is_err(), "{pointer}");
        }
        let mut changed = decision;
        changed["tools"][0]["limits"]["artifacts"]["hostPath"] = json!("/etc");
        assert!(derive(&execution, &changed).is_err());
    }

    #[test]
    fn two_selected_tools_intersect_caps_and_pin_the_retained_policy() {
        let (mut execution, mut decision) = fixture();
        let mut material = execution["tools"][0].clone();
        material["spec"]["limits"]["effects"] = json!("none");
        material["spec"]["limits"]["artifacts"]["operation"] = json!("read");
        let mut signed = material["spec"]["limits"].clone();
        signed["artifacts"]["maxOperations"] = json!(2);
        signed["artifacts"]["maxFiles"] = json!(3);
        execution["tools"].as_array_mut().unwrap().push(material);
        decision["tools"]
            .as_array_mut()
            .unwrap()
            .push(json!({"limits":signed}));
        let pinned = derive(&execution, &decision).unwrap().unwrap();
        assert!(pinned.read && pinned.write);
        assert_eq!((pinned.operations, pinned.files), (2, 3));
        decision["lifecycle"] = json!("enduring-turn");
        assert_eq!(derive(&execution, &decision).unwrap(), Some(pinned.clone()));
        decision["tools"][1]["limits"]["artifacts"]["maxOperations"] = json!(1);
        assert_ne!(derive(&execution, &decision).unwrap(), Some(pinned));
    }
}
