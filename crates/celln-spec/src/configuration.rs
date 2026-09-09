//! Versioned execution configuration fingerprint, not admission or authority.
use crate::ExecutionRequest;
use celln_manifest::Hash;
use serde::Serialize;
use serde_json::Value;

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConfigurationRole {
    OneShot,
    Parent,
    Worker,
}

impl ExecutionRequest {
    /// Hash the complete normalized request with a protocol and role domain.
    /// No identity, argument, input, model grant or authority field is removed.
    /// Object keys sort lexically; arrays retain order; scalar encoding is JSON
    /// as emitted by serde_json. This is not RFC 8785/JCS. Future changes to
    /// normalization require a new protocol version and new operator approval.
    /// Transport-specific size limits must be enforced before deserialization;
    /// hashing adds no new size restriction to existing local execution paths.
    ///
    /// Worker grants/turn-specific arguments cannot be substituted under this
    /// fingerprint: a future worker-template contract must separately define
    /// its host-derived fields and bind the unchanged authority configuration.
    pub fn configuration_binding(&self, role: ConfigurationRole) -> Result<Hash, String> {
        if !self.problems().is_empty() {
            return Err("invalid execution configuration".into());
        }
        let value = serde_json::to_value(("celln.execution-configuration/v1", role, self))
            .map_err(|_| "invalid execution configuration")?;
        let mut bytes = Vec::new();
        canonical(&value, &mut bytes).map_err(|_| "invalid execution configuration")?;
        Ok(Hash::of(&bytes))
    }
}

fn canonical(value: &Value, bytes: &mut Vec<u8>) -> serde_json::Result<()> {
    match value {
        Value::Object(map) => {
            bytes.push(b'{');
            let mut entries: Vec<_> = map.iter().collect();
            entries.sort_by(|a, b| a.0.cmp(b.0));
            for (index, (key, value)) in entries.into_iter().enumerate() {
                if index != 0 {
                    bytes.push(b',');
                }
                serde_json::to_writer(&mut *bytes, key)?;
                bytes.push(b':');
                canonical(value, bytes)?;
            }
            bytes.push(b'}');
        }
        Value::Array(values) => {
            bytes.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    bytes.push(b',');
                }
                canonical(value, bytes)?;
            }
            bytes.push(b']');
        }
        _ => serde_json::to_writer(bytes, value)?,
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> ExecutionRequest {
        serde_json::from_value(serde_json::json!({
            "apiVersion":"celln.dev/v1alpha1", "id":"run-one",
            "workload":{"id":"run-one","caller":"tenant/one"},
            "mote":{"hash":Hash::of(b"mote").0},
            "tools":[{"alias":"/tools/run","hash":Hash::of(b"program").0}],
            "invocation":{"alias":"/tools/run","args":["one","two"]},
            "capabilities":{"workspace":"none","timeoutMs":1000,"memoryBytes":268435456,"outputBytes":1024},
            "execution":{"lane":"agent","requireHardwareIsolation":true}
        })).unwrap()
    }
    #[test]
    fn direct_tool_has_no_harness_requirement_and_roles_cannot_be_swapped() {
        let request = request();
        assert!(request.harness.is_none());
        let one = request
            .configuration_binding(ConfigurationRole::OneShot)
            .unwrap();
        let parent = request
            .configuration_binding(ConfigurationRole::Parent)
            .unwrap();
        let worker = request
            .configuration_binding(ConfigurationRole::Worker)
            .unwrap();
        assert_ne!(one, parent);
        assert_ne!(parent, worker);
        assert_ne!(one, worker);
    }
    #[test]
    fn identity_artifacts_arguments_and_authority_are_all_bound() {
        let original = request();
        let hash = original
            .configuration_binding(ConfigurationRole::Worker)
            .unwrap();
        for pointer in [
            "/id",
            "/workload/id",
            "/workload/caller",
            "/mote/hash",
            "/tools/0/hash",
            "/invocation/args/0",
            "/capabilities/timeoutMs",
            "/capabilities/memoryBytes",
            "/capabilities/outputBytes",
        ] {
            let mut value = serde_json::to_value(&original).unwrap();
            let field = value.pointer_mut(pointer).unwrap();
            *field = if pointer.ends_with("hash") {
                serde_json::json!(Hash::of(b"other").0)
            } else if field.is_string() {
                serde_json::json!("changed")
            } else {
                serde_json::json!(field.as_u64().unwrap() + 1)
            };
            let changed: ExecutionRequest = serde_json::from_value(value).unwrap();
            assert_ne!(
                hash,
                changed
                    .configuration_binding(ConfigurationRole::Worker)
                    .unwrap(),
                "{pointer}"
            );
        }
        let mut changed = original.clone();
        changed.invocation.as_mut().unwrap().args.reverse();
        assert_ne!(
            hash,
            changed
                .configuration_binding(ConfigurationRole::Worker)
                .unwrap()
        );
        changed = original;
        changed.mote.as_mut().unwrap().hash = "latest".into();
        assert!(changed
            .configuration_binding(ConfigurationRole::Worker)
            .is_err());
    }
    #[test]
    fn immutable_inputs_and_workspace_are_bound() {
        let mut request = request();
        request.capabilities.workspace = crate::WorkspaceAccess::ReadOnly;
        request.inputs.push(crate::ExecutionInput {
            name: "facts".into(),
            hash: Hash::of(b"data").0,
            media_type: "text/plain".into(),
            bytes: 4,
        });
        let original = request
            .configuration_binding(ConfigurationRole::Worker)
            .unwrap();
        request.inputs[0].hash = Hash::of(b"next").0;
        assert_ne!(
            original,
            request
                .configuration_binding(ConfigurationRole::Worker)
                .unwrap()
        );
        request.inputs[0].hash = Hash::of(b"data").0;
        request.capabilities.workspace = crate::WorkspaceAccess::ReadWrite;
        assert_ne!(
            original,
            request
                .configuration_binding(ConfigurationRole::Worker)
                .unwrap()
        );
    }
    #[test]
    fn canonical_json_sorts_nested_objects_but_preserves_arrays() {
        let value: Value =
            serde_json::from_str(r#"{"z":[2,1],"a":{"b":false,"a":"x\ny"}}"#).unwrap();
        let mut bytes = Vec::new();
        canonical(&value, &mut bytes).unwrap();
        assert_eq!(bytes, br#"{"a":{"a":"x\ny","b":false},"z":[2,1]}"#);
        let request = request();
        let value = serde_json::to_value(&request).unwrap();
        let reparsed: ExecutionRequest =
            serde_json::from_str(&serde_json::to_string_pretty(&value).unwrap()).unwrap();
        assert_eq!(
            request
                .configuration_binding(ConfigurationRole::Parent)
                .unwrap(),
            reparsed
                .configuration_binding(ConfigurationRole::Parent)
                .unwrap()
        );
    }
}
