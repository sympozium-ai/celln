//! Binding tests, not a substitute for signed admission or KVM execution.
use super::*;
use celln_manifest::closure::{Closure, Member};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

const SCHEMA: &str = r#"{"type":"object","properties":{"text":{"type":"string","minLength":0,"maxLength":64}},"required":["text"],"additionalProperties":false}"#;

fn fixture(root: &Path) -> (ExecutionRequest, super::super::closure::Admitted, Value) {
    let mut wire: Value = serde_json::from_str(include_str!(
        "../../../examples/execution/harness-reference.json"
    ))
    .unwrap();
    let schema = celln_store::Store::open(root.join("tool-schemas"))
        .unwrap()
        .put(SCHEMA.as_bytes())
        .unwrap();
    wire["apiVersion"] = json!("celln.dev/v1alpha3");
    wire["harness"]["contractVersion"] = json!("celln.json-tools/v1");
    wire["harness"]["json"] = json!({"system":"Approved persona","maxTurns":3,"maxCalls":2});
    for tool in wire["harness"]["borrowedTools"].as_array_mut().unwrap() {
        tool["jsonStdio"] = json!({"abi":"celln.json-stdio/v1","inputSchema":schema.0,
            "outputSchema":schema.0,"inputBytes":1024,"outputBytes":1024,"timeoutMs":1000});
    }
    let request: ExecutionRequest = serde_json::from_value(wire).unwrap();
    let h = request.harness.as_ref().unwrap();
    let mut members = BTreeMap::new();
    for tool in &h.borrowed_tools {
        members.insert(
            tool.path.clone(),
            Member {
                hash: tool.hash.clone(),
                dependencies: BTreeSet::new(),
            },
        );
    }
    members.insert(
        "/pilot-fetch".into(),
        Member {
            hash: Hash::of(b"fetch").0,
            dependencies: BTreeSet::new(),
        },
    );
    members.insert(
        "/harness".into(),
        Member {
            hash: request.tools[0].hash.clone(),
            dependencies: members.keys().cloned().collect(),
        },
    );
    let signed = Closure {
        api_version: "celln.dev/closure-v1".into(),
        toolfs: Hash::of(b"image").0,
        entrypoint: "/harness".into(),
        interpreter: false,
        members,
    }
    .sign(&[19; 32])
    .unwrap();
    let admitted = super::super::closure::Admitted {
        provenance: super::super::closure::Provenance {
            hash: request.tools[0].closure.as_ref().unwrap().hash.clone(),
            publisher: signed.publisher.clone(),
            toolfs: signed.closure.toolfs.clone(),
            members: signed.closure.members.clone(),
        },
        signed,
    };
    let grant = json!({"apiVersion":"celln.dev/harness-grant-v2","contractVersion":h.contract_version,
        "json":h.json,"caller":request.workload.caller,"mote":request.mote.as_ref().unwrap().hash,
        "runtime":request.tools[0].hash,"closure":admitted.provenance.hash,"borrowedTools":h.borrowed_tools,
        "url":"https://api.deepseek.com/chat/completions","model":h.model,"credentialFile":"/not-read-or-delivered",
        "maxRequests":3,"maxOutputTokens":512,"maxTotalOutputTokens":1536});
    (request, admitted, grant)
}

fn install(root: &Path, request: &mut ExecutionRequest, grant: &Value) -> PathBuf {
    let bytes = serde_json::to_vec(grant).unwrap();
    let hash = Hash::of(&bytes);
    request.harness.as_mut().unwrap().model_grant.hash = hash.0.clone();
    let dir = root.join("trusted-harness");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("{}.json", hash.0.trim_start_matches("blake3:")));
    std::fs::write(&path, bytes).unwrap();
    path
}

#[test]
fn json_resolution_pins_schema_bytes_and_never_delivers_host_credentials() {
    let root = tempfile::tempdir().unwrap();
    let (mut request, admitted, grant) = fixture(root.path());
    assert!(request.problems().is_empty());
    assert!(resolve(&request, Some(&admitted), root.path()).is_err());
    let path = install(root.path(), &mut request, &grant);
    let resolved = resolve(&request, Some(&admitted), root.path())
        .unwrap()
        .unwrap();
    let config: Value = serde_json::from_str(&resolved.args[0]).unwrap();
    assert_eq!(config["contract"], "celln.json-tools/v1");
    assert_eq!(config["tools"][0]["input_schema"]["bytes"], SCHEMA);
    assert_eq!(config["max_turns"], 3);
    assert_eq!(resolved.policy.max_requests, 3);
    assert!(!resolved.args[0].contains("not-read-or-delivered"));
    for pointer in [
        "/harness/json/system",
        "/harness/json/maxCalls",
        "/harness/borrowedTools/0/jsonStdio/inputSchema",
        "/harness/borrowedTools/0/jsonStdio/outputBytes",
        "/harness/borrowedTools/0/jsonStdio/timeoutMs",
        "/workload/caller",
    ] {
        let mut changed = serde_json::to_value(&request).unwrap();
        let slot = changed.pointer_mut(pointer).unwrap();
        *slot = if slot.is_number() {
            json!(1)
        } else if pointer.ends_with("Schema") {
            json!(Hash::of(b"other").0)
        } else {
            json!("other")
        };
        let bad: ExecutionRequest = serde_json::from_value(changed).unwrap();
        assert!(
            bad.problems().is_empty(),
            "must test host grant mismatch, not only syntax: {pointer}"
        );
        assert!(
            resolve(&bad, Some(&admitted), root.path()).is_err(),
            "{pointer}"
        );
    }
    std::fs::remove_file(path).unwrap();
    assert!(resolve(&request, Some(&admitted), root.path()).is_err());
}

#[test]
fn legacy_grants_budget_shortfalls_and_wrong_contracts_cannot_authorize_json() {
    let root = tempfile::tempdir().unwrap();
    let (request, admitted, grant) = fixture(root.path());
    for (field, replacement) in [
        ("apiVersion", json!("celln.dev/harness-grant-v1")),
        ("contractVersion", json!("celln.reference-functions/v1")),
        ("json", Value::Null),
        ("maxRequests", json!(2)),
        ("maxTotalOutputTokens", json!(1024)),
    ] {
        let mut grant = grant.clone();
        grant[field] = replacement;
        let mut request = request.clone();
        install(root.path(), &mut request, &grant);
        assert!(
            resolve(&request, Some(&admitted), root.path()).is_err(),
            "{field}"
        );
    }
}

#[test]
fn stored_schema_must_be_present_bounded_valid_and_exact() {
    let root = tempfile::tempdir().unwrap();
    let (mut request, admitted, mut grant) = fixture(root.path());
    let store = celln_store::Store::open(root.path().join("tool-schemas")).unwrap();
    for bytes in [
        b"not a schema".to_vec(),
        br#"{"type":"string"}"#.to_vec(),
        vec![b' '; celln_manifest::tool_schema::MAX_SCHEMA_BYTES + 1],
    ] {
        let hash = store.put(&bytes).unwrap();
        request.harness.as_mut().unwrap().borrowed_tools[0]
            .json_stdio
            .as_mut()
            .unwrap()
            .input_schema = hash.0;
        grant["borrowedTools"] =
            serde_json::to_value(&request.harness.as_ref().unwrap().borrowed_tools).unwrap();
        install(root.path(), &mut request, &grant);
        assert!(resolve(&request, Some(&admitted), root.path()).is_err());
    }
    let hash = Hash::of(SCHEMA.as_bytes());
    request.harness.as_mut().unwrap().borrowed_tools[0]
        .json_stdio
        .as_mut()
        .unwrap()
        .input_schema = hash.0.clone();
    grant["borrowedTools"] =
        serde_json::to_value(&request.harness.as_ref().unwrap().borrowed_tools).unwrap();
    install(root.path(), &mut request, &grant);
    let hex = hash.0.trim_start_matches("blake3:");
    let path = root
        .path()
        .join("tool-schemas/objects")
        .join(&hex[..2])
        .join(hex);
    std::fs::write(&path, b"tampered").unwrap();
    assert!(resolve(&request, Some(&admitted), root.path()).is_err());
    std::fs::remove_file(path).unwrap();
    assert!(resolve(&request, Some(&admitted), root.path()).is_err());
}

#[test]
fn empty_selection_requires_an_exact_runtime_and_broker_only_closure() {
    let root = tempfile::tempdir().unwrap();
    let (mut request, mut admitted, mut grant) = fixture(root.path());
    request.harness.as_mut().unwrap().borrowed_tools.clear();
    grant["borrowedTools"] = json!([]);
    install(root.path(), &mut request, &grant);
    assert!(request.problems().is_empty());
    assert!(
        resolve(&request, Some(&admitted), root.path()).is_err(),
        "unselected members must not leak into the closure"
    );
    admitted
        .signed
        .closure
        .members
        .retain(|path, _| path == "/harness" || path == "/pilot-fetch");
    admitted
        .signed
        .closure
        .members
        .get_mut("/harness")
        .unwrap()
        .dependencies = BTreeSet::from(["/pilot-fetch".into()]);
    let resolved = resolve(&request, Some(&admitted), root.path())
        .unwrap()
        .unwrap();
    let config: Value = serde_json::from_str(&resolved.args[0]).unwrap();
    assert_eq!(config["tools"], json!([]));
    admitted.signed.closure.interpreter = true;
    assert!(resolve(&request, Some(&admitted), root.path()).is_err());
}
