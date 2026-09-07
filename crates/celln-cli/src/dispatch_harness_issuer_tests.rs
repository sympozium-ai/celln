use super::*;
use serde_json::json;

pub(super) fn prove_issuance(request: &ExecutionRequest, root: &Path) {
    let profile = setup(root, request);
    set_expiry(&profile, 300_000);
    let bytes = candidate(request, "reviewed", root).unwrap();
    let hash = Hash::of(&bytes);
    let path = root.join("issuer-request.json");
    std::fs::write(&path, serde_json::to_vec(request).unwrap()).unwrap();
    for _ in 0..2 {
        assert_eq!(issue(&path, "reviewed", root).unwrap(), 0);
    }
    let issued = root
        .join("trusted-harness")
        .join(format!("{}.json", hash.0.trim_start_matches("blake3:")));
    assert_eq!(std::fs::read(&issued).unwrap(), bytes);
    let mut bound = request.clone();
    bound.harness.as_mut().unwrap().model_grant.hash = hash.0.clone();
    let bundle =
        crate::dispatch::resolve_bundle(&bound, &root.join("motes"), &root.join("tools")).unwrap();
    let closure = crate::dispatch::closure::resolve(&bound, &bundle, root).unwrap();
    assert!(resolve(&bound, closure.as_ref(), root).unwrap().is_some());
    std::fs::remove_file(profile).unwrap();
    assert!(resolve(&bound, closure.as_ref(), root).is_err());
    assert!(issue(&path, "reviewed", root).is_err());
    assert_eq!(std::fs::read(issued).unwrap(), bytes);
    eprintln!("PASS real-KVM issuer: boot-bound expiring profile, two checks, idempotent publication, v3 resolution and policy withdrawal refusal; modelCalls=0; grant={}", hash.0);
}

fn set_expiry(path: &Path, lifetime_ms: u64) {
    let mut profile: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    profile["apiVersion"] = json!("celln.dev/model-issuer-profile-v2");
    profile["expiry"] = serde_json::to_value(expiry::test_expiry(lifetime_ms)).unwrap();
    std::fs::write(path, serde_json::to_vec(&profile).unwrap()).unwrap();
}

#[test]
#[cfg(target_os = "linux")]
fn unchanged_profile_expires_without_a_reconciler_and_cannot_downgrade() {
    let root = tempfile::tempdir().unwrap();
    let (request, closure, _) = super::super::json_tests::fixture(root.path());
    let path = setup(root.path(), &request);
    set_expiry(&path, 500);
    let original = std::fs::read(&path).unwrap();
    let bytes = candidate(&request, "reviewed", root.path()).unwrap();
    assert!(resolve_bytes(&request, &closure, root.path(), &bytes).is_ok());
    let mut altered: serde_json::Value = serde_json::from_slice(&original).unwrap();
    altered["apiVersion"] = json!("celln.dev/model-issuer-profile-v1");
    std::fs::write(&path, serde_json::to_vec(&altered).unwrap()).unwrap();
    assert!(candidate(&request, "reviewed", root.path()).is_err());
    altered["apiVersion"] = json!("celln.dev/model-issuer-profile-v2");
    altered.as_object_mut().unwrap().remove("expiry");
    std::fs::write(&path, serde_json::to_vec(&altered).unwrap()).unwrap();
    assert!(candidate(&request, "reviewed", root.path()).is_err());
    std::fs::write(&path, &original).unwrap();
    // No profile mutation, cleanup worker or API call causes this refusal.
    std::thread::sleep(std::time::Duration::from_millis(510));
    assert!(resolve_bytes(&request, &closure, root.path(), &bytes)
        .err()
        .unwrap()
        .contains("expired"));
    assert!(candidate(&request, "reviewed", root.path()).is_err());
    assert_eq!(std::fs::read(path).unwrap(), original);
}

fn setup(root: &Path, request: &ExecutionRequest) -> PathBuf {
    let directory = root.join("trusted-model-profiles");
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("reviewed.json");
    std::fs::write(&path, serde_json::to_vec(&json!({
        "apiVersion":"celln.dev/model-issuer-profile-v1", "requestBinding":request_binding(request).unwrap(),
        "model":request.harness.as_ref().unwrap().model,"url":"https://api.deepseek.com/chat/completions",
        "credentialFile":"/never-read-test-credential","maxRequests":3,"maxOutputTokens":512,"maxTotalOutputTokens":1536
    })).unwrap()).unwrap();
    path
}

#[test]
fn issued_grants_pin_full_request_and_live_profile_without_reading_credentials() {
    let root = tempfile::tempdir().unwrap();
    let (mut request, closure, _) = super::super::json_tests::fixture(root.path());
    let path = setup(root.path(), &request);
    let bytes = candidate(&request, "reviewed", root.path()).unwrap();
    let before = request_binding(&request).unwrap();
    request.harness.as_mut().unwrap().model_grant.hash = Hash::of(&bytes).0;
    assert_eq!(request_binding(&request).unwrap(), before);
    let resolved = resolve_bytes(&request, &closure, root.path(), &bytes).unwrap();
    assert!(!resolved.args[0].contains("never-read-test-credential"));
    for field in ["task", "persona", "id", "caller", "timeout", "tools"] {
        let mut changed = serde_json::to_value(&request).unwrap();
        match field {
            "task" => changed["harness"]["task"] = json!("different task"),
            "persona" => changed["harness"]["json"]["system"] = json!("different persona"),
            "id" => changed["id"] = json!("new-attempt"),
            "caller" => changed["workload"]["caller"] = json!("other-caller"),
            "timeout" => changed["capabilities"]["timeoutMs"] = json!(1000),
            "tools" => {
                changed["harness"]["borrowedTools"][0]["description"] =
                    json!("different tool description")
            }
            _ => unreachable!(),
        }
        let changed: ExecutionRequest = serde_json::from_value(changed).unwrap();
        assert!(
            resolve_bytes(&changed, &closure, root.path(), &bytes).is_err(),
            "{field}"
        );
    }
    let original = std::fs::read(&path).unwrap();
    let mut altered = original.clone();
    altered.push(b' ');
    std::fs::write(&path, altered).unwrap();
    assert!(resolve_bytes(&request, &closure, root.path(), &bytes).is_err());
    std::fs::write(&path, original).unwrap();
    std::fs::remove_file(&path).unwrap();
    assert!(resolve_bytes(&request, &closure, root.path(), &bytes).is_err());
    assert!(candidate(&request, "reviewed", root.path()).is_err());
}

#[test]
fn profile_paths_and_issuer_downgrades_refuse() {
    let root = tempfile::tempdir().unwrap();
    let (request, closure, _) = super::super::json_tests::fixture(root.path());
    setup(root.path(), &request);
    for name in ["", "../reviewed", "/reviewed", "with.dot"] {
        assert!(candidate(&request, name, root.path()).is_err());
    }
    let bytes = candidate(&request, "reviewed", root.path()).unwrap();
    let mut grant: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    grant["apiVersion"] = json!("celln.dev/harness-grant-v2");
    assert!(resolve_bytes(
        &request,
        &closure,
        root.path(),
        &serde_json::to_vec(&grant).unwrap()
    )
    .is_err());
    grant["apiVersion"] = json!("celln.dev/harness-grant-v3");
    grant.as_object_mut().unwrap().remove("issuer");
    assert!(resolve_bytes(
        &request,
        &closure,
        root.path(),
        &serde_json::to_vec(&grant).unwrap()
    )
    .is_err());
}

#[test]
fn missing_hardware_or_artifacts_never_publishes_a_grant() {
    let root = tempfile::tempdir().unwrap();
    let (request, _, _) = super::super::json_tests::fixture(root.path());
    setup(root.path(), &request);
    let path = root.path().join("request.json");
    std::fs::write(&path, serde_json::to_vec(&request).unwrap()).unwrap();
    assert!(issue(&path, "reviewed", root.path()).is_err());
    assert!(!root.path().join("trusted-harness").exists());
}
