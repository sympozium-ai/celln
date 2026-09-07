use super::*;

#[cfg(target_os = "linux")]
pub(super) fn prove_prewarm_on_kvm(request: &ExecutionRequest, root: &Path, source: &str) {
    use std::sync::atomic::Ordering;
    let state = state(root);
    let bytes = serde_json::to_vec(request).unwrap();
    crate::dispatch::warm::evict();
    let before = crate::dispatch::warm::PREPARATIONS.load(Ordering::SeqCst);
    let mut observations = Vec::new();
    for _ in 0..2 {
        let response = http(&state, &bytes, &state.token, bytes.len());
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        let report: serde_json::Value =
            serde_json::from_str(response.split_once("\r\n\r\n").unwrap().1).unwrap();
        assert_eq!(report["apiVersion"], "celln.dev/artifact-prewarm-v1");
        assert_eq!(report["requestHash"], celln_manifest::Hash::of(&bytes).0);
        assert_eq!(
            report["verification"]["closure"],
            request.tools[0].closure.as_ref().unwrap().hash
        );
        assert_eq!(
            report["verification"]["memberIntegrity"],
            "verified-in-sealed-cell"
        );
        assert_eq!(report["verification"]["toolExecution"], false);
        assert_eq!(report["verification"]["cellDissolved"], true);
        assert_eq!(report["warmState"], "present-at-observation");
        assert_eq!(report["executionAuthorized"], false);
        assert_eq!(report["artifactReadiness"], "not_checked");
        assert!(state.prewarm.lock().unwrap().is_none());
        assert!(state.executions.lock().unwrap().is_empty());
        assert_eq!(
            crate::dispatch::warm::PREPARATIONS.load(Ordering::SeqCst),
            before + 1
        );
        observations.push(report);
    }
    assert_eq!(
        observations[0]["processEpoch"],
        observations[1]["processEpoch"]
    );
    assert_ne!(
        observations[0]["verification"]["challenge"],
        observations[1]["verification"]["challenge"]
    );
    let policy_path = root.join("trusted-closures.json");
    let original = std::fs::read(&policy_path).unwrap();
    let mut policy: serde_json::Value = serde_json::from_slice(&original).unwrap();
    policy["revoked"] = serde_json::json!([source]);
    std::fs::write(&policy_path, serde_json::to_vec(&policy).unwrap()).unwrap();
    let denied = http(&state, &bytes, &state.token, bytes.len());
    std::fs::write(&policy_path, original).unwrap();
    assert!(denied.starts_with("HTTP/1.1 422"), "{denied}");
    assert!(denied.contains("revoked"), "{denied}");
    assert!(!denied.contains("present-at-observation"));
    assert!(state.prewarm.lock().unwrap().is_none());
    let node = current_node(&state, &HashMap::new());
    assert_eq!((node.live_cells, node.memory_bytes), (0, 268435456));
    let evidence_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(format!("../../target/prewarm-proof-{}", std::process::id()));
    std::fs::create_dir(&evidence_dir).unwrap();
    std::fs::write(evidence_dir.join("evidence.json"),serde_json::to_vec_pretty(&serde_json::json!({
        "status":"passed","scope":"authenticated TCP dispatcher handler + real KVM, not router/controller readiness",
        "observations":observations,"sourceRevocationRefused":true,"preparations":1,"checks":2,"capacityReleased":true,
        "modelCalls":0,"toolExecution":false
    })).unwrap()).unwrap();
    eprintln!("PASS real-KVM prewarm endpoint: {}", evidence_dir.display());
}
fn state(root: &Path) -> State {
    State {
        token_file: PathBuf::new(),
        token: "public-prewarm-test-token-24bytes".into(),
        egress_policy: EgressPolicy::new(&[]).unwrap(),
        root: root.into(),
        probe: NodeProbeArgs {
            node_name: "test".into(),
            mote_store: root.join("motes"),
            tool_store: root.join("tools"),
            max_cells: 2,
            memory_bytes: 268435456,
            egress_slots: 0,
        },
        executions: Arc::new(Mutex::new(HashMap::new())),
        prewarm: Mutex::new(None),
    }
}
fn request() -> serde_json::Value {
    let h = celln_manifest::Hash::of(b"fixture").0;
    serde_json::json!({"apiVersion":"celln.dev/v1alpha1","id":"prewarm","workload":{"id":"test","caller":"operator"},
            "mote":{"hash":h},"tools":[{"alias":"/harness","hash":h,"closure":{"hash":h}}],"invocation":{"alias":"/harness","args":[]},
            "capabilities":{"workspace":"none","timeoutMs":10000,"memoryBytes":268435456,"outputBytes":4096},
            "execution":{"lane":"agent","requireHardwareIsolation":true}})
}
fn http(state: &State, body: &[u8], token: &str, length: usize) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let (server, _) = listener.accept().unwrap();
    write!(client,"POST /v1/artifacts/prewarm HTTP/1.1\r\nAuthorization: Bearer {token}\r\nContent-Length: {length}\r\n\r\n").unwrap();
    client.write_all(body).unwrap();
    super::super::handle(server, state).unwrap();
    let mut out = String::new();
    client.read_to_string(&mut out).unwrap();
    out
}
#[test]
fn prewarm_http_refuses_unauthenticated_oversized_and_executable_requests() {
    let dir = tempfile::tempdir().unwrap();
    let state = state(dir.path());
    assert!(http(&state, b"{}", "wrong", 2).starts_with("HTTP/1.1 401"));
    assert!(http(&state, b"", &state.token, 65537).starts_with("HTTP/1.1 413"));
    let mut r = request();
    r["invocation"]["args"] = serde_json::json!(["execute-me"]);
    let bytes = serde_json::to_vec(&r).unwrap();
    assert!(http(&state, &bytes, &state.token, bytes.len()).starts_with("HTTP/1.1 422"));
    assert!(state.prewarm.lock().unwrap().is_none());
    assert!(state.executions.lock().unwrap().is_empty());
}
#[test]
fn prewarm_reservation_reduces_capacity_and_drop_releases_it() {
    let dir = tempfile::tempdir().unwrap();
    let state = state(dir.path());
    *state.prewarm.lock().unwrap() = Some(Reservation {
        memory_bytes: 268435456,
        egress_slots: 0,
    });
    let lease = Lease(&state);
    let node = current_node(&state, &HashMap::new());
    assert_eq!((node.live_cells, node.memory_bytes), (1, 0));
    let bytes = serde_json::to_vec(&request()).unwrap();
    assert!(http(&state, &bytes, &state.token, bytes.len()).starts_with("HTTP/1.1 503"));
    drop(lease);
    let node = current_node(&state, &HashMap::new());
    assert_eq!((node.live_cells, node.memory_bytes), (0, 268435456));
}
#[test]
fn unavailable_artifacts_or_hardware_never_claim_warmth_and_release_capacity() {
    let dir = tempfile::tempdir().unwrap();
    let state = state(dir.path());
    let bytes = serde_json::to_vec(&request()).unwrap();
    let response = http(&state, &bytes, &state.token, bytes.len());
    assert!(response.starts_with("HTTP/1.1 422"), "{response}");
    assert!(!response.contains("present-at-observation"));
    assert!(state.prewarm.lock().unwrap().is_none());
}
