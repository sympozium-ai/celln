//! Explicitly billable HTTP→dispatcher→warm-fork model/tool proof.
use super::*;
use celln_manifest::{closure::SignedClosure, Hash};
use serde_json::{json, Value};

fn http(state: &State, method: &str, path: &str, body: &str) -> (u16, Value) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let (server, _) = listener.accept().unwrap();
    write!(
        client,
        "{method} {path} HTTP/1.1\r\nAuthorization: Bearer {}\r\nContent-Length: {}\r\n\r\n{body}",
        state.token,
        body.len()
    )
    .unwrap();
    handle(server, state).unwrap();
    let mut response = String::new();
    client.read_to_string(&mut response).unwrap();
    let status = response.split_whitespace().nth(1).unwrap().parse().unwrap();
    let body = serde_json::from_str(response.split_once("\r\n\r\n").unwrap().1).unwrap();
    (status, body)
}

fn controller_hook(
    state: &Arc<State>,
    request: &ExecutionRequest,
    package: &Path,
    namespace: &str,
    hook: &std::ffi::OsStr,
) {
    use std::sync::atomic::{AtomicBool, Ordering};
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    listener.set_nonblocking(true).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let server_stop = stop.clone();
    let server_state = state.clone();
    let server = thread::spawn(move || {
        while !server_stop.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _)) => {
                    handle(stream, &server_state).unwrap();
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(20))
                }
                Err(e) => panic!("fixture listener: {e}"),
            }
        }
    });
    let mut token_file = tempfile::NamedTempFile::new().unwrap();
    token_file.write_all(state.token.as_bytes()).unwrap();
    let request_file = package.join("controller-request.json");
    std::fs::write(&request_file, serde_json::to_vec_pretty(request).unwrap()).unwrap();
    let output = std::process::Command::new("timeout")
        .args(["240s", "bash"])
        .arg(hook)
        .env("CELLN_ROUTER_URL", url)
        .env("CELLN_TOKEN_FILE", token_file.path())
        .env("CELLN_PROOF_REQUEST", request_file)
        .env("CELLN_PROOF_EVIDENCE", package.join("controller"))
        .env("CELLN_PROOF_NAMESPACE", namespace)
        .output();
    stop.store(true, Ordering::SeqCst);
    server.join().unwrap();
    let output = output.unwrap();
    assert!(
        output.status.success(),
        "controller hook failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    eprintln!("{}", String::from_utf8_lossy(&output.stdout));
}

#[test]
#[ignore = "billable: requires CELLN_HARNESS_PACKAGE, CELLN_MODEL_TOKEN_FILE and real KVM"]
fn harness_model_over_authenticated_dispatch() {
    let _lock = crate::dispatch::warm::PROOF_LOCK.lock().unwrap();
    let package = PathBuf::from(
        std::env::var_os("CELLN_HARNESS_PACKAGE")
            .expect("set package directory from celln-harness-proof --package-only"),
    );
    let token = PathBuf::from(
        std::env::var_os("CELLN_MODEL_TOKEN_FILE").expect("set private host credential file"),
    );
    assert!(
        Path::new("/dev/kvm").exists(),
        "explicit hardware proof requires KVM"
    );
    let work = tempfile::tempdir().unwrap();
    let root = work.path();
    let namespace = format!("celln-harness-proof-{}", std::process::id());
    let hook = std::env::var_os("CELLN_HARNESS_CONTROLLER_HOOK");
    let caller = if hook.is_some() {
        format!("sympozium:{namespace}/harness-proof")
    } else {
        "test:controller".into()
    };
    let motes = Store::open(root.join("motes")).unwrap();
    let tools = Store::open(root.join("tools")).unwrap();
    let runtime = tools
        .put(&std::fs::read(package.join("harness")).unwrap())
        .unwrap();
    let signed_bytes = std::fs::read(package.join("signed-closure.json")).unwrap();
    let signed: SignedClosure = serde_json::from_slice(&signed_bytes).unwrap();
    let closure = Store::open(root.join("closures"))
        .unwrap()
        .put(&signed_bytes)
        .unwrap();
    std::fs::write(root.join("trusted-closures.json"),json!({"apiVersion":"celln.dev/closure-policy-v1","publishers":[signed.publisher],"revoked":[]}).to_string()).unwrap();
    let kernel = warden::vmm::boot::BootConfig::host_kernel().expect("kernel");
    let kernel = motes.put(&std::fs::read(kernel).unwrap()).unwrap();
    let initrd = motes
        .put(&std::fs::read(package.join("initramfs.cpio")).unwrap())
        .unwrap();
    let toolfs = motes
        .put(&std::fs::read(package.join("toolfs.img")).unwrap())
        .unwrap();
    let mote = motes.put(&serde_json::to_vec(&json!({"apiVersion":"celln.dev/v1alpha1","format":"celln.warm-closure-v1","kernel":kernel.0,"initrd":initrd.0,"toolfs":toolfs.0,"invocation":{"alias":"/harness","toolHash":runtime.0}})).unwrap()).unwrap();
    std::fs::write(
        root.join("trusted-motes.json"),
        json!({"apiVersion":"celln.dev/v1alpha1","bundles":[mote.0]}).to_string(),
    )
    .unwrap();
    let borrowed = json!([
        {"name":"add","path":"/add","hash":signed.closure.members["/add"].hash,"description":"Add two integer strings."},
        {"name":"multiply","path":"/multiply","hash":signed.closure.members["/multiply"].hash,"description":"Multiply two integer strings."}
    ]);
    let grant = serde_json::to_vec(&json!({"apiVersion":"celln.dev/harness-grant-v1","caller":caller,"mote":mote.0,"runtime":runtime.0,"closure":closure.0,"borrowedTools":borrowed,"url":"https://api.deepseek.com/chat/completions","model":"deepseek-chat","credentialFile":token,"maxRequests":3,"maxOutputTokens":512,"maxTotalOutputTokens":1536})).unwrap();
    let grant_hash = Hash::of(&grant);
    let grant_dir = root.join("trusted-harness");
    std::fs::create_dir(&grant_dir).unwrap();
    let grant_file = grant_dir.join(format!(
        "{}.json",
        grant_hash.0.trim_start_matches("blake3:")
    ));
    std::fs::write(&grant_file, &grant).unwrap();
    let request: ExecutionRequest = serde_json::from_value(json!({"apiVersion":"celln.dev/v1alpha2","id":"harness-dispatch-proof","workload":{"id":"test-run","caller":caller},"mote":{"hash":mote.0},"tools":[{"alias":"/harness","hash":runtime.0,"closure":{"hash":closure.0}}],"invocation":{"alias":"/harness"},"harness":{"model":"deepseek-chat","contractVersion":"celln.reference-functions/v1","modelGrant":{"hash":grant_hash.0},"task":"Use add with args [\"37\",\"5\"], wait for its result, then multiply that result by \"2\". Reply with exactly the final integer.","borrowedTools":borrowed},"capabilities":{"workspace":"none","egress":["https://api.deepseek.com"],"timeoutMs":180000,"memoryBytes":268435456,"outputBytes":65536},"execution":{"lane":"agent","requireHardwareIsolation":true}})).unwrap();
    assert!(request.problems().is_empty(), "{:?}", request.problems());
    let state = State {
        token_file: PathBuf::new(),
        token: "test-token-at-least-24-bytes".into(),
        egress_policy: EgressPolicy::new(&["api.deepseek.com".into()]).unwrap(),
        root: root.into(),
        probe: NodeProbeArgs {
            node_name: "harness-proof-node".into(),
            mote_store: root.join("motes"),
            tool_store: root.join("tools"),
            max_cells: 1,
            memory_bytes: 268435456,
            egress_slots: 1,
        },
        executions: Arc::new(Mutex::new(HashMap::new())),
    };
    let state = Arc::new(state);
    let resolved =
        crate::dispatch::resolve_bundle(&request, &state.probe.mote_store, &state.probe.tool_store)
            .unwrap();
    let admitted = crate::dispatch::closure::resolve(&request, &resolved, root).unwrap();
    for change in ["caller", "tool", "grant"] {
        let mut bad = request.clone();
        match change {
            "caller" => bad.workload.caller = "tenant:other".into(),
            "tool" => {
                bad.harness.as_mut().unwrap().borrowed_tools[0].hash = Hash::of(b"wrong tool").0
            }
            _ => bad.harness.as_mut().unwrap().model_grant.hash = Hash::of(b"unknown grant").0,
        }
        assert!(crate::dispatch::harness::resolve(&bad, admitted.as_ref(), root).is_err());
    }
    let (status, body) = http(
        &state,
        "POST",
        "/v1/executions",
        &serde_json::to_string(&request).unwrap(),
    );
    assert_eq!(status, 202, "{body}");
    let deadline = Instant::now() + Duration::from_secs(190);
    let terminal = loop {
        let (_, body) = http(&state, "GET", "/v1/executions/harness-dispatch-proof", "");
        if matches!(
            body["phase"].as_str(),
            Some("Succeeded" | "Failed" | "Refused" | "Cancelled")
        ) {
            break body;
        }
        assert!(Instant::now() < deadline, "dispatch deadline");
        thread::sleep(Duration::from_millis(200));
    };
    assert_eq!(terminal["phase"], "Succeeded", "{terminal}");
    assert_eq!(terminal["receipt"]["apiVersion"], "celln.dev/v1alpha2");
    let events: Vec<Value> = terminal["output"]
        .as_str()
        .unwrap()
        .lines()
        .filter_map(|line| line.strip_prefix("CELLN_HARNESS_EVENT "))
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let calls: Vec<_> = events.iter().filter(|e| e["type"] == "tool").collect();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0]["result"], "42\n");
    assert_eq!(calls[1]["args"], json!(["42", "2"]));
    assert_eq!(calls[1]["result"], "84\n");
    assert!(events
        .iter()
        .any(|e| e["type"] == "completed" && e["answer"] == "84"));
    let (_, audit) = http(
        &state,
        "GET",
        "/v1/executions/harness-dispatch-proof/audit",
        "",
    );
    assert_eq!(audit["execution"]["modelGrant"], grant_hash.0);
    assert_eq!(audit["execution"]["broker"]["requests"], 3);
    assert!(!serde_json::to_string(&audit)
        .unwrap()
        .contains(&token.display().to_string()));
    // Emulate losing the in-memory registry: disk claim still refuses replay.
    assert!(crate::dispatch::harness::claim(&request, root)
        .unwrap_err()
        .contains("already claimed"));
    if let Some(hook) = hook {
        controller_hook(&state, &request, &package, &namespace, &hook);
    }
    std::fs::remove_file(&grant_file).unwrap();
    assert!(crate::dispatch::harness::resolve(&request, admitted.as_ref(), root).is_err());
    let evidence = json!({"scope":"authenticated host HTTP dispatcher; not router/Sympozium/Kind","request":request,"terminal":terminal,"audit":audit,"callerMismatchDenied":true,"toolMismatchDenied":true,"unknownGrantDenied":true,"localReplayDenied":true,"grantWithdrawalDenied":true});
    std::fs::write(
        package.join("dispatch-evidence.json"),
        serde_json::to_vec_pretty(&evidence).unwrap(),
    )
    .unwrap();
    eprintln!(
        "PASS: authenticated Harness dispatch; evidence {}",
        package.join("dispatch-evidence.json").display()
    );
}
