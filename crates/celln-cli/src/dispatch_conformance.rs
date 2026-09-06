//! Public HTTP → production worker → real KVM → receipt/audit proof.
//! Called from the ignored declared-substrate proof to reuse its exact fixture.

use celln_spec::ExecutionRequest;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const TOKEN: &str = "isolated-conformance-token-not-a-real-secret";

pub(crate) fn prove_closure(
    request: &ExecutionRequest,
    motes: &Path,
    tools: &Path,
    root: &Path,
    evidence: &Path,
) {
    let binary = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/celln");
    let address = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let token = root.join("closure-test-token");
    std::fs::write(&token, TOKEN).unwrap();
    let log = std::fs::File::create(evidence.join("dispatcher.log")).unwrap();
    let child = Command::new(binary)
        .arg("--root")
        .arg(root)
        .arg("dispatcher")
        .arg("--listen")
        .arg(address.to_string())
        .arg("--token-file")
        .arg(&token)
        .arg("--mote-store")
        .arg(motes)
        .arg("--tool-store")
        .arg(tools)
        .args(["--memory-bytes", "268435456", "--egress-slots", "1"])
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log))
        .spawn()
        .unwrap();
    let mut server = Server {
        child,
        address,
        evidence: evidence.to_owned(),
    };
    let start = Instant::now();
    while TcpStream::connect(address).is_err() {
        assert!(
            server.child.try_wait().unwrap().is_none(),
            "dispatcher exited"
        );
        assert!(start.elapsed() < Duration::from_secs(10));
        std::thread::sleep(Duration::from_millis(25));
    }
    server.submit(request);
    let audit = server.terminal(request, "Succeeded");
    assert_eq!(
        audit["execution"]["substrate"]["closure"]["hash"],
        request.tools[0].closure.as_ref().unwrap().hash
    );
    let mut refused = request.clone();
    refused.id = "unknown-closure".into();
    refused.tools[0].closure.as_mut().unwrap().hash =
        celln_manifest::Hash::of(b"unknown closure").0;
    server.submit(&refused);
    assert!(server.terminal(&refused, "Failed")["execution"].is_null());
    if let Some(script) = std::env::var_os("CELLN_SYMPOZIUM_PROOF") {
        let external = evidence.join("sympozium");
        std::fs::create_dir_all(&external).unwrap();
        let reference = evidence.join(format!("{}-request.json", request.id));
        let log = std::fs::File::create(external.join("proof.log")).unwrap();
        let status = Command::new("timeout")
            .args(["--signal=TERM", "--kill-after=10s", "600s"])
            .arg(script)
            .env("CELLN_ROUTER_URL", format!("http://{address}"))
            .env("CELLN_TOKEN_FILE", &token)
            .env("CELLN_PROOF_REQUEST", reference)
            .env("CELLN_PROOF_EVIDENCE", &external)
            .env("CELLN_PROOF_ROOT", root)
            .env(
                "CELLN_PROOF_BINARY",
                Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/celln"),
            )
            .env("CELLN_PROOF_MODE", "closure")
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .status()
            .unwrap();
        assert!(
            status.success(),
            "external closure proof failed; inspect {}",
            external.display()
        );
    }
}

struct Server {
    child: Child,
    address: SocketAddr,
    evidence: PathBuf,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Server {
    fn http(&self, method: &str, path: &str, body: Option<&Value>, token: &str) -> (u16, Value) {
        let mut socket = TcpStream::connect(self.address).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let body = body.map(Value::to_string).unwrap_or_default();
        write!(socket, "{method} {path} HTTP/1.1\r\nAuthorization: Bearer {token}\r\nContent-Length: {}\r\n\r\n{body}", body.len()).unwrap();
        let mut response = String::new();
        socket.read_to_string(&mut response).unwrap();
        let (header, body) = response.split_once("\r\n\r\n").unwrap();
        (
            header.split_whitespace().nth(1).unwrap().parse().unwrap(),
            serde_json::from_str(body).unwrap(),
        )
    }

    fn save(&self, name: &str, value: &Value) {
        std::fs::write(
            self.evidence.join(format!("{name}.json")),
            serde_json::to_vec_pretty(value).unwrap(),
        )
        .unwrap();
    }

    fn submit(&self, request: &ExecutionRequest) {
        let value = serde_json::to_value(request).unwrap();
        self.save(&format!("{}-request", request.id), &value);
        let (status, body) = self.http("POST", "/v1/executions", Some(&value), TOKEN);
        assert_eq!(status, 202, "{body}");
    }

    fn terminal(&self, request: &ExecutionRequest, expected: &str) -> Value {
        let started = Instant::now();
        let result = loop {
            let (status, body) = self.http(
                "GET",
                &format!("/v1/executions/{}", request.id),
                None,
                TOKEN,
            );
            assert_eq!(status, 200, "{body}");
            if matches!(
                body["phase"].as_str(),
                Some("Succeeded" | "Failed" | "Cancelled" | "Refused")
            ) {
                break body;
            }
            assert!(
                started.elapsed() < Duration::from_secs(20),
                "execution did not terminate: {body}"
            );
            std::thread::sleep(Duration::from_millis(25));
        };
        self.save(&format!("{}-result", request.id), &result);
        assert_eq!(result["phase"], expected, "{result}");
        let (status, audit) = self.http(
            "GET",
            &format!("/v1/executions/{}/audit", request.id),
            None,
            TOKEN,
        );
        assert_eq!(status, 200, "{audit}");
        self.save(&format!("{}-audit", request.id), &audit);
        assert_eq!(audit["requestId"], request.id);
        assert_eq!(audit["caller"], request.workload.caller);
        if let Some(receipt) = result.get("receipt") {
            let parsed: celln_spec::ExecutionReceipt =
                serde_json::from_value(receipt.clone()).unwrap();
            assert!(parsed.problems().is_empty(), "invalid receipt: {receipt}");
            assert_eq!(audit["receipt"], *receipt);
            assert_eq!(audit["execution"]["cellId"], receipt["cellId"]);
            assert!(audit["events"]
                .as_array()
                .unwrap()
                .iter()
                .any(|event| event["phase"] == "Dissolved"));
        }
        let (_, node) = self.http("GET", "/v1/node", None, TOKEN);
        assert_eq!(node["node"]["live_cells"], 0, "reservation leak: {node}");
        assert_eq!(node["node"]["memory_bytes"], 268435456u64);
        assert_eq!(node["node"]["egress_slots"], 1);
        audit
    }
}

pub(crate) fn prove(base: ExecutionRequest, motes: &Path, tools: &Path, root: &Path) {
    let isolated_root = root.join("http-conformance");
    std::fs::create_dir(&isolated_root).unwrap();
    std::fs::copy(
        root.join("trusted-motes.json"),
        isolated_root.join("trusted-motes.json"),
    )
    .unwrap();
    let root = isolated_root.as_path();
    let input = celln_store::Store::open(root.join("inputs"))
        .unwrap()
        .put(b"first-input")
        .unwrap();
    std::fs::write(
        root.join("trusted-inputs.json"),
        serde_json::to_vec(&json!({"apiVersion": "celln.dev/v1alpha1", "hashes": [input.0]}))
            .unwrap(),
    )
    .unwrap();
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let binary = repo.join("target/debug/celln");
    assert!(
        binary.is_file(),
        "build the dispatcher first: cargo build -p celln-cli"
    );
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let evidence = repo.join(format!(
        "target/dispatch-conformance/{nonce}-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&evidence).unwrap();
    let address = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let token = root.join("conformance-token");
    std::fs::write(&token, TOKEN).unwrap();
    let log = std::fs::File::create(evidence.join("dispatcher.log")).unwrap();
    let child = Command::new(&binary)
        .arg("--root")
        .arg(root)
        .arg("dispatcher")
        .arg("--listen")
        .arg(address.to_string())
        .arg("--token-file")
        .arg(&token)
        .arg("--mote-store")
        .arg(motes)
        .arg("--tool-store")
        .arg(tools)
        .args([
            "--node-name",
            "conformance",
            "--max-cells",
            "2",
            "--memory-bytes",
            "268435456",
            "--egress-slots",
            "1",
            "--allow-egress-host",
            "example.com",
        ])
        .stdin(Stdio::null())
        .stdout(log.try_clone().unwrap())
        .stderr(log)
        .spawn()
        .unwrap();
    let mut server = Server {
        child,
        address,
        evidence,
    };
    let started = Instant::now();
    while TcpStream::connect(address).is_err() {
        assert!(
            server.child.try_wait().unwrap().is_none(),
            "dispatcher exited; see {}",
            server.evidence.display()
        );
        assert!(started.elapsed() < Duration::from_secs(5));
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(server.http("GET", "/v1/node", None, "wrong").0, 401);
    let (_, health) = server.http("GET", "/v1/health", None, "");
    assert_eq!(health["ok"], true, "{health}");
    server.save("health", &health);
    let mut request = base;
    request.capabilities.timeout_ms = 15000;
    for (mode, phase, code) in [
        ("silent", "Succeeded", 0),
        ("failed", "Failed", 7),
        ("spoof", "Failed", 9),
        ("fetch-grant", "Succeeded", 0),
    ] {
        request.id = format!("http-{mode}");
        request.invocation.as_mut().unwrap().args = vec![mode.into()];
        request.capabilities.egress = if mode == "fetch-grant" {
            vec!["https://example.com".into()]
        } else {
            vec![]
        };
        server.submit(&request);
        let audit = server.terminal(&request, phase);
        assert_eq!(audit["execution"]["exitCode"], code);
        assert_eq!(audit["execution"]["pilot"]["tool"], request.tools[0].hash);
        assert_eq!(audit["execution"]["pilot"]["lane"], "agent");
        if mode == "silent" {
            assert!(audit["receipt"]["output"].is_null());
        }
        if mode == "fetch-grant" {
            assert_eq!(audit["execution"]["broker"]["denied"], 1);
        }
    }
    request.capabilities.egress.clear();
    for (access, name) in [
        (celln_spec::WorkspaceAccess::None, "none"),
        (celln_spec::WorkspaceAccess::ReadOnly, "read-only"),
        (celln_spec::WorkspaceAccess::ReadWrite, "read-write"),
    ] {
        request.id = format!("http-workspace-{name}");
        request.capabilities.workspace = access;
        request.invocation.as_mut().unwrap().args = vec!["workspace".into(), name.into()];
        server.submit(&request);
        let audit = server.terminal(&request, "Succeeded");
        assert_eq!(audit["execution"]["granted"]["workspace"], name);
    }
    request.id = "http-input".into();
    request.inputs.push(celln_spec::ExecutionInput {
        name: "data".into(),
        hash: celln_manifest::Hash::of(b"first-input").0,
        media_type: "text/plain".into(),
        bytes: 11,
    });
    request.invocation.as_mut().unwrap().args = vec!["inputs".into(), "first-input".into()];
    server.submit(&request);
    let audit = server.terminal(&request, "Succeeded");
    assert_eq!(
        audit["receipt"]["resolved"]["inputs"],
        json!([request.inputs[0].hash])
    );
    request.inputs.clear();
    let mut unapproved = request.clone();
    unapproved.id = "http-unapproved-input".into();
    unapproved.inputs.push(celln_spec::ExecutionInput {
        name: "data".into(),
        hash: celln_manifest::Hash::of(b"unapproved").0,
        media_type: "text/plain".into(),
        bytes: 10,
    });
    server.submit(&unapproved);
    let audit = server.terminal(&unapproved, "Refused");
    assert!(audit["execution"].is_null());
    assert!(audit["receipt"].is_null());
    let mut unsupported = request.clone();
    unsupported.id = "http-unsupported-closure".into();
    unsupported.capabilities.egress = vec!["https://example.com".into()];
    unsupported.tools[0].closure = Some(celln_spec::ImmutableRef {
        hash: celln_manifest::Hash::of(b"closure").0,
    });
    let refusal = server.http(
        "POST",
        "/v1/executions",
        Some(&serde_json::to_value(unsupported).unwrap()),
        TOKEN,
    );
    assert_eq!(refusal.0, 422);
    assert_eq!(refusal.1["reason"], "unsupported");
    server.save("unsupported-closure", &refusal.1);
    request.invocation.as_mut().unwrap().args = vec!["timeout".into()];
    request.capabilities.egress = vec!["https://example.com".into()];
    request.id = "http-cancel".into();
    server.submit(&request);
    let started = Instant::now();
    while crate::cells::live_count(root) == 0 {
        assert!(started.elapsed() < Duration::from_secs(5));
        std::thread::sleep(Duration::from_millis(20));
    }
    std::thread::sleep(Duration::from_millis(300));
    let (_, busy) = server.http("GET", "/v1/node", None, TOKEN);
    assert_eq!(busy["node"]["live_cells"], 1);
    assert_eq!(busy["node"]["memory_bytes"], 0);
    assert_eq!(busy["node"]["egress_slots"], 0);
    server.save("busy-capacity", &busy);
    // Duplicate ID is idempotent; another request cannot overcommit RAM even
    // though the configured two-cell slot limit has room.
    server.submit(&request);
    let mut excess = request.clone();
    excess.id = "http-excess".into();
    assert_eq!(
        server
            .http(
                "POST",
                "/v1/executions",
                Some(&serde_json::to_value(&excess).unwrap()),
                TOKEN
            )
            .0,
        503
    );
    assert_eq!(
        server
            .http("POST", "/v1/executions/http-cancel/cancel", None, "wrong")
            .0,
        401
    );
    assert_eq!(
        server
            .http("POST", "/v1/executions/http-cancel/cancel", None, TOKEN)
            .0,
        202
    );
    let audit = server.terminal(&request, "Cancelled");
    assert!(
        audit["receipt"]["output"].is_object(),
        "guest must have run before cancellation"
    );
    assert_eq!(crate::cells::live_count(root), 0);
    request.id = "http-deadline".into();
    request.capabilities.timeout_ms = 700;
    server.submit(&request);
    let audit = server.terminal(&request, "Failed");
    assert_eq!(audit["execution"]["watchdogStopped"], true);
    assert_eq!(crate::cells::live_count(root), 0);
    // Optional full external-controller proof. The operator explicitly opts
    // into a local executable; ordinary CI never creates a Kubernetes cluster.
    // It receives only this isolated fixture's address/token and pinned request.
    if let Some(proof) = std::env::var_os("CELLN_SYMPOZIUM_PROOF") {
        let mut reference = request.clone();
        reference.capabilities.timeout_ms = 15000;
        reference.capabilities.egress.clear();
        reference.capabilities.workspace = celln_spec::WorkspaceAccess::ReadOnly;
        reference.execution.lane = celln_spec::RequestedLane::Tool;
        reference.invocation.as_mut().unwrap().args = vec!["silent".into()];
        reference.inputs = vec![celln_spec::ExecutionInput {
            name: "data".into(),
            hash: celln_manifest::Hash::of(b"first-input").0,
            media_type: "text/plain".into(),
            bytes: 11,
        }];
        server.save(
            "external-reference",
            &serde_json::to_value(reference).unwrap(),
        );
        let status = Command::new("timeout")
            .args(["--signal=TERM", "--kill-after=10s", "600s"])
            .arg(proof)
            .env("CELLN_ROUTER_URL", format!("http://{}", server.address))
            .env("CELLN_TOKEN_FILE", &token)
            .env("CELLN_PROOF_ROOT", root)
            .env("CELLN_PROOF_BINARY", &binary)
            .env(
                "CELLN_PROOF_REQUEST",
                server.evidence.join("external-reference.json"),
            )
            .env("CELLN_PROOF_EVIDENCE", server.evidence.join("sympozium"))
            .status()
            .expect("start explicitly configured external proof");
        assert!(
            status.success(),
            "external Sympozium proof failed: {status}"
        );
        assert_eq!(crate::cells::live_count(root), 0);
    }
    request.id = "http-revoked-tool".into();
    request.capabilities.timeout_ms = 15000;
    request.invocation.as_mut().unwrap().args = vec!["silent".into()];
    let mut assayer = assay::Assayer::open(root.join("assay")).unwrap();
    let bytes = celln_store::Store::open(tools)
        .unwrap()
        .get(&celln_manifest::Hash(request.tools[0].hash.clone()))
        .unwrap();
    let tool_hash = assayer
        .admit_verified("/tools/program", &bytes, false)
        .unwrap();
    assayer.revoke(&tool_hash);
    server.submit(&request);
    let audit = server.terminal(&request, "Failed");
    assert!(audit["execution"].is_null());
    let (_, refusal) = server.http("GET", "/v1/executions/http-revoked-tool", None, TOKEN);
    assert!(refusal["reason"].as_str().unwrap().contains("revoked"));
    server.save("summary", &json!({"suite": "dispatcher-real-kvm", "status": "passed", "revision": String::from_utf8(Command::new("git").args(["rev-parse", "HEAD"]).current_dir(&repo).output().unwrap().stdout).unwrap().trim(),
        "dirty": !Command::new("git").args(["status", "--porcelain"]).current_dir(&repo).output().unwrap().stdout.is_empty(),
        "binary": celln_manifest::Hash::of(&std::fs::read(&binary).unwrap()).0,
        "host": String::from_utf8(Command::new("uname").args(["-srmo"]).output().unwrap().stdout).unwrap().trim(),
        "cases": ["silent", "failed", "spoof", "fetch-grant", "workspace-none", "workspace-read-only", "workspace-read-write", "immutable-input", "unapproved-input", "unsupported-closure", "cancel", "deadline", "aggregate-memory", "revoked-tool", "audit", "authentication"]}));
    eprintln!(
        "PASS: production dispatcher HTTP conformance; evidence {}",
        server.evidence.display()
    );
}
