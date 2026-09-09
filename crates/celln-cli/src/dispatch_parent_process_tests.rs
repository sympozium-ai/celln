//! Real dispatcher-process qualification; no in-process owner registry.
use super::*;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::process::{Child, Command, Stdio};

struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn http(
    address: std::net::SocketAddr,
    method: &str,
    path: &str,
    token: &str,
    body: &str,
) -> String {
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(3)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    write!(stream,"{method} {path} HTTP/1.1\r\nHost: {address}\r\nAuthorization: Bearer {token}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
    let mut reply = String::new();
    stream.read_to_string(&mut reply).unwrap();
    reply
}

fn start(
    binary: &Path,
    root: &Path,
    address: std::net::SocketAddr,
    token: &Path,
    label: &str,
) -> OwnedChild {
    let log = std::fs::File::create(root.join(format!("dispatcher-{label}.log"))).unwrap();
    let mut child = OwnedChild(
        Command::new(binary)
            .args(["--root"])
            .arg(root)
            .args([
                "dispatcher",
                "--listen",
                &address.to_string(),
                "--token-file",
            ])
            .arg(token)
            .args(["--mote-store"])
            .arg(root.join("motes"))
            .args(["--tool-store"])
            .arg(root.join("tools"))
            .args([
                "--max-cells",
                "2",
                "--memory-bytes",
                "2147483648",
                "--egress-slots",
                "1",
            ])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "dispatcher exited before readiness"
        );
        if TcpStream::connect_timeout(&address, Duration::from_millis(50)).is_ok() {
            break;
        }
        assert!(Instant::now() < deadline, "dispatcher readiness timed out");
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(http(address, "GET", "/v1/health", "", "").starts_with("HTTP/1.1 200"));
    child
}

pub(super) fn prove(root: &Path, borrowed: bool, binary: &Path) -> Vec<serde_json::Value> {
    // Explicit private retention of real guest events for this qualification.
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(root.join("parent-audit"))
        .unwrap();
    assert!(binary.is_absolute() && binary.is_file());
    assert!(
        std::env::var_os("CELLN_INTEROP_PROVISION_BINARY").is_some(),
        "real dispatcher requires fresh issuance mode"
    );
    let client = std::env::var_os("CELLN_PARENT_INTEROP_BINARY").expect("external client required");
    let parent_token = "parent-process-proof-credential-24";
    let dispatcher_token = "dispatcher-process-proof-distinct-24";
    super::tests::policy(root, parent_token, "test:parent");
    let parent_path = root.join("interop-token");
    let dispatcher_path = root.join("dispatcher-token");
    for (path, value) in [
        (&parent_path, parent_token),
        (&dispatcher_path, dispatcher_token),
    ] {
        std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .unwrap()
            .write_all(value.as_bytes())
            .unwrap();
    }
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let dispatcher = start(binary, root, address, &dispatcher_path, "live");
    eprintln!("real dispatcher process started: {}", dispatcher.0.id());
    let result_path = root.join("interop-results.json");
    let hold = std::env::var("CELLN_INTEROP_HOLD_SECONDS")
        .map(|value| value.parse::<u64>().expect("integer hold seconds"))
        .unwrap_or(0);
    assert!(hold <= 43200, "hold seconds exceed development bound");
    let timeout = if hold == 0 { 100 } else { hold + 190 };
    let go_timeout = format!("{timeout}s");
    let mut go = OwnedChild(
        Command::new(client)
            .args([
                "-test.run",
                "^TestLiveCellnParentClient$",
                "-test.v",
                "-test.timeout",
                &go_timeout,
            ])
            .env("CELLN_INTEROP_ORIGIN", format!("http://{address}"))
            .env("CELLN_INTEROP_TOKEN_FILE", &parent_path)
            .env("CELLN_INTEROP_BORROWED", borrowed.to_string())
            .env("CELLN_INTEROP_RESULT", &result_path)
            .env_remove("CELLN_INTEROP_LAUNCH")
            .env_remove("CELLN_INTEROP_PARENT")
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(timeout + 5);
    loop {
        if let Some(status) = go.0.try_wait().unwrap() {
            assert!(status.success(), "external process driver failed");
            break;
        }
        assert!(
            Instant::now() < deadline,
            "external process driver timed out"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let results: Vec<serde_json::Value> =
        serde_json::from_slice(&std::fs::read(result_path).unwrap()).unwrap();
    assert_eq!(results.len(), 2);
    let mut records = vec![serde_json::from_slice::<serde_json::Value>(
        &std::fs::read(root.join("interop-provisioned.json")).unwrap(),
    )
    .unwrap()];
    if std::env::var("CELLN_INTEROP_REUSE_TEMPLATE").as_deref() == Ok("true") {
        records.push(
            serde_json::from_slice(&std::fs::read(root.join("interop-reused.json")).unwrap())
                .unwrap(),
        );
    }
    if hold > 0 {
        records.push(
            serde_json::from_slice(&std::fs::read(root.join("hands-on.json")).unwrap()).unwrap(),
        );
    }
    for record in &records {
        let id = record["incarnation"].as_str().unwrap();
        let stopped = http(
            address,
            "POST",
            &format!("/v1/parents/{id}/stop"),
            parent_token,
            "",
        );
        assert!(
            stopped.starts_with("HTTP/1.1 200") && stopped.contains("\"teardownConfirmed\":true"),
            "{stopped}"
        );
        let body =
            json!({"apiVersion":"celln.parent-create/v1","launchProfile":record["launchProfile"]})
                .to_string();
        assert!(
            http(address, "POST", "/v1/parents", parent_token, &body).starts_with("HTTP/1.1 409")
        );
        assert!(http(
            address,
            "GET",
            &format!("/v1/parents/{id}"),
            dispatcher_token,
            ""
        )
        .starts_with("HTTP/1.1 401"));
    }
    let response = http(address, "GET", "/v1/capabilities", dispatcher_token, "");
    assert!(response.starts_with("HTTP/1.1 200"));
    let capacity: crate::capabilities::DispatcherCapabilities =
        serde_json::from_str(response.split_once("\r\n\r\n").unwrap().1).unwrap();
    assert_eq!(capacity.node.live_cells, 0);
    assert_eq!(capacity.node.memory_bytes, 2u64 << 30);
    // Dispatcher has no shutdown API; stop only after every parent joined.
    drop(dispatcher);
    let recovered = start(binary, root, address, &dispatcher_path, "recovered");
    for record in &records {
        let id = record["incarnation"].as_str().unwrap();
        let path = format!("/v1/parents/{id}");
        let status = http(address, "GET", &path, parent_token, "");
        assert!(
            status.starts_with("HTTP/1.1 200")
                && status.contains("ContextLost")
                && status.contains("\"statusIsLiveOwnerObservation\":false"),
            "{status}"
        );
        for action in ["turns", "stop", "cancel"] {
            assert!(http(
                address,
                "POST",
                &format!("{path}/{action}"),
                parent_token,
                "{}"
            )
            .starts_with("HTTP/1.1 409"));
        }
    }
    drop(recovered);
    std::fs::write(root.join("dispatcher-process-proof.json"),serde_json::to_vec_pretty(&json!({"parents":records.len(),"joinedBeforeProcessStop":true,"capacityReclaimed":true,"restartHistoricalOnly":true})).unwrap()).unwrap();
    std::fs::remove_file(parent_path).unwrap();
    std::fs::remove_file(dispatcher_path).unwrap();
    results
}
