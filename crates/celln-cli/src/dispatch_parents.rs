//! Experimental lifecycle routes. Creation selects an operator-owned profile;
//! no enduring capability is advertised until deployed integration is proven.
//! Parent routes deliberately do not accept the shared dispatcher credential.
use super::*;
use celln_manifest::Hash;
use serde_json::json;

#[cfg(all(test, target_os = "linux"))]
#[path = "dispatch_parent_process_tests.rs"]
mod process_tests;

/// Test/internal capacity gate. Creation uses spawn_after_check to claim its
/// durable identity after the same one-shot/prewarm capacity check. Artifact
/// preparation then runs on the reserved owner thread before parent launch.
#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn spawn_admitted<F, H>(
    state: &State,
    principal: &str,
    incarnation: &Hash,
    lifetime: Duration,
    reservation: Reservation,
    initialize: F,
) -> Result<()>
where
    F: FnOnce() -> std::result::Result<H, String> + Send + 'static,
    H: FnMut(&[u8]) -> std::result::Result<Vec<u8>, String> + 'static,
{
    spawn_after_check(state, principal, incarnation, lifetime, reservation, || {
        Ok(move |_| initialize())
    })
}

fn spawn_after_check<A, F, H>(
    state: &State,
    principal: &str,
    incarnation: &Hash,
    lifetime: Duration,
    reservation: Reservation,
    admit: A,
) -> Result<()>
where
    A: FnOnce() -> Result<F>,
    F: FnOnce(
            Arc<warden::parent_child_control::ChildControlSlot>,
        ) -> std::result::Result<H, String>
        + Send
        + 'static,
    H: FnMut(&[u8]) -> std::result::Result<Vec<u8>, String> + 'static,
{
    let registry = state
        .executions
        .lock()
        .map_err(|_| anyhow::anyhow!("dispatcher capacity unavailable"))?;
    let node = current_node(state, &registry);
    if node.max_cells.saturating_sub(node.live_cells) < 2
        || reservation.memory_bytes == 0
        || reservation.memory_bytes > node.memory_bytes
        || reservation.egress_slots > node.egress_slots
    {
        bail!("parent capacity exhausted");
    }
    let initialize = admit()?;
    state
        .parents
        .spawn_admitted_with_children(
            principal,
            incarnation,
            lifetime,
            reservation.memory_bytes,
            initialize,
        )
        .map_err(anyhow::Error::msg)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Clients {
    api_version: String,
    clients: Vec<Client>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Client {
    principal: String,
    token_hash: String,
}

fn hash_valid(hash: &str) -> bool {
    hash.strip_prefix("blake3:").is_some_and(|s| {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// Reopen on every operation so rotation/revocation takes effect without a
/// dispatcher restart. Operator file contains hashes of high-entropy bearer
/// secrets, not plaintext credentials; it is never an uploadable store object.
fn authenticate(root: &Path, bearer: Option<&str>) -> Result<Option<String>> {
    let mut bytes = Vec::new();
    std::fs::File::open(root.join("trusted-parent-clients.json"))?
        .take(65537)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 65536 {
        bail!("parent client policy exceeds bound");
    }
    let clients: Clients = serde_json::from_slice(&bytes)?;
    if clients.api_version != "celln.parent-clients/v1" || clients.clients.len() > 128 {
        bail!("invalid parent client policy");
    }
    let mut seen = BTreeSet::new();
    for client in &clients.clients {
        if client.principal.is_empty()
            || client.principal.len() > 512
            || client.principal.chars().any(char::is_control)
            || !hash_valid(&client.token_hash)
            || !seen.insert(&client.token_hash)
        {
            bail!("invalid parent client policy");
        }
    }
    let Some(bearer) = bearer
        .filter(|b| (24..=4096).contains(&b.len()) && b.bytes().all(|c| c.is_ascii_graphic()))
    else {
        return Ok(None);
    };
    let digest = Hash::of(bearer.as_bytes());
    let mut principal = None;
    // Scan every entry; do not return at the first matching credential.
    for client in clients.clients {
        if constant_time_eq(client.token_hash.as_bytes(), digest.0.as_bytes()) {
            principal = Some(client.principal);
        }
    }
    Ok(principal)
}

pub(super) struct RequestMetadata<'a> {
    pub length: usize,
    pub bearer: Option<&'a str>,
    pub respond_async: bool,
}

pub(super) fn handle(
    state: &State,
    stream: &mut TcpStream,
    reader: &mut impl Read,
    method: &str,
    path: &str,
    metadata: RequestMetadata<'_>,
) -> Result<()> {
    let RequestMetadata {
        length,
        bearer,
        respond_async,
    } = metadata;
    let principal = match authenticate(&state.root, bearer) {
        Ok(Some(principal)) => principal,
        Ok(None) => return reply(stream, 401, &json!({"error":"unauthorized"})),
        Err(_) => {
            return reply(
                stream,
                503,
                &json!({"error":"parent authentication unavailable"}),
            )
        }
    };
    if path == "/v1/parents" {
        if method != "POST" {
            return reply(stream, 404, &json!({"error":"not found"}));
        }
        return create(state, stream, reader, length, &principal);
    }
    let mut parts = path.trim_start_matches("/v1/parents/").split('/');
    let id = parts.next().unwrap_or_default();
    let action = parts.next();
    let turn = parts.next();
    let turn_action = parts.next();
    if !hash_valid(id)
        || parts.next().is_some()
        || (turn.is_some() && action != Some("turns"))
        || (turn_action.is_some() && turn_action != Some("cancel"))
    {
        return reply(stream, 404, &json!({"error":"parent owner not found"}));
    }
    let id = Hash(id.into());
    let (status, live_observation) = match state.parents.status(&principal, &id) {
        Ok(status) => (status, true),
        Err(_)
            if warden::parent_journal::historical_owner(
                &state.root.join("parent-journal"),
                &id,
                &principal,
            )
            .unwrap_or(false) =>
        {
            // Durable ownership permits reading evidence, never turn delivery,
            // cancellation or a claim that teardown was confirmed after restart.
            if method != "GET" {
                return reply(
                    stream,
                    409,
                    &json!({"error":"live parent unavailable; context lost",
                    "retryAuthorized":false,"teardownConfirmed":false}),
                );
            }
            (warden::parent_registry::Status::ContextLost, false)
        }
        Err(_) => return reply(stream, 404, &json!({"error":"parent owner not found"})),
    };
    if let Some(turn) = turn {
        if turn.is_empty()
            || turn.len() > 64
            || !turn
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
        {
            return reply(stream, 404, &json!({"error":"turn not found"}));
        }
        if method == "POST" && turn_action == Some("cancel") {
            if length != 0 {
                return reply(
                    stream,
                    400,
                    &json!({"error":"cancellation body must be empty"}),
                );
            }
            // The immutable parent/turn pair selects exactly one child. Never
            // interpret this as "cancel whichever child is active now".
            let identity = warden::parent_child_control::Identity {
                child: Hash::of(&serde_json::to_vec(&(&id.0, turn))?),
                parent: id,
                turn: turn.into(),
            };
            return match state.parents.cancel_child(&principal, &identity) {
                Ok(()) => reply(
                    stream,
                    202,
                    &json!({"cancellationRequested":true,
                    "teardownConfirmed":false,"retryAuthorized":false}),
                ),
                Err(_) => reply(
                    stream,
                    409,
                    &json!({"error":"exact live child unavailable",
                    "teardownConfirmed":false,"retryAuthorized":false}),
                ),
            };
        }
        if method != "GET" || turn_action.is_some() {
            return reply(stream, 404, &json!({"error":"turn not found"}));
        }
        return match warden::parent_journal::inspect_turn(
            &state.root.join("parent-journal"),
            &id,
            turn,
        ) {
            Ok(record) => reply(
                stream,
                200,
                &json!({"turn":record,"retryAuthorized":false,"ownerStatus":format!("{status:?}")}),
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => reply(
                stream,
                404,
                &json!({"error":"turn not found","retryAuthorized":false}),
            ),
            Err(_) => reply(
                stream,
                503,
                &json!({"error":"turn journal unavailable","retryAuthorized":false}),
            ),
        };
    }
    match (method, action) {
        ("GET", None) => reply(
            stream,
            200,
            &json!({"incarnation":id.0,"status":format!("{status:?}"),"statusIsLiveOwnerObservation":live_observation,"retryAuthorized":false}),
        ),
        ("POST", Some("cancel")) => {
            state
                .parents
                .cancel(&principal, &id)
                .map_err(anyhow::Error::msg)?;
            reply(
                stream,
                202,
                &json!({"cancellationRequested":true,"teardownConfirmed":false}),
            )
        }
        ("POST", Some("stop")) => match state.parents.stop(&principal, &id) {
            Ok(()) => reply(stream, 200, &json!({"teardownConfirmed":true})),
            Err(_) => reply(
                stream,
                409,
                &json!({"error":"parent teardown pending or uncertain"}),
            ),
        },
        ("POST", Some("turns")) => {
            if length == 0 || length > warden::parent_mailbox::MAX_FRAME_BYTES {
                return reply(stream, 413, &json!({"error":"invalid turn size"}));
            }
            let mut bytes = vec![0; length];
            stream.set_read_timeout(Some(Duration::from_secs(5)))?;
            reader.read_exact(&mut bytes)?;
            let pending = match state.parents.submit(&principal, &id, &bytes) {
                Ok(pending) => pending,
                Err(_) => {
                    return reply(
                        stream,
                        409,
                        &json!({"error":"parent unavailable or turn active; reconcile original turn"}),
                    )
                }
            };
            if respond_async {
                // Dropping the response receiver does not cancel the admitted
                // owner. Its durable journal remains the source of completion.
                return reply(
                    stream,
                    202,
                    &json!({"pending":true,"retryAuthorized":false}),
                );
            }
            match pending.recv_timeout(Duration::from_secs(30)) {
                Ok(Ok(bytes)) => reply(
                    stream,
                    200,
                    &serde_json::from_slice::<serde_json::Value>(&bytes)?,
                ),
                Ok(Err(_)) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => reply(
                    stream,
                    409,
                    &json!({"error":"turn failed or context lost; reconcile original turn"}),
                ),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => reply(
                    stream,
                    202,
                    &json!({"pending":true,"retryAuthorized":false}),
                ),
            }
        }
        _ => reply(stream, 404, &json!({"error":"not found"})),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CreateRequest {
    api_version: String,
    launch_profile: Hash,
}

/// Explicit hardware proof uses the actual authenticated HTTP request handler,
/// capacity gate, durable claim, registry, turn delivery and joined stop.
#[cfg(all(test, target_os = "linux"))]
pub(crate) fn prove_parent_http(
    root: &Path,
    launch: &Hash,
    id: &Hash,
    borrowed: bool,
    cancel: bool,
) -> Vec<serde_json::Value> {
    if let Some(binary) = std::env::var_os("CELLN_INTEROP_DISPATCHER_BINARY") {
        return process_tests::prove(root, borrowed, Path::new(&binary));
    }
    let mut state = super::tests::lifecycle_state(root);
    state.probe.max_cells = 2;
    state.probe.memory_bytes = 2u64 << 30;
    state.probe.egress_slots = 1;
    state.parents = warden::parent_registry::ParentRegistry::new(4, 2u64 << 30).unwrap();
    let token = "parent-hardware-http-proof-credential";
    tests::policy(root, token, "test:parent");
    let body = json!({"apiVersion":"celln.parent-create/v1","launchProfile":launch}).to_string();
    let replies = if let Some(binary) = std::env::var_os("CELLN_PARENT_INTEROP_BINARY") {
        prove_external_client(
            &state,
            root,
            launch,
            id,
            borrowed,
            Path::new(&binary),
            token,
        )
    } else {
        let created = tests::http(&state, "POST", "/v1/parents", token, &body);
        assert!(created.starts_with("HTTP/1.1 202"), "{created}");
        let ready_deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let response = tests::http(&state, "GET", &format!("/v1/parents/{}", id.0), token, "");
            assert!(response.starts_with("HTTP/1.1 200"), "{response}");
            if response.contains("\"status\":\"Ready\"") {
                break;
            }
            assert!(
                response.contains("\"status\":\"Initializing\""),
                "{response}"
            );
            assert!(Instant::now() < ready_deadline, "parent never became ready");
            std::thread::sleep(Duration::from_millis(10));
        }
        let mut replies = Vec::new();
        let messages = if borrowed {
            [("one", "My value is violet. Call uppercase with my value and answer only the tool result text."),
         ("two", "Find the value stated in the first user message of this conversation. Call uppercase on that value now. Answer only the tool result text.")]
        } else {
            [
                ("one", "My value is violet. Remember it."),
                (
                    "two",
                    "What was my original value? Reply with that value only.",
                ),
            ]
        };
        for (turn, message) in messages {
            if cancel && turn == "two" {
                prove_cancelled_model_child(&state, root, id, token);
            }
            let response = tests::http(
                &state,
                "POST",
                &format!("/v1/parents/{}/turns", id.0),
                token,
                &json!({"kind":"turn","apiVersion":pilot::parent_harness::VERSION,
                "turnId":turn,"message":message})
                .to_string(),
            );
            assert!(response.starts_with("HTTP/1.1 200"), "{response}");
            let reply: serde_json::Value =
                serde_json::from_str(response.split_once("\r\n\r\n").unwrap().1).unwrap();
            assert_eq!(reply["succeeded"], true);
            if turn == "two" {
                assert!(reply["answer"]
                    .as_str()
                    .unwrap()
                    .to_lowercase()
                    .contains("violet"));
            }
            replies.push(reply);
        }
        replies
    };
    let provisioned: Option<serde_json::Value> = std::env::var_os("CELLN_INTEROP_PROVISION_BINARY")
        .map(|_| {
            serde_json::from_slice(&std::fs::read(root.join("interop-provisioned.json")).unwrap())
                .unwrap()
        });
    let provisioned_id: Hash;
    let provisioned_launch: Hash;
    let (id, body) = if let Some(record) = provisioned {
        provisioned_id = serde_json::from_value(record["incarnation"].clone()).unwrap();
        provisioned_launch = serde_json::from_value(record["launchProfile"].clone()).unwrap();
        (
            &provisioned_id,
            json!({"apiVersion":"celln.parent-create/v1","launchProfile":provisioned_launch})
                .to_string(),
        )
    } else {
        (id, body)
    };
    let stopped = tests::http(
        &state,
        "POST",
        &format!("/v1/parents/{}/stop", id.0),
        token,
        "",
    );
    assert!(stopped.starts_with("HTTP/1.1 200"), "{stopped}");
    assert!(stopped.contains("\"teardownConfirmed\":true"));
    assert_eq!(state.parents.reserved_capacity().unwrap().owners, 0);
    if std::env::var("CELLN_INTEROP_REUSE_TEMPLATE").as_deref() == Ok("true") {
        let second: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.join("interop-reused.json")).unwrap())
                .unwrap();
        let second_id = second["incarnation"].as_str().unwrap();
        let stopped = tests::http(
            &state,
            "POST",
            &format!("/v1/parents/{second_id}/stop"),
            token,
            "",
        );
        assert!(
            stopped.starts_with("HTTP/1.1 200") && stopped.contains("\"teardownConfirmed\":true")
        );
        let replay =
            json!({"apiVersion":"celln.parent-create/v1","launchProfile":second["launchProfile"]})
                .to_string();
        assert!(
            tests::http(&state, "POST", "/v1/parents", token, &replay).starts_with("HTTP/1.1 409")
        );
    }
    assert!(tests::http(&state, "POST", "/v1/parents", token, &body).starts_with("HTTP/1.1 409"));
    // Fresh serving state has no live-owner entries. Durable ownership grants
    // historical reads only, including after operator admission expiry.
    let recovered = super::tests::lifecycle_state(root);
    let path = format!("/v1/parents/{}", id.0);
    let status = tests::http(&recovered, "GET", &path, token, "");
    assert!(status.starts_with("HTTP/1.1 200"), "{status}");
    assert!(
        status.contains("ContextLost") && status.contains("\"statusIsLiveOwnerObservation\":false")
    );
    assert_eq!(replies.len(), 2);
    for result in &replies {
        let turn = result["turnId"].as_str().unwrap();
        let response = tests::http(
            &recovered,
            "GET",
            &format!("{path}/turns/{turn}"),
            token,
            "",
        );
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.contains("parent-committed") && response.contains("ContextLost"));
    }
    for action in ["turns", "stop", "cancel"] {
        let response = tests::http(&recovered, "POST", &format!("{path}/{action}"), token, "{}");
        assert!(response.starts_with("HTTP/1.1 409"), "{response}");
        assert!(response.contains("\"retryAuthorized\":false"));
    }
    tests::policy(root, token, "unrelated-tenant");
    assert!(tests::http(&recovered, "GET", &path, token, "").starts_with("HTTP/1.1 404"));
    assert!(tests::http(
        &recovered,
        "GET",
        &format!("{path}/turns/{}", replies[0]["turnId"].as_str().unwrap()),
        token,
        ""
    )
    .starts_with("HTTP/1.1 404"));
    replies
}

// Observe only owned subprocess IDs and executable names, never model request
// arguments or credential files. This proves interruption during model
// transport, not that the remote provider received or billed the request.
#[cfg(all(test, target_os = "linux"))]
fn prove_cancelled_model_child(state: &State, root: &Path, id: &Hash, token: &str) {
    let body = json!({"kind":"turn","apiVersion":pilot::parent_harness::VERSION,
        "turnId":"cancelled","message":"My value is orange. Call uppercase on my value."})
    .to_string();
    let pending = state
        .parents
        .submit("test:parent", id, body.as_bytes())
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    let curl = loop {
        let mut found = None;
        for task in std::fs::read_dir("/proc/self/task").unwrap().flatten() {
            let children =
                std::fs::read_to_string(task.path().join("children")).unwrap_or_default();
            for pid in children.split_whitespace() {
                if std::fs::read_to_string(format!("/proc/{pid}/comm"))
                    .unwrap_or_default()
                    .trim()
                    == "curl"
                {
                    found = Some(pid.to_owned());
                }
            }
        }
        if let Some(pid) = found {
            break pid;
        }
        assert!(
            Instant::now() < deadline,
            "model transport never became observable"
        );
        std::thread::sleep(Duration::from_millis(1));
    };
    let response = tests::http(
        state,
        "POST",
        &format!("/v1/parents/{}/turns/cancelled/cancel", id.0),
        token,
        "",
    );
    assert!(response.starts_with("HTTP/1.1 202"), "{response}");
    let reply = pending
        .recv_timeout(Duration::from_secs(10))
        .unwrap()
        .unwrap();
    let reply: serde_json::Value = serde_json::from_slice(&reply).unwrap();
    assert_eq!(reply["succeeded"], false);
    assert_eq!(reply["answer"], "Turn cancelled after child teardown.");
    assert!(
        !Path::new(&format!("/proc/{curl}")).exists(),
        "model subprocess not joined"
    );
    assert_eq!(
        state.parents.status("test:parent", id).unwrap(),
        warden::parent_registry::Status::Ready
    );
    assert!(matches!(
        warden::parent_journal::inspect_turn(&root.join("parent-journal"), id, "cancelled")
            .unwrap(),
        warden::parent_journal::TurnStatus::ParentCommitted(_)
    ));
    std::fs::write(root.join("cancelled-model-proof.json"), serde_json::to_vec(&json!({"parent":id,"turn":reply,"modelTransportObserved":true,"modelProcessJoined":true,"parentReady":true})).unwrap()).unwrap();
}

/// Test-only bridge: serve the real handler to a separately built client.
/// The executable is explicitly operator-selected, never request supplied.
#[cfg(all(test, target_os = "linux"))]
fn prove_external_client(
    state: &State,
    root: &Path,
    launch: &Hash,
    id: &Hash,
    borrowed: bool,
    binary: &Path,
    token: &str,
) -> Vec<serde_json::Value> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::sync::atomic::{AtomicBool, Ordering};
    assert!(binary.is_absolute() && binary.is_file());
    let token_path = root.join("interop-token");
    let result_path = root.join("interop-results.json");
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&token_path)
        .unwrap()
        .write_all(token.as_bytes())
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let mut child = std::process::Command::new(binary)
        .args([
            "-test.run",
            "^TestLiveCellnParentClient$",
            "-test.v",
            "-test.timeout",
            "100s",
        ])
        .env("CELLN_INTEROP_ORIGIN", origin)
        .env("CELLN_INTEROP_TOKEN_FILE", &token_path)
        .env("CELLN_INTEROP_LAUNCH", &launch.0)
        .env("CELLN_INTEROP_PARENT", &id.0)
        .env("CELLN_INTEROP_BORROWED", borrowed.to_string())
        .env("CELLN_INTEROP_RESULT", &result_path)
        .spawn()
        .unwrap();
    let done = AtomicBool::new(false);
    let status = std::thread::scope(|scope| {
        let server = scope.spawn(|| {
            while !done.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        super::handle(stream, state).unwrap();
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5))
                    }
                    Err(e) => panic!("interop accept: {e}"),
                }
            }
        });
        let deadline = Instant::now() + Duration::from_secs(105);
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Ok(status),
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10))
                }
                other => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break Err(format!("interop child timeout/wait: {other:?}"));
                }
            }
        };
        done.store(true, Ordering::Release);
        server.join().unwrap();
        status
    });
    std::fs::remove_file(token_path).unwrap();
    assert!(status.unwrap().success(), "external parent client failed");
    serde_json::from_slice(&std::fs::read(result_path).unwrap()).unwrap()
}

fn create(
    state: &State,
    stream: &mut TcpStream,
    reader: &mut impl Read,
    length: usize,
    principal: &str,
) -> Result<()> {
    if length == 0 || length > 1024 {
        return reply(stream, 413, &json!({"error":"invalid creation size"}));
    }
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut bytes = vec![0; length];
    reader.read_exact(&mut bytes)?;
    let request = match serde_json::from_slice::<CreateRequest>(&bytes) {
        Ok(request)
            if request.api_version == "celln.parent-create/v1"
                && hash_valid(&request.launch_profile.0) =>
        {
            request
        }
        _ => {
            return reply(
                stream,
                400,
                &json!({"error":"invalid parent creation request"}),
            )
        }
    };
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (state, principal, request);
        reply(
            stream,
            503,
            &json!({"error":"parent creation unsupported on this host"}),
        )
    }
    #[cfg(target_os = "linux")]
    {
        let admission = match crate::dispatch::parent_create::admit(
            &state.root,
            &request.launch_profile,
            principal,
        ) {
            Ok(admission) => admission,
            Err(_) => {
                return reply(
                    stream,
                    403,
                    &json!({"error":"parent launch not authorized"}),
                )
            }
        };
        let id = admission.incarnation().clone();
        let lifetime = admission.lifetime();
        let reservation = Reservation {
            memory_bytes: admission.reserved_memory_bytes(),
            egress_slots: 1,
        };
        // Claim is serialized after capacity checks but before owner creation.
        // Any subsequent failure is non-retryable for this incarnation.
        match spawn_after_check(state, principal, &id, lifetime, reservation, || {
            admission.claim(principal).map_err(anyhow::Error::msg)
        }) {
            Ok(()) => reply(
                stream,
                202,
                &json!({"incarnation":id.0,
                "initializationPending":true,"retryAuthorized":false}),
            ),
            Err(_) => reply(
                stream,
                409,
                &json!({"error":"parent creation refused; reconcile incarnation",
                "incarnation":id.0,"retryAuthorized":false}),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_turn_http_cancel_preserves_parent_and_rejects_stale_requests() {
        let root = tempfile::tempdir().unwrap();
        let state = super::super::tests::lifecycle_state(root.path());
        let token = "child-cancel-http-test-credential";
        policy(root.path(), token, "tenant");
        let id = Hash::of(b"child-cancel-http");
        let bound = id.clone();
        let (entered, ready) = std::sync::mpsc::sync_channel(1);
        state
            .parents
            .spawn_admitted_with_children(
                "tenant",
                &id,
                Duration::from_secs(30),
                4096,
                move |children| {
                    Ok(move |bytes: &[u8]| {
                        let turn = String::from_utf8(bytes.to_vec()).map_err(|e| e.to_string())?;
                        let reserved = warden::parent_lease::ReservedTurn {
                            parent: bound.clone(),
                            child: Hash::of(&serde_json::to_vec(&(&bound.0, &turn)).unwrap()),
                            request: warden::parent_protocol::TurnRequest {
                                api_version: warden::parent_protocol::VERSION.into(),
                                turn_id: turn,
                                task: "test".into(),
                            },
                            limits: warden::parent_lease::TurnLimits {
                                memory_bytes: 4096,
                                timeout: Duration::from_secs(5),
                                model_requests: 0,
                                output_tokens: 0,
                            },
                        };
                        let (identity, control) = children.register(&reserved)?;
                        entered.send(()).map_err(|e| e.to_string())?;
                        while control.check().is_ok() {
                            std::thread::sleep(Duration::from_millis(1));
                        }
                        celln_control::check().map_err(|e| e.to_string())?;
                        // Synthetic worker: routing proof only, not VM teardown proof.
                        children.retire(&identity)?;
                        Ok(b"cancelled".to_vec())
                    })
                },
            )
            .unwrap();
        let path = format!("/v1/parents/{}/turns", id.0);
        for turn in ["first", "second"] {
            let pending = state
                .parents
                .submit("tenant", &id, turn.as_bytes())
                .unwrap();
            ready.recv_timeout(Duration::from_secs(2)).unwrap();
            let exact = format!("{path}/{turn}/cancel");
            assert!(http(&state, "POST", &exact, "wrong-token", "").starts_with("HTTP/1.1 401"));
            assert!(http(&state, "GET", &exact, token, "").starts_with("HTTP/1.1 404"));
            assert!(http(&state, "POST", &exact, token, "{}").starts_with("HTTP/1.1 400"));
            assert!(
                http(&state, "POST", &format!("{path}/missing/cancel"), token, "")
                    .starts_with("HTTP/1.1 409")
            );
            if turn == "second" {
                assert!(
                    http(&state, "POST", &format!("{path}/first/cancel"), token, "")
                        .starts_with("HTTP/1.1 409")
                );
            }
            assert!(pending.try_recv().is_err());
            let response = http(&state, "POST", &exact, token, "");
            assert!(response.starts_with("HTTP/1.1 202"), "{response}");
            assert!(response.contains("\"teardownConfirmed\":false"));
            assert_eq!(
                pending
                    .recv_timeout(Duration::from_secs(2))
                    .unwrap()
                    .unwrap(),
                b"cancelled"
            );
            assert_eq!(
                state.parents.status("tenant", &id).unwrap(),
                warden::parent_registry::Status::Ready
            );
            assert_eq!(
                state.parents.reserved_capacity().unwrap().memory_bytes,
                4096
            );
        }
        state.parents.stop("tenant", &id).unwrap();
    }
    #[test]
    fn historical_http_access_is_read_only_and_requires_durable_owner() {
        let root = tempfile::tempdir().unwrap();
        let state = super::super::tests::lifecycle_state(root.path());
        let token = "historical-http-test-credential";
        policy(root.path(), token, "tenant");
        let id = Hash::of(b"historical-http");
        let journal = warden::parent_journal::ParentJournal::create(
            &root.path().join("parent-journal"),
            id.clone(),
        )
        .unwrap();
        let path = format!("/v1/parents/{}", id.0);
        assert!(http(&state, "GET", &path, token, "").starts_with("HTTP/1.1 404"));
        journal.bind_owner("tenant").unwrap();
        let response = http(&state, "GET", &path, token, "");
        assert!(response.starts_with("HTTP/1.1 200") && response.contains("ContextLost"));
        for action in ["turns", "stop", "cancel"] {
            assert!(
                http(&state, "POST", &format!("{path}/{action}"), token, "{}")
                    .starts_with("HTTP/1.1 409")
            );
        }
        policy(root.path(), token, "another");
        assert!(http(&state, "GET", &path, token, "").starts_with("HTTP/1.1 404"));
        assert_eq!(state.parents.reserved_capacity().unwrap().owners, 0);
    }
    pub(super) fn policy(root: &Path, token: &str, principal: &str) {
        std::fs::write(root.join("trusted-parent-clients.json"), json!({"apiVersion":"celln.parent-clients/v1", "clients":[{"principal":principal,"tokenHash":Hash::of(token.as_bytes()).0}]}).to_string()).unwrap();
    }
    #[test]
    fn creation_accepts_only_bounded_operator_profile_selection() {
        let root = tempfile::tempdir().unwrap();
        let state = super::super::tests::lifecycle_state(root.path());
        let token = "parent-create-test-credential-long-enough";
        policy(root.path(), token, "tenant");
        for body in [
            "{}".to_string(),
            json!({"apiVersion":"celln.parent-create/v1",
            "launchProfile":"../../elsewhere"})
            .to_string(),
            json!({"apiVersion":"celln.parent-create/v1","launchProfile":Hash::of(b"launch"),
                "principal":"someone-else"})
            .to_string(),
        ] {
            assert!(http(&state, "POST", "/v1/parents", token, &body).starts_with("HTTP/1.1 400"));
        }
        assert!(
            http(&state, "POST", "/v1/parents", token, &"x".repeat(1025))
                .starts_with("HTTP/1.1 413")
        );
        #[cfg(target_os = "linux")]
        assert!(http(
            &state,
            "POST",
            "/v1/parents",
            token,
            &json!({"apiVersion":"celln.parent-create/v1","launchProfile":Hash::of(b"missing")})
                .to_string()
        )
        .starts_with("HTTP/1.1 403"));
        assert!(!root.path().join("parent-journal").exists());
        assert_eq!(state.parents.reserved_capacity().unwrap().owners, 0);
    }
    pub(super) fn http(state: &State, method: &str, path: &str, token: &str, body: &str) -> String {
        http_preference(state, method, path, token, body, false)
    }

    fn http_preference(
        state: &State,
        method: &str,
        path: &str,
        token: &str,
        body: &str,
        respond_async: bool,
    ) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let prefer = if respond_async {
            "Prefer: respond-async\r\n"
        } else {
            ""
        };
        write!(client, "{method} {path} HTTP/1.1\r\nAuthorization: Bearer {token}\r\n{prefer}Content-Length: {}\r\n\r\n{body}", body.len()).unwrap();
        let (server, _) = listener.accept().unwrap();
        super::super::handle(server, state).unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        response
    }
    #[test]
    fn async_turn_acknowledges_before_worker_completion_without_cancelling_owner() {
        let root = tempfile::tempdir().unwrap();
        let state = super::super::tests::lifecycle_state(root.path());
        let token = "async-parent-test-credential";
        policy(root.path(), token, "tenant");
        let id = Hash::of(b"async-parent");
        let (release, wait) = std::sync::mpsc::sync_channel(1);
        let (finished, done) = std::sync::mpsc::sync_channel(1);
        state
            .parents
            .spawn_admitted("tenant", &id, Duration::from_secs(10), 4096, move || {
                Ok(move |_: &[u8]| {
                    wait.recv_timeout(Duration::from_secs(2))
                        .map_err(|e| e.to_string())?;
                    celln_control::check().map_err(|e| e.to_string())?;
                    finished.send(()).unwrap();
                    Ok(vec![])
                })
            })
            .unwrap();
        let response = http_preference(
            &state,
            "POST",
            &format!("/v1/parents/{}/turns", id.0),
            token,
            "{}",
            true,
        );
        assert!(response.starts_with("HTTP/1.1 202"), "{response}");
        assert!(response.contains("\"pending\":true"));
        assert!(done.try_recv().is_err());
        assert_eq!(
            state.parents.reserved_capacity().unwrap().memory_bytes,
            4096
        );
        release.send(()).unwrap();
        done.recv_timeout(Duration::from_secs(2)).unwrap();
        state.parents.stop("tenant", &id).unwrap();
    }
    #[test]
    fn parent_capacity_gate_serializes_competitors_and_respects_prewarm() {
        type Handler = fn(&[u8]) -> std::result::Result<Vec<u8>, String>;
        let root = tempfile::tempdir().unwrap();
        let mut state = super::super::tests::lifecycle_state(root.path());
        state.probe.max_cells = 2;
        *state.prewarm.lock().unwrap() = Some(Reservation {
            memory_bytes: 4096,
            egress_slots: 0,
        });
        assert!(spawn_admitted(
            &state,
            "tenant",
            &Hash::of(b"blocked"),
            Duration::from_secs(10),
            Reservation {
                memory_bytes: 4096,
                egress_slots: 0
            },
            || -> std::result::Result<Handler, String> {
                panic!("capacity refusal must not initialize a runtime")
            }
        )
        .is_err());
        *state.prewarm.lock().unwrap() = None;
        let start = std::sync::Barrier::new(2);
        std::thread::scope(|scope| {
            let first = scope.spawn(|| {
                start.wait();
                spawn_admitted(
                    &state,
                    "tenant",
                    &Hash::of(b"one"),
                    Duration::from_secs(10),
                    Reservation {
                        memory_bytes: 4096,
                        egress_slots: 0,
                    },
                    || Ok(|_: &[u8]| Ok(vec![1])),
                )
            });
            start.wait();
            let second = spawn_admitted(
                &state,
                "tenant",
                &Hash::of(b"two"),
                Duration::from_secs(10),
                Reservation {
                    memory_bytes: 4096,
                    egress_slots: 0,
                },
                || Ok(|_: &[u8]| Ok(vec![1])),
            );
            assert_ne!(first.join().unwrap().is_ok(), second.is_ok());
        });
        assert_eq!(state.parents.reserved_capacity().unwrap().owners, 1);
        for name in [b"one", b"two"] {
            let id = Hash::of(name);
            if state.parents.status("tenant", &id).is_ok() {
                state.parents.stop("tenant", &id).unwrap();
            }
        }
    }

    #[test]
    fn http_session_commits_turn_and_reads_journal_after_stop() {
        let root = tempfile::tempdir().unwrap();
        let state = super::super::tests::lifecycle_state(root.path());
        let token = "public-parent-session-test-token-24";
        policy(root.path(), token, "tenant-one");
        let id = Hash::of(b"session");
        let session_id = id.clone();
        let journal_root = root.path().join("parent-journal");
        pilot::parent_session::spawn_registered(
            &state.parents,
            "tenant-one",
            &id,
            Duration::from_secs(10),
            4096,
            move || {
                let journal = warden::parent_journal::ParentJournal::create(
                    &journal_root,
                    session_id.clone(),
                )?;
                let lease = warden::parent_lease::ParentLease::new(
                    session_id,
                    Duration::from_secs(10),
                    warden::parent_lease::TurnLimits {
                        memory_bytes: 4096,
                        timeout: Duration::from_secs(1),
                        model_requests: 0,
                        output_tokens: 0,
                    },
                    2,
                    0,
                    0,
                )?;
                let mut context = pilot::parent_harness::ParentContext::default();
                Ok(pilot::parent_session::ParentSession::new(
                    move |bytes: &[u8]| {
                        Ok(serde_json::to_vec(
                            &context.exchange(bytes).map_err(anyhow::Error::msg)?,
                        )?)
                    },
                    |turn: &warden::parent_lease::ReservedTurn| {
                        Ok(pilot::parent_session::DestroyedChild {
                            child: turn.child.clone(),
                            succeeded: true,
                            answer: "fixture answer".into(),
                        })
                    },
                    lease,
                    journal,
                ))
            },
        )
        .unwrap();
        let path = format!("/v1/parents/{}", id.0);
        for turn in ["one", "two"] {
            let body = json!({"kind":"turn", "apiVersion":pilot::parent_harness::VERSION,"turnId":turn,"message":"hello"}).to_string();
            assert!(http(&state, "POST", &format!("{path}/turns"), token, &body)
                .contains("fixture answer"));
            let observed = http(&state, "GET", &format!("{path}/turns/{turn}"), token, "");
            assert!(observed.contains("parent-committed"));
            assert!(observed.contains("\"retryAuthorized\":false"));
        }
        assert!(http(&state, "POST", &format!("{path}/stop"), token, "")
            .contains("\"teardownConfirmed\":true"));
        assert!(http(&state, "GET", &format!("{path}/turns/one"), token, "")
            .contains("parent-committed"));
        policy(root.path(), token, "tenant-two");
        assert!(http(&state, "GET", &format!("{path}/turns/one"), token, "")
            .starts_with("HTTP/1.1 404"));
    }

    #[test]
    fn duplicate_credentials_and_unknown_policy_fields_fail_closed() {
        let root = tempfile::tempdir().unwrap();
        let token = "public-parent-auth-negative-token-24";
        for value in [
            json!({"apiVersion":"celln.parent-clients/v1", "clients":[
                {"principal":"one","tokenHash":Hash::of(token.as_bytes()).0},
                {"principal":"two","tokenHash":Hash::of(token.as_bytes()).0}]}),
            json!({"apiVersion":"celln.parent-clients/v1", "clients":[], "allowAll":true}),
        ] {
            std::fs::write(
                root.path().join("trusted-parent-clients.json"),
                value.to_string(),
            )
            .unwrap();
            assert!(authenticate(root.path(), Some(token)).is_err());
        }
    }

    #[test]
    fn real_http_routes_isolate_principals_rotate_credentials_and_refuse_creation() {
        let root = tempfile::tempdir().unwrap();
        let state = super::super::tests::lifecycle_state(root.path());
        let token = "public-parent-test-token-at-least-24";
        let id = Hash::of(b"incarnation");
        state
            .parents
            .spawn_admitted("tenant-one", &id, Duration::from_secs(10), 4096, || {
                Ok(|_: &[u8]| Ok(br#"{"kind":"completed"}"#.to_vec()))
            })
            .unwrap();
        let path = format!("/v1/parents/{}", id.0);
        assert!(http(&state, "GET", &path, token, "").starts_with("HTTP/1.1 503"));
        policy(root.path(), token, "tenant-one");
        assert!(http(&state, "GET", &path, &state.token, "").starts_with("HTTP/1.1 401"));
        let status = http(&state, "GET", &path, token, "");
        assert!(
            status.contains("Ready") || status.contains("Initializing"),
            "{status}"
        );
        assert!(http(&state, "POST", &format!("{path}/turns"), token, "{}").contains("completed"));
        assert!(http(&state, "POST", "/v1/parents", token, "{}").starts_with("HTTP/1.1 400"));
        policy(root.path(), token, "tenant-two");
        for suffix in ["", "/turns", "/stop", "/cancel"] {
            assert!(
                http(&state, "POST", &format!("{path}{suffix}"), token, "{}")
                    .starts_with("HTTP/1.1 404")
            );
        }
        let rotated = "rotated-public-parent-test-token-24";
        policy(root.path(), rotated, "tenant-one");
        assert!(http(&state, "GET", &path, token, "").starts_with("HTTP/1.1 401"));
        assert!(http(&state, "POST", &format!("{path}/stop"), rotated, "")
            .contains("\"teardownConfirmed\":true"));
        assert!(http(&state, "GET", &path, rotated, "").contains("Stopped"));
    }
}
