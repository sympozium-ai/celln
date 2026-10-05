//! `/v1/scoped/*` forwarding. Scoped state (prepared material, admission
//! journal, retained parents) is node-local, so every operation id is bound to
//! exactly one node BEFORE its first forward and is never re-placed: permits
//! are not node-bound and replay protection lives in that node's journal.
//!
//! The router authenticates the scoped operator bearer only to decide whether
//! to forward; the dispatcher stays the sole verifier of that bearer and of
//! every permit. A lost node surfaces as the dispatcher's own
//! `AUTH_CONTEXT_LOST` refusal, never as a fresh placement elsewhere.
use super::*;
use serde_json::{json, Value};
use std::cell::Cell;
use zeroize::Zeroizing;

/// Same bound the dispatcher's scoped receiver applies.
const MAX_BODY: usize = 262144;

/// A retired binding is removed only once it is older than any permit that
/// could still be admitted for it: a start decision's admission window closes
/// at most 60 s after issuance (plus 5 s skew), and the binding was claimed
/// after issuance. The rest is margin for clock skew between router replicas.
pub(super) const QUARANTINE: Duration = Duration::from_secs(600);

#[derive(Default)]
pub(super) struct Permits {
    pub execution: Option<Zeroizing<String>>,
    pub model: Option<Zeroizing<String>>,
}

fn context_lost() -> Value {
    json!({"error":"scoped admission refused","reason":"AUTH_CONTEXT_LOST"})
}

/// The scoped bearer, which must differ from every other router credential.
pub(super) fn scoped_credential(state: &RouterState) -> Result<Option<String>> {
    let Some(path) = state.scoped_token_file.as_deref() else {
        return Ok(None);
    };
    let token = read_token(path)?;
    let (client, backend, capability) = credentials(state)?;
    let parent = state
        .parent_token_file
        .as_deref()
        .map(read_token)
        .transpose()?;
    if [Some(client), Some(backend), capability, parent]
        .iter()
        .flatten()
        .any(|other| constant_time_eq(token.as_bytes(), other.as_bytes()))
    {
        bail!("scoped credential must be distinct");
    }
    Ok(Some(token))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn forward(
    state: &RouterState,
    stream: &mut TcpStream,
    reader: &mut impl Read,
    method: &str,
    path: &str,
    length: usize,
    presented: Option<&str>,
    permits: &Permits,
    pinned: bool,
) -> Result<()> {
    if state.scoped_token_file.is_none() {
        return reply(stream, 404, &json!({"error":"scoped receiver disabled"}));
    }
    let token = match scoped_credential(state) {
        Ok(Some(token)) => Zeroizing::new(token),
        _ => return reply(stream, 503, &json!({"error":"scoped receiver unavailable"})),
    };
    if !presented.is_some_and(|got| constant_time_eq(got.as_bytes(), token.as_bytes())) {
        return reply(stream, 401, &json!({"error":"unauthorized"}));
    }
    if pinned {
        return reply(
            stream,
            400,
            &json!({"error":"backend pin only applies to submission or prewarm"}),
        );
    }
    let route = match (method, path) {
        ("POST", "/v1/scoped/prepare") => Route::Prepare,
        ("POST", "/v1/scoped/start") => Route::Start,
        ("POST", "/v1/scoped/read") => Route::Read,
        ("POST", "/v1/scoped/cleanup") => Route::Cleanup,
        _ => return reply(stream, 404, &json!({"error":"not found"})),
    };
    if length > MAX_BODY {
        return reply(
            stream,
            413,
            &json!({"error":"scoped request body exceeds 256 KiB"}),
        );
    }
    let mut raw = vec![0; length];
    reader.read_exact(&mut raw)?;
    // Claims bind the canonical bytes, and exactly those bytes are forwarded.
    let Ok(body) = crate::tenancy_contract::canonical(&raw) else {
        return reply(
            stream,
            400,
            &json!({"error":"scoped request must be bounded unambiguous I-JSON"}),
        );
    };
    let backend_token = credentials(state).ok().map(|(_, backend, _)| backend);
    let request: Value = serde_json::from_slice(&body)?;
    let backend = match route {
        Route::Prepare => match place(state, stream, &request, &body, &backend_token)? {
            Some(backend) => backend,
            None => return Ok(()),
        },
        Route::Start | Route::Read | Route::Cleanup => {
            let Some(id) = request["id"].as_str().filter(|id| id.len() <= 512) else {
                let error = if route == Route::Start {
                    "invalid scoped start"
                } else {
                    "invalid scoped access"
                };
                return reply(stream, 400, &json!({ "error": error }));
            };
            match state.scoped_ops.lookup(id) {
                Ok(Some(owner)) => owner.backend,
                // The dispatcher's answer for an id it never prepared.
                Ok(None) => {
                    return reply(stream, 404, &json!({"error":"unknown prepared operation"}))
                }
                Err(_) => {
                    return reply(
                        stream,
                        503,
                        &json!({"error":"scoped ownership unavailable"}),
                    )
                }
            }
        }
    };
    let response = match send(state, &backend, path, &token, permits, &body) {
        Sent::Response(response) => response,
        Sent::Lost => return reply(stream, 409, &context_lost()),
        Sent::Uncertain => {
            return reply(
                stream,
                502,
                &json!({"error":"scoped outcome uncertain; retry the same request"}),
            )
        }
    };
    if route == Route::Cleanup && parse_status(&response) == 200 {
        retire(state, &request, extract_body(&response));
    }
    raw_reply(stream, &response)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Route {
    Prepare,
    Start,
    Read,
    Cleanup,
}

/// Binds the operation (and, for an enduring root, its parent) to one node
/// before anything is forwarded. `None` means a refusal was already written.
fn place(
    state: &RouterState,
    stream: &mut TcpStream,
    request: &Value,
    body: &[u8],
    backend_token: &Option<String>,
) -> Result<Option<String>> {
    let (Some(operation), Some(decision), 2) = (
        request.get("operation"),
        request.get("decision"),
        request.as_object().map_or(0, |o| o.len()),
    ) else {
        reply(stream, 400, &json!({"error":"invalid scoped preparation"}))?;
        return Ok(None);
    };
    let Ok(id) = crate::tenancy_contract::scoped_operation_id(operation, decision) else {
        reply(stream, 422, &json!({"error":"scoped preparation refused"}))?;
        return Ok(None);
    };
    let incarnation = decision["parent"]["incarnation"]
        .as_str()
        .filter(|i| i.len() <= 512);
    let lifecycle = match (decision["lifecycle"].as_str(), incarnation) {
        (Some("one-shot"), None) if decision["parent"].is_null() => Lifecycle::OneShot,
        (Some("enduring-initial"), Some(parent)) => Lifecycle::Initial(parent),
        (Some("enduring-turn"), Some(parent)) => Lifecycle::Turn(parent),
        _ => {
            reply(
                stream,
                422,
                &json!({"error":"scoped preparation refused","reason":"unsupported scoped lifecycle operation"}),
            )?;
            return Ok(None);
        }
    };
    let lost = Cell::new(false);
    let choose = || -> Result<String> {
        match lifecycle {
            Lifecycle::OneShot => pick_owner(state, &id, backend_token),
            // The parent's placement is itself bound once, keyed by its
            // incarnation, so a retried root lands where the first one did.
            Lifecycle::Initial(parent) => {
                match claim(&state.scoped_parents, parent, parent.as_bytes(), || {
                    pick_owner(state, parent, backend_token)
                })? {
                    ownership::Claim::New(owner) | ownership::Claim::Existing(owner) => {
                        Ok(owner.backend)
                    }
                    _ => bail!("scoped parent ownership unavailable"),
                }
            }
            // A turn only ever follows its parent; it never places one.
            Lifecycle::Turn(parent) => match state.scoped_parents.lookup(parent)? {
                Some(owner) => Ok(owner.backend),
                None => {
                    lost.set(true);
                    bail!("scoped parent binding absent")
                }
            },
        }
    };
    match claim(&state.scoped_ops, &id, body, choose) {
        Ok(ownership::Claim::New(owner)) | Ok(ownership::Claim::Existing(owner)) => {
            Ok(Some(owner.backend))
        }
        Ok(ownership::Claim::Conflict) => {
            reply(
                stream,
                409,
                &json!({"error":"operation identity already has different prepared material"}),
            )?;
            Ok(None)
        }
        _ if lost.get() => {
            reply(stream, 409, &context_lost())?;
            Ok(None)
        }
        _ => {
            reply(
                stream,
                503,
                &json!({"error":"scoped ownership unavailable"}),
            )?;
            Ok(None)
        }
    }
}

#[derive(Clone, Copy)]
enum Lifecycle<'a> {
    OneShot,
    Initial(&'a str),
    Turn(&'a str),
}

/// A full ledger first reclaims retired bindings that finished quarantine.
fn claim(
    ledger: &ownership::Ledger,
    id: &str,
    body: &[u8],
    choose: impl Fn() -> Result<String>,
) -> Result<ownership::Claim> {
    match ledger.claim(id, body, &choose)? {
        ownership::Claim::Full => {
            ledger.sweep_retired(QUARANTINE)?;
            ledger.claim(id, body, choose)
        }
        claim => Ok(claim),
    }
}

/// After the owning node confirms cleanup, the operation (and, for an
/// enduring root, its parent) can never again be started anywhere, so the
/// bindings retire. Failure to retire only leaves a binding in place.
fn retire(state: &RouterState, request: &Value, response: &str) {
    let confirmed = serde_json::from_str::<Value>(response)
        .is_ok_and(|status| status["cleanupConfirmed"] == true);
    let Some(id) = request["id"].as_str().filter(|_| confirmed) else {
        return;
    };
    let _ = state.scoped_ops.retire(id, QUARANTINE);
    if request["decision"]["lifecycle"] == "enduring-initial" {
        if let Some(parent) = request["decision"]["parent"]["incarnation"].as_str() {
            let _ = state.scoped_parents.retire(parent, QUARANTINE);
        }
    }
}

enum Sent {
    Response(String),
    /// The node is gone from discovery or refused the connection: nothing was
    /// delivered, and its node-local context is unreachable.
    Lost,
    /// Delivery started; the node may or may not have acted.
    Uncertain,
}

fn send(
    state: &RouterState,
    backend: &str,
    path: &str,
    token: &str,
    permits: &Permits,
    body: &[u8],
) -> Sent {
    if !state.backends().iter().any(|url| url == backend) {
        return Sent::Lost;
    }
    let Ok(mut conn) = backend_to_addr(backend).and_then(|addr| connect(&addr)) else {
        return Sent::Lost;
    };
    let response = (|| -> Result<String> {
        let mut head = Zeroizing::new(format!(
            "POST {path} HTTP/1.1\r\nHost: dispatcher\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
            body.len()
        ));
        if let Some(permit) = &permits.execution {
            head.push_str(&format!(
                "X-Celln-Execution-Permit: {}\r\n",
                permit.as_str()
            ));
        }
        if let Some(permit) = &permits.model {
            head.push_str(&format!("X-Celln-Model-Permit: {}\r\n", permit.as_str()));
        }
        head.push_str("Connection: close\r\n\r\n");
        conn.write_all(head.as_bytes())?;
        conn.write_all(body)?;
        conn.flush()?;
        read_response(&mut conn)
    })();
    match response {
        Ok(response) => Sent::Response(response),
        Err(_) => Sent::Uncertain,
    }
}

// Real TCP parsing and forwarding against protocol fixtures standing in for
// dispatchers; not a KVM, permit-verification or multi-host proof.
#[cfg(test)]
mod tests {
    use super::super::tests::{request, state, BACKEND_TOKEN, CLIENT_TOKEN};
    use super::*;
    use std::sync::atomic::AtomicU32;

    const SCOPED: &str = "scoped-operator-credential-at-least-24";
    const OWNER: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    struct Seen {
        path: String,
        headers: Vec<String>,
        body: Vec<u8>,
    }

    struct Node {
        url: String,
        seen: Arc<Mutex<Vec<Seen>>>,
        live: Arc<AtomicU32>,
        confirm: Arc<AtomicBool>,
    }

    impl Node {
        fn paths(&self) -> Vec<String> {
            self.seen
                .lock()
                .unwrap()
                .iter()
                .map(|s| s.path.clone())
                .collect()
        }
    }

    /// A dispatcher fixture: health reports `live` of 8 cells (advanced by
    /// `jitter` per probe), scoped routes are recorded and answered.
    fn node(jitter: u32) -> Node {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let live = Arc::new(AtomicU32::new(0));
        let confirm = Arc::new(AtomicBool::new(true));
        let (record, load, confirmed) = (seen.clone(), live.clone(), confirm.clone());
        std::thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let line = read_bounded_line(&mut reader, MAX_REQUEST_LINE).unwrap();
                let path = line.split_whitespace().nth(1).unwrap().to_owned();
                let mut headers = Vec::new();
                let mut length = 0;
                loop {
                    let h = read_bounded_line(&mut reader, MAX_HEADER_LINE).unwrap();
                    let h = h.trim_end().to_owned();
                    if h.is_empty() {
                        break;
                    }
                    if let Some(v) = h.strip_prefix("Content-Length: ") {
                        length = v.parse().unwrap();
                    }
                    headers.push(h);
                }
                let mut body = vec![0; length];
                reader.read_exact(&mut body).unwrap();
                if path == "/v1/health" {
                    let live = load.fetch_add(jitter, Ordering::SeqCst) % 8;
                    reply(&mut stream, 200, &json!({"ok":true,"kvm":true,"node":{"live_cells":live,"max_cells":8,"memory_bytes":1u64<<30}})).unwrap();
                    continue;
                }
                let request: Value = serde_json::from_slice(&body).unwrap();
                let (status, answer) = match path.as_str() {
                    "/v1/scoped/prepare" => (
                        200,
                        json!({"id":crate::tenancy_contract::scoped_operation_id(&request["operation"], &request["decision"]).unwrap(),"owner":OWNER}),
                    ),
                    "/v1/scoped/cleanup" if confirmed.load(Ordering::SeqCst) => (
                        200,
                        json!({"id":request["id"],"phase":"Cancelled","cleanupConfirmed":true}),
                    ),
                    "/v1/scoped/cleanup" => (
                        202,
                        json!({"id":request["id"],"phase":"Cancelling","cleanupConfirmed":false}),
                    ),
                    _ => (
                        200,
                        json!({"id":request["id"],"phase":"Running","cleanupConfirmed":false}),
                    ),
                };
                record.lock().unwrap().push(Seen {
                    path,
                    headers,
                    body,
                });
                reply(&mut stream, status, &answer).unwrap();
            }
        });
        Node {
            url,
            seen,
            live,
            confirm,
        }
    }

    fn scoped_state(dir: &Path) -> RouterState {
        let mut state = state(dir);
        let file = dir.join("scoped");
        std::fs::write(&file, SCOPED).unwrap();
        state.scoped_token_file = Some(file);
        state
    }

    fn prepare_body(lifecycle: &str, parent: Value, deadline: i64) -> String {
        json!({
            "operation":{"resolution":{"execution":{"source":{"clusterId":"c","namespaceUid":"ns","runUid":"run"}}}},
            "decision":{"lifecycle":lifecycle,"parent":parent,"windows":{"admissionDeadline":deadline}},
        })
        .to_string()
    }

    fn op_id(body: &str) -> String {
        let value: Value = serde_json::from_str(body).unwrap();
        crate::tenancy_contract::scoped_operation_id(&value["operation"], &value["decision"])
            .unwrap()
    }

    fn post(state: &RouterState, route: &str, extra: &str, body: &str) -> String {
        request(
            state,
            "POST",
            &format!("/v1/scoped/{route}"),
            &format!(
                "Authorization: Bearer {SCOPED}\r\n{extra}Content-Length: {}\r\n",
                body.len()
            ),
            body,
        )
    }

    fn access(id: &str) -> String {
        json!({"id":id,"decision":{"lifecycle":"one-shot"}}).to_string()
    }

    fn age(ledger: &ownership::Ledger, id: &str) {
        std::fs::File::options()
            .write(true)
            .open(ledger.path(id))
            .unwrap()
            .set_modified(std::time::SystemTime::now() - QUARANTINE - Duration::from_secs(1))
            .unwrap();
    }

    fn assert_context_lost(response: &str) {
        assert_eq!(parse_status(response), 409, "{response}");
        assert_eq!(
            serde_json::from_str::<Value>(extract_body(response)).unwrap(),
            json!({"error":"scoped admission refused","reason":"AUTH_CONTEXT_LOST"})
        );
    }

    #[test]
    fn scoped_bearer_is_required_distinct_and_opens_only_scoped_routes() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = state(dir.path());
        assert_eq!(parse_status(&post(&state, "prepare", "", "{}")), 404);
        assert!(post(&state, "prepare", "", "{}").contains("scoped receiver disabled"));
        let file = dir.path().join("scoped");
        std::fs::write(&file, SCOPED).unwrap();
        state.scoped_token_file = Some(file.clone());
        for header in [
            String::new(),
            "Authorization: Bearer wrong\r\n".into(),
            format!("Authorization: Bearer {CLIENT_TOKEN}\r\n"),
            format!("Authorization: Bearer {BACKEND_TOKEN}\r\n"),
        ] {
            let response = request(
                &state,
                "POST",
                "/v1/scoped/prepare",
                &format!("{header}Content-Length: 2\r\n"),
                "{}",
            );
            assert_eq!(parse_status(&response), 401, "{header}");
        }
        // The scoped bearer opens nothing else.
        let auth = format!("Authorization: Bearer {SCOPED}\r\n");
        for (method, path) in [
            ("GET", "/v1/executions/x"),
            ("POST", "/v1/executions/x/cancel"),
            ("GET", "/v1/cells"),
            ("POST", "/v1/capabilities"),
            ("GET", "/v1/node"),
        ] {
            assert_eq!(parse_status(&request(&state, method, path, &auth, "")), 401);
        }
        // Except scoped capability discovery, which reveals no node detail.
        assert_eq!(
            parse_status(&request(&state, "GET", "/v1/capabilities", &auth, "")),
            200
        );
        assert_eq!(
            parse_status(&request(&state, "GET", "/v1/scoped/prepare", &auth, "")),
            404
        );
        assert_eq!(parse_status(&post(&state, "launch", "", "{}")), 404);
        assert_eq!(
            parse_status(&post(
                &state,
                "prepare",
                "X-Celln-Backend: http://n:1\r\n",
                "{}"
            )),
            400
        );
        // Accepted without contacting a node: the shape is refused first.
        assert_eq!(parse_status(&post(&state, "prepare", "", "{}")), 400);
        assert!(scoped_credential(&state).unwrap().is_some());
        // Equal to any other router credential: unavailable, never accepted.
        let parent = dir.path().join("parent");
        let capability = dir.path().join("capability");
        for (other, file_for) in [
            (CLIENT_TOKEN, None),
            (BACKEND_TOKEN, None),
            ("capability-credential-at-least-24", Some(&capability)),
            ("parent-credential-at-least-24-bytes", Some(&parent)),
        ] {
            if let Some(path) = file_for {
                std::fs::write(path, other).unwrap();
            }
            state.capability_token_file = Some(capability.clone()).filter(|p| p.exists());
            state.parent_token_file = Some(parent.clone()).filter(|p| p.exists());
            std::fs::write(&file, other).unwrap();
            assert!(scoped_credential(&state).is_err(), "{other}");
            let response = request(
                &state,
                "POST",
                "/v1/scoped/prepare",
                &format!("Authorization: Bearer {other}\r\nContent-Length: 2\r\n"),
                "{}",
            );
            assert_eq!(parse_status(&response), 503, "{other}");
        }
        // The parent principal refuses to share the scoped bearer as well.
        let incarnation = format!("blake3:{}", "a".repeat(64));
        let response = request(
            &state,
            "GET",
            &format!("/v1/parents/{incarnation}"),
            &format!("Authorization: Bearer {CLIENT_TOKEN}\r\n"),
            "",
        );
        assert_eq!(parse_status(&response), 503);
        assert!(response.contains("parent credential must be distinct"));
    }

    #[test]
    fn only_bearer_permits_and_canonical_body_reach_the_node() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = scoped_state(dir.path());
        let node = node(0);
        state.backends = vec![node.url.clone()];
        let body = format!(
            " {} ",
            prepare_body("one-shot", Value::Null, 7).replace(",", ", ")
        );
        let extra = format!("X-Celln-Execution-Permit: exec.jwt.sig\r\nX-Celln-Model-Permit: model.jwt.sig\r\nX-Celln-Parent-Incarnation: blake3:{}\r\nPrefer: respond-async\r\nCookie: session=1\r\nX-Forwarded-For: 10.0.0.1\r\n", "a".repeat(64));
        let response = post(&state, "prepare", &extra, &body);
        assert_eq!(parse_status(&response), 200, "{response}");
        let id = op_id(&body);
        assert!(extract_body(&response).contains(&id));
        let seen = node.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        let canonical = crate::tenancy_contract::canonical(body.as_bytes()).unwrap();
        assert_eq!(seen[0].body, canonical);
        assert_eq!(
            seen[0].headers,
            vec![
                "Host: dispatcher".to_string(),
                format!("Authorization: Bearer {SCOPED}"),
                "Content-Type: application/json".into(),
                format!("Content-Length: {}", canonical.len()),
                "X-Celln-Execution-Permit: exec.jwt.sig".into(),
                "X-Celln-Model-Permit: model.jwt.sig".into(),
                "Connection: close".into(),
            ]
        );
        drop(seen);
        // Ambiguous, header-splitting, oversized or non-I-JSON input refuses
        // before any node sees it.
        for extra in [
            "X-Celln-Execution-Permit: a\r\nx-celln-execution-permit: b\r\n",
            "X-Celln-Model-Permit: a\r\nX-Celln-Model-Permit: a\r\n",
            "X-Celln-Execution-Permit: a\x01b\r\n",
            "X-Celln-Execution-Permit: \r\n",
        ] {
            assert_eq!(parse_status(&post(&state, "start", extra, "{}")), 400);
        }
        let response = request(
            &state,
            "POST",
            "/v1/scoped/prepare",
            &format!("Authorization: Bearer {SCOPED}\r\nContent-Length: 262145\r\n"),
            "",
        );
        assert_eq!(parse_status(&response), 413);
        assert_eq!(
            parse_status(&post(&state, "prepare", "", r#"{"a":1,"a":2}"#)),
            400
        );
        assert_eq!(
            parse_status(&post(
                &state,
                "prepare",
                "",
                r#"{"operation":{},"decision":{},"x":1}"#
            )),
            400
        );
        assert_eq!(node.paths(), vec!["/v1/scoped/prepare"]);
    }

    #[test]
    fn an_operation_binds_one_node_for_every_route_until_retired() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = scoped_state(dir.path());
        let (a, b) = (node(0), node(0));
        state.backends = vec![a.url.clone(), b.url.clone()];
        let body = prepare_body("one-shot", Value::Null, 7);
        let id = op_id(&body);
        assert_eq!(parse_status(&post(&state, "prepare", "", &body)), 200);
        let owner = state.scoped_ops.lookup(&id).unwrap().unwrap().backend;
        let (bound, other) = if owner == a.url { (&a, &b) } else { (&b, &a) };
        // Make the other node roomier: an idempotent retry must not move.
        other.live.store(0, Ordering::SeqCst);
        bound.live.store(7, Ordering::SeqCst);
        let reordered = body
            .replace(r#""lifecycle":"one-shot","#, "")
            .replace(r#""decision":{"#, r#""decision":{"lifecycle":"one-shot","#);
        assert_eq!(op_id(&reordered), id);
        assert_eq!(parse_status(&post(&state, "prepare", "", &reordered)), 200);
        // Changed material for the same identity is refused before any node.
        let changed = prepare_body("one-shot", Value::Null, 8);
        let response = post(&state, "prepare", "", &changed);
        assert_eq!(parse_status(&response), 409);
        assert!(response.contains("different prepared material"));
        let permit = "X-Celln-Execution-Permit: exec.jwt.sig\r\n";
        let start = json!({"id":id,"owner":OWNER}).to_string();
        assert_eq!(parse_status(&post(&state, "start", permit, &start)), 200);
        assert_eq!(
            parse_status(&post(&state, "read", permit, &access(&id))),
            200
        );
        // Pending teardown keeps the binding untouched.
        bound.confirm.store(false, Ordering::SeqCst);
        assert_eq!(
            parse_status(&post(&state, "cleanup", permit, &access(&id))),
            202
        );
        assert!(!state
            .scoped_ops
            .path(&id)
            .with_extension("retired")
            .exists());
        // Confirmed cleanup of a young binding only marks it: still routable.
        bound.confirm.store(true, Ordering::SeqCst);
        assert_eq!(
            parse_status(&post(&state, "cleanup", permit, &access(&id))),
            200
        );
        assert!(state
            .scoped_ops
            .path(&id)
            .with_extension("retired")
            .exists());
        assert_eq!(
            parse_status(&post(&state, "read", permit, &access(&id))),
            200
        );
        assert_eq!(
            bound.paths(),
            ["prepare", "prepare", "start", "read", "cleanup", "cleanup", "read"]
                .map(|r| format!("/v1/scoped/{r}"))
        );
        assert!(other.paths().is_empty());
        // Past quarantine, confirmed cleanup removes the binding.
        age(&state.scoped_ops, &id);
        assert_eq!(
            parse_status(&post(&state, "cleanup", permit, &access(&id))),
            200
        );
        assert!(state.scoped_ops.lookup(&id).unwrap().is_none());
        let response = post(&state, "start", permit, &start);
        assert_eq!(parse_status(&response), 404);
        assert_eq!(
            extract_body(&response),
            r#"{"error":"unknown prepared operation"}"#
        );
        assert_eq!(
            parse_status(&post(&state, "start", "", r#"{"owner":"x"}"#)),
            400
        );
        assert_eq!(parse_status(&post(&state, "read", "", "[1]")), 400);
    }

    #[test]
    fn enduring_turns_follow_their_parent_and_never_place_one() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = scoped_state(dir.path());
        let (a, b) = (node(0), node(0));
        state.backends = vec![a.url.clone(), b.url.clone()];
        let parent = format!("blake3:{}", "b".repeat(64));
        let turn =
            |n: &str| prepare_body("enduring-turn", json!({"incarnation":parent,"turnId":n}), 7);
        assert_context_lost(&post(&state, "prepare", "", &turn("t1")));
        assert!(state
            .scoped_ops
            .lookup(&op_id(&turn("t1")))
            .unwrap()
            .is_none());
        assert!(a.paths().is_empty() && b.paths().is_empty());
        // A malformed lifecycle is never placed either.
        assert_eq!(
            parse_status(&post(
                &state,
                "prepare",
                "",
                &prepare_body("enduring-initial", Value::Null, 7)
            )),
            422
        );
        let initial = prepare_body(
            "enduring-initial",
            json!({"incarnation":parent,"turnId":null}),
            7,
        );
        assert_eq!(parse_status(&post(&state, "prepare", "", &initial)), 200);
        let owner = state
            .scoped_parents
            .lookup(&parent)
            .unwrap()
            .unwrap()
            .backend;
        assert_eq!(
            state
                .scoped_ops
                .lookup(&op_id(&initial))
                .unwrap()
                .unwrap()
                .backend,
            owner
        );
        let (bound, other) = if owner == a.url { (&a, &b) } else { (&b, &a) };
        other.live.store(0, Ordering::SeqCst);
        bound.live.store(7, Ordering::SeqCst);
        for n in ["t1", "t2"] {
            assert_eq!(parse_status(&post(&state, "prepare", "", &turn(n))), 200);
            assert_eq!(
                state
                    .scoped_ops
                    .lookup(&op_id(&turn(n)))
                    .unwrap()
                    .unwrap()
                    .backend,
                owner
            );
        }
        assert_eq!(bound.paths().len(), 3);
        assert!(other.paths().is_empty());
        // The parent's confirmed final cleanup retires its binding: later
        // turns are context-lost, never placed on a fresh node.
        age(&state.scoped_ops, &op_id(&initial));
        age(&state.scoped_parents, &parent);
        let cleanup = json!({"id":op_id(&initial),"decision":{"lifecycle":"enduring-initial","parent":{"incarnation":parent,"turnId":null}}}).to_string();
        assert_eq!(parse_status(&post(&state, "cleanup", "", &cleanup)), 200);
        assert!(state.scoped_parents.lookup(&parent).unwrap().is_none());
        assert_context_lost(&post(&state, "prepare", "", &turn("t3")));
        assert!(other.paths().is_empty());
    }

    #[test]
    fn a_lost_node_is_auth_context_lost_and_never_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = scoped_state(dir.path());
        let (a, spare) = (node(0), node(0));
        state.backends = vec![a.url.clone()];
        let body = prepare_body("one-shot", Value::Null, 7);
        let id = op_id(&body);
        assert_eq!(parse_status(&post(&state, "prepare", "", &body)), 200);
        // The owner leaves discovery; a healthy spare must not take over.
        state.backends = vec![spare.url.clone()];
        let start = json!({"id":id,"owner":OWNER}).to_string();
        assert_context_lost(&post(&state, "start", "", &start));
        assert_context_lost(&post(&state, "prepare", "", &body));
        assert_context_lost(&post(&state, "cleanup", "", &access(&id)));
        assert!(spare.paths().is_empty());
        assert_eq!(
            state.scoped_ops.lookup(&id).unwrap().unwrap().backend,
            a.url
        );
        // Still discovered, but refusing connections: also context-lost.
        let closed = TcpListener::bind("127.0.0.1:0").unwrap();
        let dead = format!("http://{}", closed.local_addr().unwrap());
        drop(closed);
        state.backends = vec![dead.clone(), spare.url.clone()];
        let other = prepare_body("one-shot", Value::Null, 9).replace("\"run\"", "\"run-2\"");
        let canonical = crate::tenancy_contract::canonical(other.as_bytes()).unwrap();
        state
            .scoped_ops
            .claim(&op_id(&other), &canonical, || Ok(dead.clone()))
            .unwrap();
        assert_context_lost(&post(&state, "prepare", "", &other));
        assert_context_lost(&post(
            &state,
            "start",
            "",
            &json!({"id":op_id(&other)}).to_string(),
        ));
        assert!(spare.paths().is_empty());
        // Delivered but unanswered is uncertain, not lost, and still bound.
        let silent = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", silent.local_addr().unwrap());
        let third = other.replace("\"run-2\"", "\"run-3\"");
        let canonical = crate::tenancy_contract::canonical(third.as_bytes()).unwrap();
        state
            .scoped_ops
            .claim(&op_id(&third), &canonical, || Ok(url.clone()))
            .unwrap();
        state.backends.push(url.clone());
        let closer = std::thread::spawn(move || drop(silent.accept().unwrap()));
        let response = post(&state, "prepare", "", &third);
        closer.join().unwrap();
        assert_eq!(parse_status(&response), 502, "{response}");
        assert_eq!(
            state
                .scoped_ops
                .lookup(&op_id(&third))
                .unwrap()
                .unwrap()
                .backend,
            url
        );
        assert!(spare.paths().is_empty());
    }

    #[test]
    fn concurrent_prepares_reach_exactly_one_node() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = scoped_state(dir.path());
        // Capacity shifts on every probe, so racing placements would disagree.
        let nodes = [node(3), node(5), node(1)];
        state.backends = nodes.iter().map(|n| n.url.clone()).collect();
        let bodies: Vec<String> = (0..12)
            .map(|i| prepare_body("one-shot", Value::Null, 7 + (i % 3)))
            .collect();
        let statuses: Vec<u16> = std::thread::scope(|scope| {
            let state = &state;
            let calls: Vec<_> = bodies
                .iter()
                .map(|body| scope.spawn(move || parse_status(&post(state, "prepare", "", body))))
                .collect();
            calls.into_iter().map(|c| c.join().unwrap()).collect()
        });
        assert!(
            statuses.iter().all(|s| [200, 409, 503].contains(s)),
            "{statuses:?}"
        );
        // Whoever takes the ledger lock first is placed and forwarded.
        assert!(statuses.contains(&200), "{statuses:?}");
        let owner = state
            .scoped_ops
            .lookup(&op_id(&bodies[0]))
            .unwrap()
            .unwrap()
            .backend;
        for node in &nodes {
            if node.url != owner {
                assert!(node.paths().is_empty(), "op reached a second node");
            }
        }
        // Whatever won, a later retry of its exact material reaches it.
        let winner = nodes.iter().find(|n| n.url == owner).unwrap();
        let bound = winner.seen.lock().unwrap()[0].body.clone();
        let body = String::from_utf8(bound).unwrap();
        assert_eq!(parse_status(&post(&state, "prepare", "", &body)), 200);
        assert!(nodes
            .iter()
            .filter(|n| n.url != owner)
            .all(|n| n.paths().is_empty()));
    }

    /// A dispatcher answering only `/v1/capabilities` with `report` after
    /// checking it was asked with the backend credential.
    fn capability_node(report: Value) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let line = read_bounded_line(&mut reader, MAX_REQUEST_LINE).unwrap();
                assert_eq!(line, "GET /v1/capabilities HTTP/1.1\r\n");
                let mut authorized = false;
                loop {
                    let h = read_bounded_line(&mut reader, MAX_HEADER_LINE).unwrap();
                    if h.trim().is_empty() {
                        break;
                    }
                    authorized |= h == format!("Authorization: Bearer {BACKEND_TOKEN}\r\n");
                }
                assert!(authorized);
                reply(&mut stream, 200, &report).unwrap();
            }
        });
        url
    }

    fn capabilities(artifacts: &[&str], https: &[&str], eligible: bool) -> Value {
        let mut report = serde_json::to_value(crate::capabilities::DispatcherCapabilities::new(
            crate::node::NodeEligibility {
                node_name: "fixture".into(),
                kvm: true,
                cpu_virtualization: true,
                guest_kernel: true,
                mote_store: true,
                tool_store: true,
                live_cells: 0,
                max_cells: 4,
                memory_bytes: 1 << 30,
                egress_slots: 1,
            },
        ))
        .unwrap();
        report["scopedArtifactContracts"] = json!(artifacts);
        report["scopedHttpsContracts"] = json!(https);
        report["node"]["kvm"] = eligible.into();
        report
    }

    fn scoped_capabilities(state: &RouterState) -> Value {
        let response = request(
            state,
            "GET",
            "/v1/capabilities",
            &format!("Authorization: Bearer {SCOPED}\r\n"),
            "",
        );
        assert_eq!(parse_status(&response), 200, "{response}");
        serde_json::from_str(extract_body(&response)).unwrap()
    }

    #[test]
    fn scoped_capabilities_are_the_common_contracts_of_eligible_nodes() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = scoped_state(dir.path());
        let v1 = "celln.scoped-artifacts/v1";
        let v2 = "celln.scoped-artifacts/v2";
        let web = "celln.scoped-https/v1";
        let dead = {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            format!("http://{}", listener.local_addr().unwrap())
        };
        let mut incompatible = capabilities(&[], &[], true);
        incompatible["apiVersion"] = "future/unknown".into();
        state.backends = vec![
            capability_node(capabilities(&[v2, v1, v2], &[web], true)),
            capability_node(capabilities(&[v1], &[web], true)),
            // Neither ineligible, unreachable nor incompatible nodes narrow it.
            capability_node(capabilities(&[], &[], false)),
            dead,
            capability_node(incompatible),
        ];
        let body = scoped_capabilities(&state);
        assert_eq!(
            body,
            json!({
                "apiVersion": crate::capabilities::VERSION,
                "scopedArtifactContracts": [v1],
                "scopedHttpsContracts": [web],
                "eligibleNodes": 2,
            })
        );
        // Sorted and deduplicated on a single node.
        state.backends = vec![capability_node(capabilities(&[v2, v1, v2], &[web], true))];
        assert_eq!(
            scoped_capabilities(&state)["scopedArtifactContracts"],
            json!([v1, v2])
        );
        // A node without web tools removes them from the fleet's answer.
        state
            .backends
            .push(capability_node(capabilities(&[v1, v2], &[], true)));
        let body = scoped_capabilities(&state);
        assert_eq!(body["scopedArtifactContracts"], json!([v1, v2]));
        assert_eq!(body["scopedHttpsContracts"], json!([]));
        // The same probe gate as aggregate discovery.
        state.capability_probe_active.store(true, Ordering::Release);
        let response = request(
            &state,
            "GET",
            "/v1/capabilities",
            &format!("Authorization: Bearer {SCOPED}\r\n"),
            "",
        );
        assert_eq!(parse_status(&response), 503);
    }

    #[test]
    fn scoped_capabilities_fail_closed_without_an_eligible_node() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = scoped_state(dir.path());
        let empty = json!({
            "apiVersion": crate::capabilities::VERSION,
            "scopedArtifactContracts": [],
            "scopedHttpsContracts": [],
            "eligibleNodes": 0,
        });
        assert_eq!(scoped_capabilities(&state), empty);
        let full = {
            let mut report = capabilities(&["celln.scoped-artifacts/v1"], &[], true);
            report["node"]["live_cells"] = 4.into();
            report
        };
        state.backends = vec![
            capability_node(capabilities(&["celln.scoped-artifacts/v1"], &[], false)),
            capability_node(full),
        ];
        assert_eq!(scoped_capabilities(&state), empty);
    }

    #[test]
    fn capability_discovery_needs_a_known_bearer_and_keeps_node_detail_from_scoped() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = state(dir.path());
        state.backends = vec![capability_node(capabilities(
            &["celln.scoped-artifacts/v1"],
            &["celln.scoped-https/v1"],
            true,
        ))];
        // Scoped forwarding disabled: the scoped bearer is just a wrong token.
        let scoped = format!("Authorization: Bearer {SCOPED}\r\n");
        for header in [
            String::new(),
            "Authorization: Bearer wrong\r\n".into(),
            scoped.clone(),
        ] {
            let response = request(&state, "GET", "/v1/capabilities", &header, "");
            assert_eq!(parse_status(&response), 401, "{header}");
        }
        let file = dir.path().join("scoped");
        std::fs::write(&file, SCOPED).unwrap();
        state.scoped_token_file = Some(file);
        for header in [String::new(), "Authorization: Bearer wrong\r\n".into()] {
            let response = request(&state, "GET", "/v1/capabilities", &header, "");
            assert_eq!(parse_status(&response), 401, "{header}");
        }
        let body = scoped_capabilities(&state);
        let mut fields: Vec<_> = body.as_object().unwrap().keys().cloned().collect();
        fields.sort();
        assert_eq!(
            fields,
            [
                "apiVersion",
                "eligibleNodes",
                "scopedArtifactContracts",
                "scopedHttpsContracts"
            ]
        );
        let raw = request(&state, "GET", "/v1/capabilities", &scoped, "");
        assert!(!raw.contains("fixture") && !raw.contains(BACKEND_TOKEN));
        // The client credential still gets the aggregate per-node report.
        let response = request(
            &state,
            "GET",
            "/v1/capabilities",
            &format!("Authorization: Bearer {CLIENT_TOKEN}\r\n"),
            "",
        );
        assert_eq!(parse_status(&response), 200);
        let report: Value = serde_json::from_str(extract_body(&response)).unwrap();
        assert_eq!(report["nodes"][0]["report"]["node"]["node_name"], "fixture");
        assert_eq!(report["eligibleNodes"], 1);
    }
}
