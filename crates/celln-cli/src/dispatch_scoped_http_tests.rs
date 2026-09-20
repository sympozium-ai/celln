//! HTTP-level proofs of the scoped receiver: every case drives the real
//! `dispatch_http::handle` over a TCP socket with freshly signed fixture
//! capabilities. The `#[test]`s here boot no guest and run everywhere;
//! `prove_scoped_on_kvm` is the hardware half, called with real sealed
//! artifacts by `scoped_mediated_lifecycles_on_real_kvm` (`make conformance-kvm`).
use super::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::Instant;

pub(super) const OPERATOR: &str = "scoped-operator-credential-0123456789";
const ISSUER: &str = "sympozium-control-plane";
const JWKS: &[u8] =
    include_bytes!("../../../tests/fixtures/celln-authorisation/v1/signing/test-jwks.json");
/// Publicly known NON-PRODUCTION fixture seed for `test-key-1`.
const FIXTURE_SEED: [u8; 32] = [0x11; 32];

pub(super) fn unix_now() -> i64 {
    now()
}

/// Immutable runtime identity a prepared operation names. The hermetic cases
/// sign a synthetic closure; the hardware cases pass real sealed artifacts.
pub(super) struct Artifacts {
    pub mote: String,
    pub executable: String,
    pub closure: String,
    pub publisher: String,
    pub entry_point: String,
}

/// A signed, policy-trusted closure with no guest bytes behind it. Enough for
/// the receiver's publisher/closure checks; launching it would fail.
fn synthetic_artifacts(root: &Path) -> Artifacts {
    use celln_manifest::closure::{Closure, Member};
    let executable = Hash::of(b"scoped-http-runtime").0;
    let signed = Closure {
        api_version: "celln.dev/closure-v1".into(),
        sources: vec![],
        toolfs: Hash::of(b"scoped-http-toolfs").0,
        entrypoint: "/harness".into(),
        interpreter: false,
        members: BTreeMap::from([(
            "/harness".into(),
            Member {
                hash: executable.clone(),
                dependencies: Default::default(),
            },
        )]),
    }
    .sign(&[7; 32])
    .unwrap();
    let closure = Store::open(root.join("closures"))
        .unwrap()
        .put(&serde_json::to_vec(&signed).unwrap())
        .unwrap();
    fs::write(
        root.join("trusted-closures.json"),
        json!({"apiVersion":"celln.dev/closure-policy-v1","publishers":[signed.publisher],"revoked":[]})
            .to_string(),
    )
    .unwrap();
    Artifacts {
        mote: Hash::of(b"scoped-http-mote").0,
        executable,
        closure: closure.0,
        publisher: signed.publisher,
        entry_point: "/harness".into(),
    }
}

pub(super) struct NodeOptions<'a> {
    pub max_cells: u32,
    pub egress_slots: u32,
    pub gateway: Option<(&'a str, &'a Path)>,
    pub parent_template: Option<&'a Value>,
}

/// A dispatcher state whose scoped receiver came from the same
/// `ScopedState::configure` the `celln dispatcher --scoped-*` flags reach.
pub(super) fn node(root: &Path, options: NodeOptions<'_>) -> State {
    let mut state = super::super::tests::lifecycle_state(root);
    state.probe.max_cells = options.max_cells;
    state.probe.memory_bytes = 2u64 << 30;
    state.probe.egress_slots = options.egress_slots;
    state.parents = warden::parent_registry::ParentRegistry::new(4, 2u64 << 30).unwrap();
    fs::write(root.join("operator-token"), OPERATOR).unwrap();
    fs::write(root.join("jwks.json"), JWKS).unwrap();
    let template = options.parent_template.map(|template| {
        let path = root.join("scoped-parent-template.json");
        fs::write(&path, serde_json::to_vec(template).unwrap()).unwrap();
        path
    });
    state.scoped = ScopedState::configure(
        root,
        ScopedOptions {
            operator_token_file: Some(&root.join("operator-token")),
            jwks_file: Some(&root.join("jwks.json")),
            issuer: Some(ISSUER),
            gateway_origin: options.gateway.map(|(origin, _)| origin),
            gateway_ca: options.gateway.map(|(_, ca)| ca),
            parent_request_file: template.as_deref(),
        },
        &state.probe,
    )
    .unwrap();
    assert!(state.scoped.is_some(), "scoped receiver must be enabled");
    state
}

fn corpus() -> Value {
    let mut raw = Vec::new();
    flate2::read::GzDecoder::new(
        include_bytes!("../../../tests/fixtures/celln-authorisation/v1/cases.json.gz").as_slice(),
    )
    .take(4 << 20)
    .read_to_end(&mut raw)
    .unwrap();
    serde_json::from_slice(&raw).unwrap()
}

fn corpus_decision(vector: &str) -> Value {
    let cases = corpus();
    let vector = cases["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == vector)
        .unwrap();
    serde_json::from_str(
        cases["decisions"][vector["decisionRef"].as_str().unwrap()]["canonical"]
            .as_str()
            .unwrap(),
    )
    .unwrap()
}

#[derive(Clone, Copy)]
pub(super) struct Shape<'a> {
    pub lifecycle: &'a str,
    pub run_uid: &'a str,
    pub turn_id: Option<&'a str>,
    pub payload: &'a str,
    pub model: bool,
    /// Issue instant of this operation's admission window and turn deadline.
    pub issued: i64,
    /// Part of the run binding: every operation of one enduring run shares it.
    pub parent_deadline: i64,
}

/// What the operator prepared about model requests, and the budget signed
/// for them. The default is the corpus: no named cap, one request per turn.
#[derive(Clone, Copy)]
pub(super) struct Requests {
    /// `resolution.execution.requestOutputTokens`, when the operation names it.
    pub output_tokens: Option<u64>,
    /// The runtime profile's `json.maxTurns`.
    pub per_turn: u64,
    /// Signed `(turnCap, runCap)` requests and output tokens, when not the corpus's.
    pub budget: Option<((u64, u64), (u64, u64))>,
}

impl Default for Requests {
    fn default() -> Self {
        Self {
            output_tokens: None,
            per_turn: 1,
            budget: None,
        }
    }
}

/// A prepared operation plus the final decision Sympozium would sign for it,
/// derived from the shared schema-valid corpus and re-timed to `shape.issued`.
pub(super) fn compose(artifacts: &Artifacts, shape: Shape<'_>) -> (Value, Value) {
    compose_requests(artifacts, shape, Requests::default())
}

pub(super) fn compose_requests(
    artifacts: &Artifacts,
    shape: Shape<'_>,
    requests: Requests,
) -> (Value, Value) {
    let enduring = shape.lifecycle != "one-shot";
    let mut decision = corpus_decision(match shape.lifecycle {
        "one-shot" => "harness-one-shot",
        "enduring-initial" => "parent-create",
        _ => "enduring-turn",
    });
    if !shape.model {
        decision["route"] = corpus_decision("direct-one-shot")["route"].clone();
        decision["budget"]["runCap"] = json!({"requests":0,"outputTokens":0});
        decision["budget"]["turnCap"] = json!({"requests":0,"outputTokens":0});
    }
    if let Some((turn, run)) = requests.budget {
        decision["budget"]["turnCap"] = json!({"requests":turn.0,"outputTokens":turn.1});
        decision["budget"]["runCap"] = json!({"requests":run.0,"outputTokens":run.1});
    }
    decision["lifecycle"] = json!(shape.lifecycle);
    decision["operation"] = json!(if shape.turn_id.is_some() {
        "execution.turn"
    } else {
        "execution.start"
    });
    decision["tools"] = json!([]);
    decision["run"]["uid"] = json!(shape.run_uid);
    decision["subject"]["uid"] = json!(shape.run_uid);
    decision["budget"]["turnDeadlineUnix"] = json!(shape.issued + 120);
    decision["budget"]["parentDeadlineUnix"] =
        json!(if enduring { shape.parent_deadline } else { 0 });
    decision["windows"] = json!({"issuedAt":shape.issued,"notBefore":shape.issued,
        "admissionDeadline":shape.issued + 60});
    let source = json!({
        "clusterId":decision["clusterId"],"namespace":decision["run"]["namespace"],
        "namespaceUid":decision["run"]["namespaceUid"],"runName":decision["run"]["name"],
        "runUid":shape.run_uid,"runSpecSha256":decision["run"]["specSha256"]
    });
    decision["parent"] = if enduring {
        let scope = serde_json::to_string(&json!([
            "celln.scoped-parent/v1",
            source["clusterId"],
            source["namespaceUid"]
        ]))
        .unwrap();
        let incarnation = warden::parent_permit::run_incarnation(&scope, shape.run_uid).unwrap();
        json!({"incarnation":incarnation.0,"turnId":shape.turn_id})
    } else {
        Value::Null
    };
    let profile = json!({
        "revision":decision["runtime"]["revision"],"contractVersion":pilot::json_harness::CONTRACT,
        "executable":{"hash":artifacts.executable},"closure":{"hash":artifacts.closure},
        "mote":{"hash":artifacts.mote},"publisherKey":artifacts.publisher,
        "entryPoint":artifacts.entry_point,"platform":"linux/amd64","lane":"agent",
        "lifecycles":["disposable-one-shot","enduring"],
        "limits":{"timeoutMillis":60000,"memoryBytes":268435456,"taskBytes":2048,"outputBytes":65536,"workspace":"none"},
        // One model request per turn: a worker template reserves
        // maxTurns * 512 output tokens and the corpus turn cap is 512.
        "json":{"maxTurns":requests.per_turn,"maxCalls":0}
    });
    let wrapper = json!({"cellnProfileRef":{"name":"runtime","revision":"r1"},"image":"","contractVersion":"v1"});
    decision["runtime"]["specSha256"] = json!(digest_value(&json!({
        "wrapperSpec":wrapper,"profileName":"runtime","profileUid":"profile-uid",
        "profileDigest":digest_value(&profile).unwrap()
    }))
    .unwrap());
    let mut material = json!({
        "source":source,"wrapperSpec":wrapper,"profileName":"runtime","profileUid":"profile-uid",
        "profileSpec":profile,"tools":[],
        "runtimeLimits":{"timeoutMillis":60000,"memoryBytes":268435456,"taskBytes":2048,"outputBytes":65536,"workspace":"none"},
        "payload":shape.payload,"systemPrompt":"Answer briefly.","modelConnectionName":"",
        "credentialSourceRef":if shape.model {
            json!({"kind":"Secret","secretName":decision["route"]["credentialSource"]["secretName"],
                "secretKey":decision["route"]["credentialSource"]["secretKey"]})
        } else {
            Value::Null
        }
    });
    if let Some(turn) = shape.turn_id {
        material["turnUid"] = json!(turn);
    }
    if let Some(cap) = requests.output_tokens {
        material["requestOutputTokens"] = json!(cap);
    }
    let mut operation = json!({"apiVersion":"sympozium.ai/celln-prepared-operation-v1",
        "resolution":{"execution":material,"decision":Value::Null,"readSet":[]},"resolveRequest":{}});
    decision["requestDigest"] = json!(crate::tenancy_contract::digest(
        &external_request(&operation, &decision).unwrap()
    ));
    operation["resolution"]["decision"] = decision.clone();
    (operation, decision)
}

/// The same authority re-issued for `execution.read` / `execution.cleanup`.
pub(super) fn access_decision(decision: &Value, operation: &str) -> Value {
    let mut access = decision.clone();
    access["operation"] = json!(operation);
    access
}

pub(super) struct Permit<'a> {
    pub audience: &'a str,
    pub operation: &'a str,
    pub label: &'a str,
    pub issued: i64,
    pub expires: i64,
    pub seed: [u8; 32],
}

impl<'a> Permit<'a> {
    pub fn execution(decision: &'a Value, label: &'a str) -> Self {
        let issued = decision["windows"]["issuedAt"].as_i64().unwrap();
        Self {
            audience: "celln-execution",
            operation: decision["operation"].as_str().unwrap(),
            label,
            issued,
            expires: decision["windows"]["admissionDeadline"].as_i64().unwrap(),
            seed: FIXTURE_SEED,
        }
    }
    pub fn model(decision: &'a Value, label: &'a str) -> Self {
        Self {
            audience: "sympozium-model-gateway",
            operation: "model.invoke",
            label,
            issued: decision["windows"]["issuedAt"].as_i64().unwrap(),
            expires: decision["budget"]["turnDeadlineUnix"].as_i64().unwrap(),
            seed: FIXTURE_SEED,
        }
    }
    /// Read/cleanup capabilities are minted when used, not at admission.
    pub fn access(decision: &'a Value, label: &'a str) -> Self {
        let issued = decision["windows"]["issuedAt"].as_i64().unwrap();
        Self {
            audience: "celln-execution",
            operation: decision["operation"].as_str().unwrap(),
            label,
            issued,
            expires: issued + 240,
            seed: FIXTURE_SEED,
        }
    }
    pub fn sign(&self, decision: &Value) -> String {
        let canonical =
            crate::tenancy_contract::canonical(&serde_json::to_vec(decision).unwrap()).unwrap();
        let label = crate::tenancy_contract::digest(self.label.as_bytes());
        let jti = ["jti-", &label[7..39]].concat();
        let claims = json!({
            "apiVersion":"celln.sympozium.ai/authorisation-credential-v1","iss":ISSUER,
            "aud":self.audience,"iat":self.issued,"nbf":self.issued,"exp":self.expires,
            "jti":jti,
            "decisionDigest":crate::tenancy_contract::digest(&canonical),
            "budgetId":decision["budget"]["budgetId"],"operation":self.operation,
            "subject":{"runUid":decision["run"]["uid"],"turnId":decision["parent"]["turnId"],
                "parentIncarnation":decision["parent"]["incarnation"]}
        });
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD
                .encode(r#"{"alg":"EdDSA","typ":"celln-authorisation+jws","kid":"test-key-1"}"#),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
        );
        let signature = SigningKey::from_bytes(&self.seed).sign(input.as_bytes());
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
    }
}

#[derive(Default, Clone, Copy)]
pub(super) struct Headers<'a> {
    pub bearer: Option<&'a str>,
    pub execution: Option<&'a str>,
    pub model: Option<&'a str>,
}

impl<'a> Headers<'a> {
    pub fn operator() -> Self {
        Self {
            bearer: Some(OPERATOR),
            ..Self::default()
        }
    }
    pub fn permits(execution: &'a str, model: Option<&'a str>) -> Self {
        Self {
            bearer: Some(OPERATOR),
            execution: Some(execution),
            model,
        }
    }
}

/// One real request through the dispatcher's socket handler.
pub(super) fn send(
    state: &State,
    method: &str,
    path: &str,
    headers: Headers<'_>,
    body: &str,
) -> (u16, Value) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    let (server, _) = listener.accept().unwrap();
    let mut head = format!("{method} {path} HTTP/1.1\r\n");
    for (name, value) in [
        (
            "Authorization",
            headers.bearer.map(|v| format!("Bearer {v}")),
        ),
        (
            "X-Celln-Execution-Permit",
            headers.execution.map(str::to_owned),
        ),
        ("X-Celln-Model-Permit", headers.model.map(str::to_owned)),
    ] {
        if let Some(value) = value {
            head.push_str(&format!("{name}: {value}\r\n"));
        }
    }
    head.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    // The handler runs on this thread, so write from another: a prepared
    // operation may exceed what a loopback socket buffers unread.
    let body = body.to_owned();
    let writer = thread::spawn(move || {
        client.write_all(head.as_bytes()).unwrap();
        client.write_all(body.as_bytes()).unwrap();
        client
    });
    super::super::handle(server, state).unwrap();
    let mut client = writer.join().unwrap();
    let mut response = String::new();
    client.read_to_string(&mut response).unwrap();
    let status = response.split_whitespace().nth(1).unwrap().parse().unwrap();
    let body = serde_json::from_str(response.split_once("\r\n\r\n").unwrap().1).unwrap();
    (status, body)
}

pub(super) fn post(state: &State, route: &str, headers: Headers<'_>, body: &Value) -> (u16, Value) {
    send(
        state,
        "POST",
        &format!("/v1/scoped/{route}"),
        headers,
        &body.to_string(),
    )
}

/// Enrol and return `(id, owner)`.
pub(super) fn prepare(state: &State, operation: &Value, decision: &Value) -> (String, String) {
    let (status, body) = post(
        state,
        "prepare",
        Headers::operator(),
        &json!({"operation":operation,"decision":decision}),
    );
    assert_eq!(status, 200, "{body}");
    (
        body["id"].as_str().unwrap().to_owned(),
        body["owner"].as_str().unwrap().to_owned(),
    )
}

/// Every regular file beneath the state root, for "never stored" assertions.
pub(super) fn files_beneath(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut found = Vec::new();
    let mut pending = vec![root.to_owned()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            let metadata = fs::symlink_metadata(&path).unwrap();
            if metadata.is_dir() {
                pending.push(path);
            } else if metadata.is_file() {
                let bytes = fs::read(&path).unwrap();
                found.push((path, bytes));
            }
        }
    }
    found
}

pub(super) fn assert_never_stored(root: &Path, secrets: &[&str]) {
    for (path, bytes) in files_beneath(root) {
        for secret in secrets {
            assert!(
                !bytes
                    .windows(secret.len())
                    .any(|window| window == secret.as_bytes()),
                "a permit was written to {}",
                path.display()
            );
        }
    }
}

/// Stand-in for the Sympozium model gateway: real TLS (the relay speaks only
/// `https` through curl), served by `openssl s_server` because the workspace
/// deliberately links no TLS stack. Records what arrived; answers from a script.
pub(super) struct Gateway {
    child: Child,
    pub origin: String,
    pub ca: PathBuf,
    seen: Arc<Mutex<Vec<(String, Value)>>>,
}

impl Drop for Gateway {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Gateway {
    /// `answers[n]` is the assistant text of the n-th invocation.
    pub fn serve(directory: &Path, answers: Vec<String>) -> Self {
        let run = |command: &mut Command| {
            let output = command
                .output()
                .expect("the model-gateway fixture requires the openssl CLI");
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        };
        let (key, ca) = (
            directory.join("gateway-key.pem"),
            directory.join("gateway-ca.pem"),
        );
        run(Command::new("openssl")
            .args([
                "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
            ])
            .args([
                "-subj",
                "/CN=127.0.0.1",
                "-addext",
                "subjectAltName=IP:127.0.0.1",
            ])
            .arg("-keyout")
            .arg(&key)
            .arg("-out")
            .arg(&ca));
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let mut child = Command::new("openssl")
            .args([
                "s_server",
                "-quiet",
                "-accept",
                &format!("127.0.0.1:{port}"),
            ])
            .arg("-cert")
            .arg(&ca)
            .arg("-key")
            .arg(&key)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut plaintext = BufReader::new(child.stdout.take().unwrap());
        let mut reply = child.stdin.take().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let record = Arc::clone(&seen);
        // s_server relays each accepted connection's decrypted bytes in order.
        thread::spawn(move || {
            let mut answers = answers.into_iter();
            loop {
                let (mut length, mut authorization, mut target) = (0usize, String::new(), None);
                loop {
                    let mut line = String::new();
                    if std::io::BufRead::read_line(&mut plaintext, &mut line).unwrap_or(0) == 0 {
                        return;
                    }
                    let line = line.trim_end();
                    if line.is_empty() {
                        break;
                    }
                    if target.is_none() {
                        target = Some(line.to_owned());
                    } else if let Some((name, value)) = line.split_once(':') {
                        if name.eq_ignore_ascii_case("content-length") {
                            length = value.trim().parse().unwrap();
                        } else if name.eq_ignore_ascii_case("authorization") {
                            authorization = value.trim().to_owned();
                        }
                    }
                }
                let mut body = vec![0; length];
                if plaintext.read_exact(&mut body).is_err() {
                    return;
                }
                let envelope: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                record.lock().unwrap().push((
                    format!("{} {authorization}", target.unwrap_or_default()),
                    envelope,
                ));
                let answer = answers.next().unwrap_or_else(|| "unscripted".into());
                let body = json!({"choices":[{"index":0,"finish_reason":"stop",
                    "message":{"role":"assistant","content":answer}}],
                    "usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}})
                .to_string();
                if write!(reply, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).and_then(|()| reply.flush()).is_err() {
                    return;
                }
            }
        });
        let ready = Instant::now() + Duration::from_secs(10);
        while TcpStream::connect(("127.0.0.1", port)).is_err() {
            assert!(
                Instant::now() < ready,
                "model-gateway fixture never listened"
            );
            thread::sleep(Duration::from_millis(20));
        }
        Self {
            child,
            origin: format!("https://127.0.0.1:{port}"),
            ca,
            seen,
        }
    }

    /// `("POST /v1/invoke HTTP/1.1 Bearer <token>", envelope)` per invocation.
    pub fn seen(&self) -> Vec<(String, Value)> {
        self.seen.lock().unwrap().clone()
    }
}

fn template(artifacts: &Artifacts) -> Value {
    json!({"apiVersion":"celln.scoped-parent-template/v1","reservedMemoryBytes":1610612736u64,
        "request":{"apiVersion":"celln.dev/v1alpha1","id":"$parent",
            "workload":{"id":"$parent","caller":"$principal"},"mote":{"hash":artifacts.mote},
            "tools":[{"alias":"/parent","hash":artifacts.executable,"closure":{"hash":artifacts.closure}}],
            "invocation":{"alias":"/parent","args":[]},
            "capabilities":{"workspace":"none","timeoutMs":180000,"memoryBytes":268435456,"outputBytes":8192},
            "execution":{"lane":"agent","requireHardwareIsolation":true}}})
}

const GATEWAY: &str = "https://gateway.invalid";

fn one_shot<'a>(run_uid: &'a str, model: bool, issued: i64) -> Shape<'a> {
    Shape {
        lifecycle: "one-shot",
        run_uid,
        turn_id: None,
        payload: "Reply with CELLN.",
        model,
        issued,
        parent_deadline: 0,
    }
}

#[test]
fn scoped_routes_answer_disabled_until_the_operator_configures_the_receiver() {
    let root = tempfile::tempdir().unwrap();
    let state = super::super::tests::lifecycle_state(root.path());
    assert!(state.scoped.is_none());
    for route in ["prepare", "start", "read", "cleanup"] {
        for bearer in [None, Some(OPERATOR), Some(state.token.as_str())] {
            // Refused before the body is read, so none is sent: closing a
            // socket with unread bytes resets it and would lose the reply.
            let (status, body) = send(
                &state,
                "POST",
                &format!("/v1/scoped/{route}"),
                Headers {
                    bearer,
                    ..Headers::default()
                },
                "",
            );
            assert_eq!(status, 404, "{route}");
            assert_eq!(body, json!({"error":"scoped receiver disabled"}));
        }
    }
    assert!(!root.path().join("scoped").exists());
}

#[test]
fn gateway_and_parent_template_flags_require_the_receiver_and_each_other() {
    let root = tempfile::tempdir().unwrap();
    let artifacts = synthetic_artifacts(root.path());
    let probe = super::super::tests::lifecycle_state(root.path()).probe;
    fs::write(root.path().join("operator-token"), OPERATOR).unwrap();
    fs::write(root.path().join("jwks.json"), JWKS).unwrap();
    let parent = root.path().join("parent.json");
    fs::write(&parent, template(&artifacts).to_string()).unwrap();
    let (token, jwks) = (
        root.path().join("operator-token"),
        root.path().join("jwks.json"),
    );
    let configure =
        |credentials: bool, origin: Option<&str>, ca: Option<&Path>, template: Option<&Path>| {
            ScopedState::configure(
                root.path(),
                ScopedOptions {
                    operator_token_file: credentials.then_some(token.as_path()),
                    jwks_file: credentials.then_some(jwks.as_path()),
                    issuer: credentials.then_some(ISSUER),
                    gateway_origin: origin,
                    gateway_ca: ca,
                    parent_request_file: template,
                },
                &probe,
            )
            .map(|scoped| scoped.is_some())
            .map_err(|error| error.to_string())
        };
    // Gateway/parent flags never enable anything without the three credentials.
    assert!(configure(false, Some(GATEWAY), None, None).is_err());
    assert!(configure(false, None, None, Some(&parent)).is_err());
    assert!(configure(true, None, Some(&jwks), None).is_err());
    // The gateway is a fixed https origin: no plaintext, path or userinfo.
    for origin in [
        "http://gateway.invalid",
        "https://gateway.invalid/v1",
        "https://u:p@gateway.invalid",
    ] {
        assert!(
            configure(true, Some(origin), None, None).is_err(),
            "{origin}"
        );
    }
    // Enduring parents are mediated by construction.
    assert_eq!(
        configure(true, None, None, Some(&parent)).unwrap_err(),
        "scoped enduring parent template requires the mediated gateway"
    );
    assert_eq!(configure(true, None, None, None), Ok(true));
    assert_eq!(configure(true, Some(GATEWAY), None, None), Ok(true));
    assert_eq!(
        configure(true, Some(GATEWAY), None, Some(&parent)),
        Ok(true)
    );
    // A template may not smuggle standing egress or a credential reference.
    let mut egress = template(&artifacts);
    egress["request"]["capabilities"]["egress"] = json!(["https://model.example"]);
    fs::write(&parent, egress.to_string()).unwrap();
    assert!(configure(true, Some(GATEWAY), None, Some(&parent)).is_err());
    let mut credential = template(&artifacts);
    credential["request"]["credentialFile"] = json!("/etc/provider-key");
    fs::write(&parent, credential.to_string()).unwrap();
    assert!(configure(true, Some(GATEWAY), None, Some(&parent)).is_err());
}

/// What `--scoped-parent-request-file <file holding raw>` answers on an
/// otherwise fully configured mediated receiver rooted at `root`.
pub(crate) fn parent_request_file_accepted(root: &Path, raw: &[u8]) -> Result<(), String> {
    let probe = super::super::tests::lifecycle_state(root).probe;
    let (token, jwks, parent) = (
        root.join("operator-token"),
        root.join("jwks.json"),
        root.join("scoped-parent-request.json"),
    );
    fs::write(&token, OPERATOR).unwrap();
    fs::write(&jwks, JWKS).unwrap();
    fs::write(&parent, raw).unwrap();
    ScopedState::configure(
        root,
        ScopedOptions {
            operator_token_file: Some(&token),
            jwks_file: Some(&jwks),
            issuer: Some(ISSUER),
            gateway_origin: Some(GATEWAY),
            gateway_ca: None,
            parent_request_file: Some(&parent),
        },
        &probe,
    )
    .map(|_| ())
    .map_err(|error| error.to_string())
}

#[test]
fn the_starter_parent_request_is_the_scoped_parent_template_and_stays_credential_free() {
    let root = tempfile::tempdir().unwrap();
    let artifacts = synthetic_artifacts(root.path());
    // The parent request `starter-configure` builds for its reviewed package.
    let parent: ExecutionRequest = serde_json::from_value(json!({
        "apiVersion":"celln.dev/v1alpha1","id":"native-parent",
        "workload":{"id":"native-parent","caller":"operator:native-test"},
        "mote":{"hash":artifacts.mote},
        "tools":[{"alias":"/parent","hash":artifacts.executable,"closure":{"hash":artifacts.closure}}],
        "invocation":{"alias":"/parent","args":[]},
        "capabilities":{"workspace":"none","timeoutMs":3600000,"memoryBytes":268435456u64,"outputBytes":65536},
        "execution":{"lane":"agent","requireHardwareIsolation":true}
    }))
    .unwrap();
    let template = crate::starter_configure::scoped_parent_request(&parent);
    assert_eq!(template["apiVersion"], "celln.scoped-parent-template/v1");
    assert_eq!(
        template["request"]["workload"],
        json!({"id":"$parent","caller":"$principal"})
    );
    // Nothing but the per-run placeholders differs from the reviewed request.
    let mut restored = template["request"].clone();
    restored["id"] = json!("native-parent");
    restored["workload"] = json!({"id":"native-parent","caller":"operator:native-test"});
    assert_eq!(restored, serde_json::to_value(&parent).unwrap());
    // It reserves room for the parent, one worker and their substrate overhead.
    assert!(template["reservedMemoryBytes"].as_u64().unwrap() > 4 * 268435456);
    let accepted = |template: &Value| {
        parent_request_file_accepted(root.path(), &serde_json::to_vec_pretty(template).unwrap())
    };
    assert_eq!(accepted(&template), Ok(()));
    // The operator's principal is never a standing template identity…
    let mut named = template.clone();
    named["request"]["workload"]["caller"] = json!("operator:native-test");
    assert!(accepted(&named).is_err());
    // …and the file is refused with egress or a credential reference in it,
    // as a native-template.json (parent + worker + model profile) is outright.
    let mut egress = template.clone();
    egress["request"]["capabilities"]["egress"] = json!(["https://model.example"]);
    assert!(accepted(&egress).is_err());
    let mut credential = template.clone();
    credential["credentialFile"] = json!("/etc/celln-native/provider-key");
    assert!(accepted(&credential).is_err());
    assert!(
        accepted(&json!({"parent":template["request"],"reservedMemoryBytes":1342177280u64}))
            .is_err()
    );
}

#[test]
fn only_the_scoped_operator_bearer_reaches_a_scoped_route() {
    let root = tempfile::tempdir().unwrap();
    let artifacts = synthetic_artifacts(root.path());
    let state = node(
        root.path(),
        NodeOptions {
            max_cells: 1,
            egress_slots: 0,
            gateway: None,
            parent_template: None,
        },
    );
    let (operation, decision) = compose(&artifacts, one_shot("bearer-run", false, unix_now()));
    let body = json!({"operation":operation,"decision":decision});
    // The node credential of /v1/executions is a different authority.
    for bearer in [
        None,
        Some("wrong-credential-at-least-24-bytes"),
        Some(state.token.as_str()),
    ] {
        for route in ["prepare", "start", "read", "cleanup"] {
            let (status, reply) = send(
                &state,
                "POST",
                &format!("/v1/scoped/{route}"),
                Headers {
                    bearer,
                    ..Headers::default()
                },
                "",
            );
            assert_eq!(
                (status, &reply),
                (401, &json!({"error":"unauthorized"})),
                "{route}"
            );
        }
    }
    assert_eq!(
        fs::read_dir(root.path().join("scoped/prepared"))
            .unwrap()
            .count(),
        0
    );
    let (status, _) = send(&state, "GET", "/v1/scoped/prepare", Headers::operator(), "");
    assert_eq!(status, 404);
    let (status, _) = post(&state, "unknown", Headers::operator(), &body);
    assert_eq!(status, 404);
    let (status, reply) = send(
        &state,
        "POST",
        "/v1/scoped/prepare",
        Headers::operator(),
        r#"{"a":1,"a":2}"#,
    );
    assert_eq!(status, 400, "{reply}");
    assert_eq!(post(&state, "prepare", Headers::operator(), &body).0, 200);
    // Rotation is re-read per request and fails closed, without a restart.
    fs::remove_file(root.path().join("operator-token")).unwrap();
    let (status, reply) = send(
        &state,
        "POST",
        "/v1/scoped/prepare",
        Headers::operator(),
        "",
    );
    assert_eq!(
        (status, reply),
        (503, json!({"error":"scoped receiver unavailable"}))
    );
}

/// `(status, reason)` of a start attempt.
fn refused_start(state: &State, id: &str, owner: &str, headers: Headers<'_>) -> (u16, Value) {
    let (status, body) = post(state, "start", headers, &json!({"id":id,"owner":owner}));
    (status, body["reason"].clone())
}

#[test]
fn start_refuses_wrong_audience_forged_expired_and_late_permits_without_burning_the_run() {
    let root = tempfile::tempdir().unwrap();
    let artifacts = synthetic_artifacts(root.path());
    let state = node(
        root.path(),
        NodeOptions {
            max_cells: 1,
            egress_slots: 0,
            gateway: Some((GATEWAY, Path::new("/nonexistent-ca"))),
            parent_template: None,
        },
    );
    let issued = unix_now();
    let (operation, decision) = compose(&artifacts, one_shot("audience-run", true, issued));
    let (id, owner) = prepare(&state, &operation, &decision);
    let execution = Permit::execution(&decision, "audience-execution").sign(&decision);
    let model = Permit::model(&decision, "audience-model").sign(&decision);

    let (status, body) = post(
        &state,
        "start",
        Headers::operator(),
        &json!({"id":id,"owner":owner}),
    );
    assert_eq!(
        (status, body),
        (401, json!({"error":"execution permit required"}))
    );
    for (headers, reason) in [
        // A model capability is not execution authority, and vice versa.
        (Headers::permits(&model, Some(&model)), "AUTH_AUD_MISMATCH"),
        (
            Headers::permits(&execution, Some(&execution)),
            "AUTH_AUD_MISMATCH",
        ),
        // A model route needs its own capability.
        (Headers::permits(&execution, None), "AUTH_CRED_MALFORMED"),
    ] {
        assert_eq!(
            refused_start(&state, &id, &owner, headers),
            (401, json!(reason))
        );
    }
    let forged = Permit {
        seed: [0x33; 32],
        ..Permit::execution(&decision, "forged")
    }
    .sign(&decision);
    assert_eq!(
        refused_start(&state, &id, &owner, Headers::permits(&forged, Some(&model))),
        (401, json!("AUTH_CRED_SIG_INVALID"))
    );
    let expired = Permit {
        issued: issued - 120,
        expires: issued - 60,
        ..Permit::execution(&decision, "expired")
    }
    .sign(&decision);
    assert_eq!(
        refused_start(
            &state,
            &id,
            &owner,
            Headers::permits(&expired, Some(&model))
        ),
        (401, json!("AUTH_TIME_EXPIRED"))
    );
    // A permit for another run's decision cannot start this one.
    let (_, other) = compose(&artifacts, one_shot("another-run", true, issued));
    let foreign = Permit::execution(&other, "foreign").sign(&other);
    assert_eq!(
        refused_start(
            &state,
            &id,
            &owner,
            Headers::permits(&foreign, Some(&model))
        ),
        (401, json!("AUTH_DECISION_DIGEST_MISMATCH"))
    );

    // A decision whose admission window has closed, presented with an unexpired permit.
    let (late_operation, late_decision) =
        compose(&artifacts, one_shot("late-run", true, issued - 100));
    let (late_id, late_owner) = prepare(&state, &late_operation, &late_decision);
    let late = Permit {
        expires: issued + 30,
        ..Permit::execution(&late_decision, "late")
    }
    .sign(&late_decision);
    let late_model = Permit::model(&late_decision, "late-model").sign(&late_decision);
    assert_eq!(
        refused_start(
            &state,
            &late_id,
            &late_owner,
            Headers::permits(&late, Some(&late_model))
        ),
        (401, json!("AUTH_ADMISSION_WINDOW_EXPIRED"))
    );

    // None of the refusals wrote a status, claimed the run or reserved capacity…
    assert_eq!(
        fs::read_dir(root.path().join("scoped/status"))
            .unwrap()
            .count(),
        0
    );
    assert!(state.executions.lock().unwrap().is_empty());
    // …so the correctly addressed pair is still a FRESH admission (this node
    // advertises no broker slot, which is only checked after the durable claim).
    let (status, body) = post(
        &state,
        "start",
        Headers::permits(&execution, Some(&model)),
        &json!({"id":id,"owner":owner}),
    );
    assert_eq!(status, 503, "{body}");
    assert_eq!(body["reason"], "AUTH_CAPACITY");
    assert_never_stored(root.path(), &[&execution, &model, &forged, &expired]);
}

#[test]
fn model_permits_and_model_routes_must_match_the_receiver_configuration() {
    let root = tempfile::tempdir().unwrap();
    let artifacts = synthetic_artifacts(root.path());
    let state = node(
        root.path(),
        NodeOptions {
            max_cells: 1,
            egress_slots: 0,
            gateway: None,
            parent_template: None,
        },
    );
    let (operation, decision) = compose(&artifacts, one_shot("direct-run", false, unix_now()));
    let (id, owner) = prepare(&state, &operation, &decision);
    let execution = Permit::execution(&decision, "direct-execution").sign(&decision);
    // Verifies as a signature, but a model-free decision derives no model capability.
    let model = Permit::model(&decision, "direct-model").sign(&decision);
    assert_eq!(
        refused_start(
            &state,
            &id,
            &owner,
            Headers::permits(&execution, Some(&model))
        ),
        (401, json!("AUTH_ROUTE_MISMATCH"))
    );
    assert_eq!(
        fs::read_dir(root.path().join("scoped/status"))
            .unwrap()
            .count(),
        0
    );
    // Conversely, a model route on a receiver with no configured gateway is
    // refused terminally: there is no direct-to-provider fallback.
    let (operation, decision) = compose(&artifacts, one_shot("ungatewayed-run", true, unix_now()));
    let (id, owner) = prepare(&state, &operation, &decision);
    let execution = Permit::execution(&decision, "ungatewayed-execution").sign(&decision);
    let model = Permit::model(&decision, "ungatewayed-model").sign(&decision);
    let (status, body) = post(
        &state,
        "start",
        Headers::permits(&execution, Some(&model)),
        &json!({"id":id,"owner":owner}),
    );
    assert_eq!(status, 422, "{body}");
    assert_eq!(
        (&body["phase"], &body["reason"]),
        (&json!("Refused"), &json!("AUTH_CONTEXT_LOST"))
    );
    assert!(state.executions.lock().unwrap().is_empty());
}

#[test]
fn one_shot_prepare_start_read_cleanup_is_durable_idempotent_and_permit_free_on_disk() {
    let root = tempfile::tempdir().unwrap();
    let artifacts = synthetic_artifacts(root.path());
    // No broker slot: admission is refused AFTER verification, the durable
    // claim and mediated-broker construction, identically with or without KVM.
    let state = node(
        root.path(),
        NodeOptions {
            max_cells: 1,
            egress_slots: 0,
            gateway: Some((GATEWAY, Path::new("/nonexistent-ca"))),
            parent_template: None,
        },
    );
    let issued = unix_now();
    let (operation, decision) = compose(&artifacts, one_shot("lifecycle-run", true, issued));
    let (id, owner) = prepare(&state, &operation, &decision);
    assert!(id.starts_with("sha256:") && owner.starts_with("sha256:"));
    assert_eq!(
        prepare(&state, &operation, &decision),
        (id.clone(), owner.clone())
    );
    // Same run identity, different content: enrolment is immutable.
    let (changed_operation, changed_decision) = compose(
        &artifacts,
        Shape {
            payload: "Reply with something else.",
            ..one_shot("lifecycle-run", true, issued)
        },
    );
    let (status, body) = post(
        &state,
        "prepare",
        Headers::operator(),
        &json!({"operation":changed_operation,"decision":changed_decision}),
    );
    assert_eq!(status, 409, "{body}");
    // A decision the prepared operation does not resolve to is not enrolled.
    let mut widened = decision.clone();
    widened["budget"]["turnCap"]["requests"] = json!(6);
    let (status, body) = post(
        &state,
        "prepare",
        Headers::operator(),
        &json!({"operation":operation,"decision":widened}),
    );
    assert_eq!(status, 422, "{body}");

    let execution = Permit::execution(&decision, "lifecycle-execution").sign(&decision);
    let model = Permit::model(&decision, "lifecycle-model").sign(&decision);
    let start = |owner: &str, execution: &str| {
        post(
            &state,
            "start",
            Headers::permits(execution, Some(&model)),
            &json!({"id":id,"owner":owner}),
        )
    };
    // The caller must echo the owner epoch /prepare returned.
    let stale = format!("sha256:{}", "0".repeat(64));
    let (status, body) = start(&stale, &execution);
    assert_eq!(
        (status, body["reason"].as_str()),
        (409, Some("AUTH_CONTEXT_LOST"))
    );

    let (status, refused) = start(&owner, &execution);
    assert_eq!(status, 503, "{refused}");
    assert_eq!(refused["id"], id);
    assert_eq!(refused["owner"], owner);
    assert_eq!(refused["phase"], "Refused");
    assert_eq!(refused["reason"], "AUTH_CAPACITY");
    assert_eq!(refused["cleanupConfirmed"], true);
    assert!(refused.get("cellId").is_none() && refused.get("receiptDigest").is_none());
    assert!(
        state.executions.lock().unwrap().is_empty(),
        "refusal reserved capacity"
    );

    // A replayed permit, and a freshly minted one for the same run, both
    // recover the original terminal status instead of admitting again.
    let reminted = Permit::execution(&decision, "lifecycle-execution-2").sign(&decision);
    for permit in [&execution, &reminted] {
        assert_eq!(start(&owner, permit), (200, refused.clone()));
    }
    assert!(state.executions.lock().unwrap().is_empty());

    let read_decision = access_decision(&decision, "execution.read");
    let read = Permit::access(&read_decision, "lifecycle-read").sign(&read_decision);
    let cleanup_decision = access_decision(&decision, "execution.cleanup");
    let cleanup = Permit::access(&cleanup_decision, "lifecycle-cleanup").sign(&cleanup_decision);
    let access = |route: &str, permit: &str, decision: &Value| {
        post(
            &state,
            route,
            Headers::permits(permit, None),
            &json!({"id":id,"decision":decision}),
        )
    };
    assert_eq!(
        access("read", &read, &read_decision),
        (200, refused.clone())
    );
    // Read, cleanup and start capabilities are not interchangeable.
    for (route, permit, decision) in [
        ("read", &cleanup, &read_decision),
        ("cleanup", &read, &cleanup_decision),
        ("read", &execution, &read_decision),
        ("read", &model, &read_decision),
    ] {
        assert_eq!(access(route, permit, decision).0, 401, "{route}");
    }
    assert_eq!(access("read", &read, &cleanup_decision).0, 409);
    // An access decision may change operation/windows only.
    let mut escalated = read_decision.clone();
    escalated["budget"]["runCap"]["requests"] = json!(60);
    let escalated_permit = Permit::access(&escalated, "lifecycle-escalated").sign(&escalated);
    let (status, body) = access("read", &escalated_permit, &escalated);
    assert_eq!(
        (status, body),
        (
            409,
            json!({"error":"access decision changed original authority"})
        )
    );
    assert_eq!(
        access("cleanup", &cleanup, &cleanup_decision),
        (200, refused.clone())
    );

    // Losing the status file must not turn a replay into a second launch.
    fs::remove_file(state.scoped.as_ref().unwrap().status_path(&id).unwrap()).unwrap();
    let (status, body) = start(&owner, &execution);
    assert_eq!(status, 202, "{body}");
    assert_eq!(body["phase"], "Uncertain");
    assert_eq!(
        body["reason"],
        "original owner status is unavailable; replay refused"
    );
    assert!(state.executions.lock().unwrap().is_empty());

    assert_never_stored(
        root.path(),
        &[&execution, &reminted, &model, &read, &cleanup],
    );
    assert!(!root.path().join("trusted-harness").exists());
}

#[test]
fn a_restarted_receiver_reports_context_lost_instead_of_re_admitting() {
    let root = tempfile::tempdir().unwrap();
    let artifacts = synthetic_artifacts(root.path());
    let options = || NodeOptions {
        max_cells: 1,
        egress_slots: 0,
        gateway: Some((GATEWAY, Path::new("/nonexistent-ca"))),
        parent_template: None,
    };
    let (operation, decision) = compose(&artifacts, one_shot("restart-run", true, unix_now()));
    let execution = Permit::execution(&decision, "restart-execution").sign(&decision);
    let model = Permit::model(&decision, "restart-model").sign(&decision);
    let (id, owner) = {
        let first = node(root.path(), options());
        prepare(&first, &operation, &decision)
    };
    let restarted = node(root.path(), options());
    let epoch = restarted
        .scoped
        .as_ref()
        .unwrap()
        .admission
        .owner()
        .to_owned();
    assert_ne!(epoch, owner, "each receiver process is a new owner epoch");
    // Re-preparing reports the ORIGINAL enrolment owner, never the new epoch.
    assert_eq!(
        prepare(&restarted, &operation, &decision),
        (id.clone(), owner.clone())
    );
    for claimed in [&owner, &epoch] {
        let (status, body) = post(
            &restarted,
            "start",
            Headers::permits(&execution, Some(&model)),
            &json!({"id":id,"owner":claimed}),
        );
        assert_eq!(status, 409, "{body}");
        assert_eq!(body["reason"], "AUTH_CONTEXT_LOST");
    }
    assert!(restarted.executions.lock().unwrap().is_empty());
    assert_eq!(
        fs::read_dir(root.path().join("scoped/status"))
            .unwrap()
            .count(),
        0
    );
}

#[test]
fn a_one_shot_model_route_is_brokered_only_through_the_gateway_with_the_model_permit() {
    let root = tempfile::tempdir().unwrap();
    let artifacts = synthetic_artifacts(root.path());
    let gateway = Gateway::serve(root.path(), vec!["CELLN".into()]);
    let state = node(
        root.path(),
        NodeOptions {
            max_cells: 1,
            egress_slots: 1,
            gateway: Some((&gateway.origin, &gateway.ca)),
            parent_template: None,
        },
    );
    let scoped = state.scoped.as_ref().unwrap();
    let (operation, decision) = compose(&artifacts, one_shot("broker-run", true, unix_now()));
    let (id, _) = prepare(&state, &operation, &decision);
    let prepared = scoped.load_prepared(&id).unwrap();
    let execution = Permit::execution(&decision, "broker-execution").sign(&decision);
    let model = Permit::model(&decision, "broker-model").sign(&decision);
    let receiver = receiver_context(&operation, &decision, "execution.start").unwrap();
    let control = operation_control(&prepared).unwrap();
    let (native, broker) = build_native(
        scoped,
        &prepared,
        &receiver,
        &execution,
        Some(&model),
        &control,
    )
    .unwrap();
    let mut broker = broker.expect("a model route owns a broker");
    assert!(broker.is_mediated());
    // The guest gets a logical alias and no standing egress; the signed
    // provider origin never reaches the native request.
    assert!(native.capabilities.egress.is_empty());
    let native_text = serde_json::to_string(&native).unwrap();
    assert!(native_text.contains("celln-model.invalid") && !native_text.contains("model.example"));
    assert!(!native_text.contains(&model) && !native_text.contains(&execution));

    let route_model = decision["route"]["model"].as_str().unwrap();
    let wire = |url: &str| {
        json!({"apiVersion":"celln.fetch/v1","method":"POST","url":url,
            "body":{"model":route_model,"stream":false,"max_tokens":64,
                "messages":[{"role":"user","content":"Reply with CELLN."}]}})
        .to_string()
    };
    // The guest cannot name the provider (or the gateway) as a destination.
    for url in [
        "https://model.example/v1/chat/completions",
        gateway.origin.as_str(),
    ] {
        assert!(broker.fetch(&wire(url)).is_err(), "{url}");
    }
    assert!(gateway.seen().is_empty());
    let answer = broker.fetch(&wire(MODEL_ALIAS)).unwrap();
    assert!(String::from_utf8(answer).unwrap().contains("CELLN"));
    let seen = gateway.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(
        seen[0].0,
        format!("POST /v1/invoke HTTP/1.1 Bearer {model}")
    );
    assert_eq!(seen[0].1["decision"], decision);
    assert_eq!(seen[0].1["request"]["model"], route_model);
    let request_id = seen[0].1["requestId"].as_str().unwrap();
    assert!(
        request_id.starts_with("celln:sha256:") && request_id.ends_with(":1"),
        "{request_id}"
    );
    // The turn cap (2 requests) is a local ceiling on the same owned context.
    assert!(broker.fetch(&wire(MODEL_ALIAS)).is_ok());
    assert!(broker.fetch(&wire(MODEL_ALIAS)).is_err());
    assert_eq!(gateway.seen().len(), 2);
    assert_never_stored(root.path(), &[&execution, &model]);
}

/// Signed room for `per_turn` requests of `cap` tokens per turn, six per run.
fn roomy(cap: u64, per_turn: u64) -> Option<((u64, u64), (u64, u64))> {
    Some(((per_turn, per_turn * cap), (6, 6 * cap)))
}

#[test]
fn a_prepared_output_cap_is_range_checked_and_affordable_before_anything_is_enrolled() {
    let root = tempfile::tempdir().unwrap();
    let artifacts = synthetic_artifacts(root.path());
    let parent = template(&artifacts);
    let state = node(
        root.path(),
        NodeOptions {
            max_cells: 2,
            egress_slots: 1,
            gateway: Some((GATEWAY, Path::new("/nonexistent-ca"))),
            parent_template: Some(&parent),
        },
    );
    let issued = unix_now();
    let enrol = |shape: Shape<'_>, requests: Requests| {
        let (operation, decision) = compose_requests(&artifacts, shape, requests);
        post(
            &state,
            "prepare",
            Headers::operator(),
            &json!({"operation":operation,"decision":decision}),
        )
    };
    let refused = |shape: Shape<'_>, requests: Requests, reason: &str| {
        let (status, body) = enrol(shape, requests);
        assert_eq!(
            (status, body["reason"].as_str()),
            (422, Some(reason)),
            "{body}"
        );
    };
    let range = "AUTH_LIMIT_OUT_OF_RANGE";
    // Outside 256..=4096 is refused however much the budget would afford.
    for cap in [0, 255, 4097, u64::MAX >> 11] {
        let requests = Requests {
            output_tokens: Some(cap),
            budget: roomy(8192, 1),
            ..Requests::default()
        };
        refused(one_shot("ranged-one-shot", true, issued), requests, range);
        refused(
            enduring("ranged-parent", None, true, issued),
            requests,
            range,
        );
    }
    // Only an integer names a cap: no string, null or fraction is coerced.
    for cap in [json!("2048"), Value::Null, json!(-2048), json!([2048])] {
        let (mut operation, decision) =
            compose(&artifacts, one_shot("typed-one-shot", true, issued));
        operation["resolution"]["execution"]["requestOutputTokens"] = cap;
        let (status, body) = post(
            &state,
            "prepare",
            Headers::operator(),
            &json!({"operation":operation,"decision":decision}),
        );
        assert_eq!(
            (status, body["reason"].as_str()),
            (422, Some(range)),
            "{body}"
        );
    }
    // A model-free operation makes no model request for a cap to shape.
    refused(
        one_shot("model-free-capped", false, issued),
        Requests {
            output_tokens: Some(2048),
            ..Requests::default()
        },
        "AUTH_ROUTE_MISMATCH",
    );

    // A one-shot must afford its first request from the turn and the run.
    let raised = Requests {
        output_tokens: Some(2048),
        ..Requests::default()
    };
    // (the corpus turn cap is 512)
    refused(
        one_shot("unaffordable-one-shot", true, issued),
        raised,
        range,
    );
    for budget in [((2, 2047), (6, 12288)), ((2, 2048), (6, 2047))] {
        refused(
            one_shot("unaffordable-one-shot", true, issued),
            Requests {
                budget: Some(budget),
                ..raised
            },
            range,
        );
    }
    // A retained worker reserves its whole model loop each turn, so the loop
    // at the cap must fit: at the default cap too, where it used to fail at
    // the first turn with the parent VM already running.
    let looped = Requests {
        per_turn: 2,
        ..Requests::default()
    };
    refused(
        enduring("unaffordable-parent", None, true, issued),
        looped,
        range,
    );
    refused(
        enduring("unaffordable-parent", Some("turn-1"), true, issued),
        looped,
        range,
    );
    for budget in [((2, 4095), (6, 12288)), ((2, 4096), (6, 4095))] {
        refused(
            enduring("unaffordable-parent", None, true, issued),
            Requests {
                output_tokens: Some(2048),
                per_turn: 2,
                budget: Some(budget),
            },
            range,
        );
    }
    // None of that enrolled an operation, claimed a run or touched a parent.
    assert_eq!(
        fs::read_dir(root.path().join("scoped/prepared"))
            .unwrap()
            .count(),
        0
    );
    // The same shape enrolled by a receiver that predates the check is refused
    // when started: durably, before any parent permit, owner or VM exists.
    let scoped = state.scoped.as_ref().unwrap();
    let (operation, decision) = compose_requests(
        &artifacts,
        enduring("enrolled-parent", None, true, issued),
        looped,
    );
    let id = operation_id(&operation, &decision).unwrap();
    let record = PreparedRecord {
        version: 1,
        id: id.clone(),
        owner: scoped.admission.owner().to_owned(),
        operation,
        decision: decision.clone(),
    };
    write_new(
        &scoped.prepared_path(&id).unwrap(),
        &serde_json::to_vec(&record).unwrap(),
    )
    .unwrap();
    let execution = Permit::execution(&decision, "enrolled-parent").sign(&decision);
    let model = Permit::model(&decision, "enrolled-parent").sign(&decision);
    let (status, body) = post(
        &state,
        "start",
        Headers::permits(&execution, Some(&model)),
        &json!({"id":id,"owner":record.owner}),
    );
    assert_eq!(status, 422, "{body}");
    assert_eq!(
        (&body["phase"], &body["reason"], &body["cleanupConfirmed"]),
        (&json!("Refused"), &json!(range), &json!(true))
    );
    fs::remove_file(scoped.prepared_path(&id).unwrap()).unwrap();
    no_native_custody(&state);
    assert!(!root.path().join("parent-journal").exists());
    assert_eq!(
        fs::read_dir(root.path().join("trusted-parent-permits"))
            .unwrap()
            .count(),
        0
    );

    // The same shapes are enrolled once the signed budget covers them.
    for (shape, requests) in [
        (
            one_shot("affordable-one-shot", true, issued),
            Requests {
                budget: roomy(2048, 1),
                ..raised
            },
        ),
        (
            // Two requests of 2048 signed; the one-shot needs only the first.
            one_shot("looping-one-shot", true, issued),
            Requests {
                per_turn: 6,
                budget: roomy(2048, 2),
                ..raised
            },
        ),
        (
            enduring("affordable-parent", None, true, issued),
            Requests {
                budget: Some(((2, 1024), (6, 3072))),
                ..looped
            },
        ),
        (
            enduring("affordable-roomy-parent", None, true, issued),
            Requests {
                output_tokens: Some(4096),
                per_turn: 2,
                budget: roomy(4096, 2),
            },
        ),
    ] {
        let (status, body) = enrol(shape, requests);
        assert_eq!(status, 200, "{body}");
    }
}

#[test]
fn the_prepared_output_cap_shapes_the_worker_request_and_bounds_its_broker() {
    let root = tempfile::tempdir().unwrap();
    let artifacts = synthetic_artifacts(root.path());
    let gateway = Gateway::serve(root.path(), vec!["CELLN".into(), "CELLN".into()]);
    let state = node(
        root.path(),
        NodeOptions {
            max_cells: 1,
            egress_slots: 1,
            gateway: Some((&gateway.origin, &gateway.ca)),
            parent_template: None,
        },
    );
    let scoped = state.scoped.as_ref().unwrap();
    let built = |run: &str, requests: Requests| {
        let (operation, decision) =
            compose_requests(&artifacts, one_shot(run, true, unix_now()), requests);
        let (id, _) = prepare(&state, &operation, &decision);
        let prepared = scoped.load_prepared(&id).unwrap();
        let execution = Permit::execution(&decision, run).sign(&decision);
        let model = Permit::model(&decision, run).sign(&decision);
        let receiver = receiver_context(&operation, &decision, "execution.start").unwrap();
        let control = operation_control(&prepared).unwrap();
        let (native, broker) = build_native(
            scoped,
            &prepared,
            &receiver,
            &execution,
            Some(&model),
            &control,
        )
        .unwrap();
        let config: Value =
            serde_json::from_str(&native.invocation.as_ref().unwrap().args[0]).unwrap();
        (config, broker.unwrap(), decision)
    };
    let wire = |model: &Value, tokens: u64| {
        json!({"apiVersion":"celln.fetch/v1","method":"POST","url":MODEL_ALIAS,
            "body":{"model":model,"stream":false,"max_tokens":tokens,
                "messages":[{"role":"user","content":"Reply with CELLN."}]}})
        .to_string()
    };

    // Unnamed: the guest asks for the default and may not ask for more, even
    // though the signed turn would afford it.
    let (config, mut broker, decision) = built(
        "default-cap-run",
        Requests {
            budget: roomy(2048, 1),
            ..Requests::default()
        },
    );
    assert!(config.get("max_tokens").is_none(), "{config}");
    let model = &decision["route"]["model"];
    assert!(broker.fetch(&wire(model, 513)).is_err());
    assert!(gateway.seen().is_empty());
    assert!(broker.fetch(&wire(model, 512)).is_ok());
    assert_eq!(gateway.seen()[0].1["request"]["max_tokens"], 512);

    // Named: it is the worker's `max_tokens` and the broker's per-request bound.
    let (config, mut broker, _) = built(
        "raised-cap-run",
        Requests {
            output_tokens: Some(2048),
            budget: roomy(2048, 1),
            ..Requests::default()
        },
    );
    assert_eq!(config["max_tokens"], 2048);
    assert!(broker.fetch(&wire(model, 2049)).is_err());
    assert_eq!(gateway.seen().len(), 1);
    assert!(broker.fetch(&wire(model, 2048)).is_ok());
    assert_eq!(gateway.seen()[1].1["request"]["max_tokens"], 2048);
}

fn enduring<'a>(run_uid: &'a str, turn_id: Option<&'a str>, model: bool, issued: i64) -> Shape<'a> {
    Shape {
        lifecycle: if turn_id.is_some() {
            "enduring-turn"
        } else {
            "enduring-initial"
        },
        run_uid,
        turn_id,
        payload: "My value is violet. Remember it.",
        model,
        issued,
        parent_deadline: issued + 300,
    }
}

fn no_native_custody(state: &State) {
    assert!(state
        .scoped
        .as_ref()
        .unwrap()
        .enduring
        .lock()
        .unwrap()
        .is_empty());
    assert!(state.parents.statuses().unwrap().is_empty());
    assert!(state.executions.lock().unwrap().is_empty());
}

#[test]
fn enduring_runs_require_a_mediated_model_route_and_the_operator_parent_template() {
    let root = tempfile::tempdir().unwrap();
    let artifacts = synthetic_artifacts(root.path());
    let issued = unix_now();
    let start = |state: &State, shape: Shape<'_>| {
        let (operation, decision) = compose(&artifacts, shape);
        let (id, owner) = prepare(state, &operation, &decision);
        let execution = Permit::execution(&decision, shape.run_uid).sign(&decision);
        let model = Permit::model(&decision, shape.run_uid).sign(&decision);
        let reply = post(
            state,
            "start",
            Headers::permits(&execution, shape.model.then_some(model.as_str())),
            &json!({"id":id,"owner":owner}),
        );
        assert_never_stored(root.path(), &[&execution, &model]);
        reply
    };
    // No template configured: the receiver owns no enduring parent shape.
    let bare = node(
        root.path(),
        NodeOptions {
            max_cells: 2,
            egress_slots: 1,
            gateway: Some((GATEWAY, Path::new("/nonexistent-ca"))),
            parent_template: None,
        },
    );
    let (status, body) = start(&bare, enduring("untemplated-run", None, true, issued));
    assert_eq!(status, 503, "{body}");
    assert_eq!(
        (&body["phase"], &body["reason"]),
        (&json!("Refused"), &json!("AUTH_PROTOCOL_UNSUPPORTED"))
    );
    no_native_custody(&bare);
    drop(bare);

    let parent = template(&artifacts);
    let state = node(
        root.path(),
        NodeOptions {
            max_cells: 2,
            egress_slots: 0,
            gateway: Some((GATEWAY, Path::new("/nonexistent-ca"))),
            parent_template: Some(&parent),
        },
    );
    // provider == "none": an enduring parent is never model-free.
    let (status, body) = start(&state, enduring("model-free-run", None, false, issued));
    assert_eq!(status, 422, "{body}");
    assert_eq!(
        (&body["phase"], &body["reason"]),
        (&json!("Refused"), &json!("AUTH_PROTOCOL_UNSUPPORTED"))
    );
    assert_eq!(body["cleanupConfirmed"], true);
    // A mediated route on a node advertising no broker slot: refused before
    // any parent permit, claim or owner thread exists.
    let (status, body) = start(&state, enduring("unbrokered-run", None, true, issued));
    assert_eq!(status, 503, "{body}");
    assert_eq!(
        (&body["phase"], &body["reason"]),
        (&json!("Refused"), &json!("AUTH_CAPACITY"))
    );
    assert!(body["parentIncarnation"]
        .as_str()
        .unwrap()
        .starts_with("blake3:"));
    no_native_custody(&state);
    assert!(!root.path().join("parent-journal").exists());
    assert_eq!(
        fs::read_dir(root.path().join("trusted-parent-permits"))
            .unwrap()
            .count(),
        0
    );

    // A follow-up turn cannot resurrect the refused parent.
    let (status, body) = start(
        &state,
        enduring("unbrokered-run", Some("turn-1"), true, issued),
    );
    assert_eq!(
        (status, body["reason"].as_str()),
        (401, Some("AUTH_CONTEXT_LOST"))
    );
    no_native_custody(&state);
}

/// Drive `start_enduring` with a broker the HTTP path can never construct.
fn start_enduring_with(
    state: &State,
    run_uid: &str,
    broker: Option<HttpBroker>,
) -> (u16, Value, Outcome) {
    let artifacts = synthetic_artifacts(&state.root);
    let scoped = state.scoped.as_ref().unwrap();
    let (operation, decision) = compose(&artifacts, enduring(run_uid, None, true, unix_now()));
    let (id, _) = prepare(state, &operation, &decision);
    let prepared = scoped.load_prepared(&id).unwrap();
    let execution = Permit::execution(&decision, run_uid).sign(&decision);
    let model = Permit::model(&decision, run_uid).sign(&decision);
    let receiver = receiver_context(&operation, &decision, "execution.start").unwrap();
    let control = operation_control(&prepared).unwrap();
    let (worker, _mediated) = build_native(
        scoped,
        &prepared,
        &receiver,
        &execution,
        Some(&model),
        &control,
    )
    .unwrap();
    let canonical =
        crate::tenancy_contract::canonical(&serde_json::to_vec(&decision).unwrap()).unwrap();
    let external = external_request(&operation, &decision).unwrap();
    let claim = |scoped: &ScopedState| {
        scoped.admission.claim(
            &scoped.verifier,
            &execution,
            &canonical,
            &external,
            &receiver,
        )
    };
    let Ok(Claim::Fresh(fresh)) = claim(scoped) else {
        panic!("expected a fresh claim")
    };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    let (mut server, _) = listener.accept().unwrap();
    start_enduring(
        state,
        scoped,
        &mut server,
        prepared,
        fresh,
        worker,
        broker,
        control,
    )
    .unwrap();
    drop(server);
    let mut response = String::new();
    client.read_to_string(&mut response).unwrap();
    let Ok(Claim::Recovery(record)) = claim(scoped) else {
        panic!("the run slot must stay claimed")
    };
    (
        response.split_whitespace().nth(1).unwrap().parse().unwrap(),
        serde_json::from_str(response.split_once("\r\n\r\n").unwrap().1).unwrap(),
        record
            .outcome()
            .cloned()
            .expect("refusal is a durable outcome"),
    )
}

#[test]
fn an_enduring_parent_is_never_started_with_a_missing_or_credentialed_broker() {
    let root = tempfile::tempdir().unwrap();
    let parent = template(&synthetic_artifacts(root.path()));
    let state = node(
        root.path(),
        NodeOptions {
            max_cells: 2,
            egress_slots: 1,
            gateway: Some((GATEWAY, Path::new("/nonexistent-ca"))),
            parent_template: Some(&parent),
        },
    );
    // The legacy transport: a standing provider credential file on the node.
    let mut policy = HttpPolicy::new(vec![]);
    policy.json_posts.push(JsonPostGrant {
        protocol: ModelProtocol::OpenaiChat,
        url: MODEL_ALIAS.into(),
        bearer_token_file: root.path().join("provider-key"),
        model: "gpt-test".into(),
        max_output_tokens: 512,
        max_total_output_tokens: 512,
        parameters: Default::default(),
    });
    let legacy = HttpBroker::new(policy);
    assert!(!legacy.is_mediated());
    for (run, broker) in [
        ("legacy-broker-run", Some(legacy)),
        ("brokerless-run", None),
    ] {
        let (status, body, outcome) = start_enduring_with(&state, run, broker);
        assert_eq!(status, 422, "{body}");
        assert_eq!(
            (&body["phase"], &body["reason"]),
            (&json!("Refused"), &json!("AUTH_PROTOCOL_UNSUPPORTED"))
        );
        assert_eq!(outcome, Outcome::Refused);
    }
    no_native_custody(&state);
}

#[test]
fn a_follow_up_turn_without_its_original_owner_is_context_lost_not_a_new_parent() {
    let root = tempfile::tempdir().unwrap();
    let artifacts = synthetic_artifacts(root.path());
    let parent = template(&artifacts);
    let options = || NodeOptions {
        max_cells: 2,
        egress_slots: 1,
        gateway: Some((GATEWAY, Path::new("/nonexistent-ca"))),
        parent_template: Some(&parent),
    };
    let state = node(root.path(), options());
    let scoped = state.scoped.as_ref().unwrap();
    let issued = unix_now();
    let turn = |state: &State, run: &str, turn: &str| {
        let (operation, decision) = compose(&artifacts, enduring(run, Some(turn), true, issued));
        let (id, owner) = prepare(state, &operation, &decision);
        let label = format!("{run}-{turn}");
        let execution = Permit::execution(&decision, &label).sign(&decision);
        let model = Permit::model(&decision, &label).sign(&decision);
        let reply = post(
            state,
            "start",
            Headers::permits(&execution, Some(&model)),
            &json!({"id":id,"owner":owner}),
        );
        assert_never_stored(root.path(), &[&execution, &model]);
        (id, decision, reply)
    };

    // 1. A turn for an incarnation this receiver never admitted.
    let (_, _, (status, body)) = turn(&state, "never-created-run", "turn-1");
    assert_eq!(
        (status, body["reason"].as_str()),
        (401, Some("AUTH_CONTEXT_LOST"))
    );
    no_native_custody(&state);

    // 2. The journal proves this epoch admitted and completed the initial
    //    turn, but the live owner (parent VM, relay, model permit) is gone.
    let (initial_operation, initial) =
        compose(&artifacts, enduring("lost-owner-run", None, true, issued));
    prepare(&state, &initial_operation, &initial);
    let permit = Permit::execution(&initial, "lost-owner-initial").sign(&initial);
    let claimed = scoped
        .admission
        .claim(
            &scoped.verifier,
            &permit,
            &crate::tenancy_contract::canonical(&serde_json::to_vec(&initial).unwrap()).unwrap(),
            &external_request(&initial_operation, &initial).unwrap(),
            &receiver_context(&initial_operation, &initial, "execution.start").unwrap(),
        )
        .unwrap_or_else(|_| panic!("initial claim refused"));
    let Claim::Fresh(fresh) = claimed else {
        panic!("expected a fresh initial claim")
    };
    scoped
        .admission
        .finish(
            &fresh,
            Outcome::Receipt {
                digest: Hash::of(b"initial turn receipt").0,
            },
        )
        .unwrap_or_else(|_| panic!("initial completion refused"));
    let (id, decision, (status, body)) = turn(&state, "lost-owner-run", "turn-1");
    assert_eq!(status, 409, "{body}");
    assert_eq!(
        (&body["phase"], &body["reason"]),
        (&json!("Uncertain"), &json!("AUTH_CONTEXT_LOST"))
    );
    assert_eq!(body["cleanupConfirmed"], false);
    assert_eq!(body["parentIncarnation"], initial["parent"]["incarnation"]);
    assert_eq!(body["turnId"], "turn-1");
    assert!(body.get("childId").is_none() && body.get("cellId").is_none());
    no_native_custody(&state);
    assert!(!root.path().join("parent-journal").exists());
    // The uncertainty is durable and is what a reader sees; it is not success.
    let read_decision = access_decision(&decision, "execution.read");
    let read = Permit::access(&read_decision, "lost-owner-read").sign(&read_decision);
    let (status, seen) = post(
        &state,
        "read",
        Headers::permits(&read, None),
        &json!({"id":id,"decision":read_decision}),
    );
    assert_eq!(status, 202, "{seen}");
    assert_eq!(
        (&seen["phase"], &seen["reason"]),
        (&json!("Uncertain"), &json!("AUTH_CONTEXT_LOST"))
    );

    // 3. After a receiver restart the same run's next turn is refused by epoch.
    let restarted = node(root.path(), options());
    let (_, _, (status, body)) = turn(&restarted, "lost-owner-run", "turn-2");
    assert_eq!(
        (status, body["reason"].as_str()),
        (401, Some("AUTH_CONTEXT_LOST"))
    );
    no_native_custody(&restarted);
}

fn artifacts_of(request: &ExecutionRequest, publisher: &str) -> Artifacts {
    Artifacts {
        mote: request.mote.as_ref().unwrap().hash.clone(),
        executable: request.tools[0].hash.clone(),
        closure: request.tools[0].closure.as_ref().unwrap().hash.clone(),
        publisher: publisher.into(),
        entry_point: request.tools[0].alias.clone(),
    }
}

/// Poll `/v1/scoped/read` with one freshly minted read capability per request.
fn read_until(
    state: &State,
    id: &str,
    decision: &Value,
    label: &str,
    done: &[&str],
) -> (u16, Value) {
    let deadline = Instant::now() + Duration::from_secs(150);
    for attempt in 0.. {
        let read_decision = access_decision(decision, "execution.read");
        let permit =
            Permit::access(&read_decision, &format!("{label}-read-{attempt}")).sign(&read_decision);
        let (status, body) = post(
            state,
            "read",
            Headers::permits(&permit, None),
            &json!({"id":id,"decision":read_decision}),
        );
        assert!(matches!(status, 200 | 202), "{status} {body}");
        if done.contains(&body["phase"].as_str().unwrap()) {
            return (status, body);
        }
        assert!(
            matches!(
                body["phase"].as_str(),
                Some("Admitted" | "Running" | "Cancelling")
            ),
            "{body}"
        );
        assert!(
            Instant::now() < deadline,
            "scoped operation never settled: {body}"
        );
        thread::sleep(Duration::from_millis(100));
    }
    unreachable!()
}

fn listed_parent(state: &State, incarnation: &Value) -> Value {
    let (status, body) = send(
        state,
        "GET",
        "/v1/cells?all=true",
        Headers {
            bearer: Some(&state.token),
            ..Headers::default()
        },
        "",
    );
    assert_eq!(status, 200, "{body}");
    body["parents"]
        .as_array()
        .unwrap()
        .iter()
        .find(|parent| parent["incarnation"] == *incarnation)
        .cloned()
        .unwrap_or(Value::Null)
}

/// Hardware half: real sealed artifacts, real guests, real TLS to a scripted
/// gateway. `root` holds the closures/motes/tools/trust policy for all three
/// requests; no provider credential or model profile exists anywhere on it.
pub(crate) fn prove_scoped_on_kvm(
    root: &Path,
    publisher: &str,
    one_shot_runtime: &ExecutionRequest,
    parent: &ExecutionRequest,
    worker: &ExecutionRequest,
) {
    let gateway = Gateway::serve(
        root,
        vec!["CELLN".into(), "Noted: violet.".into(), "violet".into()],
    );
    let mut request = serde_json::to_value(parent).unwrap();
    request["id"] = json!("$parent");
    request["workload"] = json!({"id":"$parent","caller":"$principal"});
    let template = json!({"apiVersion":"celln.scoped-parent-template/v1",
        "reservedMemoryBytes":1610612736u64,"request":request});
    let state = node(
        root,
        NodeOptions {
            max_cells: 2,
            egress_slots: 1,
            gateway: Some((&gateway.origin, &gateway.ca)),
            parent_template: Some(&template),
        },
    );
    let mut permits = Vec::new();

    // One-shot: prepare -> start -> read -> cleanup, the model call mediated.
    let (operation, decision) = compose(
        &artifacts_of(one_shot_runtime, publisher),
        one_shot("kvm-one-shot-run", true, unix_now()),
    );
    let (id, owner) = prepare(&state, &operation, &decision);
    let execution = Permit::execution(&decision, "kvm-one-shot-execution").sign(&decision);
    let model = Permit::model(&decision, "kvm-one-shot-model").sign(&decision);
    let (status, admitted) = post(
        &state,
        "start",
        Headers::permits(&execution, Some(&model)),
        &json!({"id":id,"owner":owner}),
    );
    assert_eq!(status, 202, "{admitted}");
    assert_eq!(admitted["phase"], "Admitted");
    let (status, finished) = read_until(
        &state,
        &id,
        &decision,
        "kvm-one-shot",
        &["Succeeded", "Failed", "Refused", "Cancelled", "Uncertain"],
    );
    assert_eq!(
        (status, &finished["phase"]),
        (200, &json!("Succeeded")),
        "{finished}"
    );
    assert_eq!(finished["output"], "CELLN");
    assert_eq!(finished["cleanupConfirmed"], true);
    assert!(!finished["cellId"].as_str().unwrap().is_empty());
    assert!(finished["receiptDigest"]
        .as_str()
        .unwrap()
        .starts_with("blake3:"));
    assert!(finished["execution"].is_object() && finished["substrate"].is_object());
    let seen = gateway.seen();
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert_eq!(
        seen[0].0,
        format!("POST /v1/invoke HTTP/1.1 Bearer {model}")
    );
    assert_eq!(seen[0].1["decision"], decision);
    // No cap was prepared, so the guest asked for the default.
    assert_eq!(seen[0].1["request"]["max_tokens"], 512);
    let cleanup_decision = access_decision(&decision, "execution.cleanup");
    let cleanup = Permit::access(&cleanup_decision, "kvm-one-shot-cleanup").sign(&cleanup_decision);
    assert_eq!(
        post(
            &state,
            "cleanup",
            Headers::permits(&cleanup, None),
            &json!({"id":id,"decision":cleanup_decision}),
        ),
        (200, finished.clone())
    );
    // A replay after completion recovers the receipt; it does not run again.
    assert_eq!(
        post(
            &state,
            "start",
            Headers::permits(&execution, Some(&model)),
            &json!({"id":id,"owner":owner}),
        ),
        (200, finished)
    );
    assert_eq!(gateway.seen().len(), 1);
    permits.extend([execution, model, cleanup]);

    // Enduring: the initial turn creates the retained parent…
    let worker_artifacts = artifacts_of(worker, publisher);
    let created = unix_now();
    let initial_shape = Shape {
        parent_deadline: created + 600,
        ..enduring("kvm-enduring-run", None, true, created)
    };
    // …whose worker asks for the operator-prepared cap on every model request.
    let capped = Requests {
        output_tokens: Some(2048),
        budget: roomy(2048, 1),
        ..Requests::default()
    };
    let (initial_operation, initial) = compose_requests(&worker_artifacts, initial_shape, capped);
    let incarnation = initial["parent"]["incarnation"].clone();
    let (initial_id, owner) = prepare(&state, &initial_operation, &initial);
    let execution = Permit::execution(&initial, "kvm-initial-execution").sign(&initial);
    let initial_model = Permit::model(&initial, "kvm-initial-model").sign(&initial);
    let (status, admitted) = post(
        &state,
        "start",
        Headers::permits(&execution, Some(&initial_model)),
        &json!({"id":initial_id,"owner":owner}),
    );
    assert_eq!(status, 202, "{admitted}");
    assert_eq!(admitted["parentIncarnation"], incarnation);
    // …which the operator listing reports from the same parent registry.
    let listed = listed_parent(&state, &incarnation);
    assert!(
        matches!(
            listed["status"].as_str(),
            Some("Initializing" | "Ready" | "TurnActive")
        ),
        "scoped parent missing from /v1/cells: {listed}"
    );
    assert_eq!(listed["statusIsLiveOwnerObservation"], true);
    let scoped = state.scoped.as_ref().unwrap();
    assert!(scoped
        .enduring
        .lock()
        .unwrap()
        .contains_key(incarnation.as_str().unwrap()));
    let (status, first) = read_until(
        &state,
        &initial_id,
        &initial,
        "kvm-initial",
        &["Running", "Failed", "Refused", "Cancelled", "Uncertain"],
    );
    // The initial operation stays open (202) while its parent lives.
    assert_eq!(
        (status, &first["phase"]),
        (202, &json!("Running")),
        "{first}"
    );
    assert_eq!(first["output"], "Noted: violet.");
    assert_eq!(first["parentId"], incarnation);
    permits.extend([execution, initial_model.clone()]);

    // A follow-up turn under the same signed budget but prepared without the
    // cap is another worker: refused against the retained parent's binding,
    // with no model call and no turn.
    let (drift_operation, drift) = compose_requests(
        &worker_artifacts,
        Shape {
            turn_id: Some("turn-drift"),
            lifecycle: "enduring-turn",
            issued: unix_now(),
            ..initial_shape
        },
        Requests {
            output_tokens: None,
            ..capped
        },
    );
    let (drift_id, owner) = prepare(&state, &drift_operation, &drift);
    let execution = Permit::execution(&drift, "kvm-drift-execution").sign(&drift);
    let drift_model = Permit::model(&drift, "kvm-drift-model").sign(&drift);
    let (status, refused) = post(
        &state,
        "start",
        Headers::permits(&execution, Some(&drift_model)),
        &json!({"id":drift_id,"owner":owner}),
    );
    assert_eq!(
        (
            status,
            refused["phase"].as_str(),
            refused["reason"].as_str()
        ),
        (409, Some("Refused"), Some("AUTH_REQUEST_BINDING_MISMATCH")),
        "{refused}"
    );
    assert_eq!(gateway.seen().len(), 2);
    permits.extend([execution, drift_model]);

    // …and a follow-up turn reaches THAT parent with its own fresh permits.
    let (turn_operation, turn) = compose_requests(
        &worker_artifacts,
        Shape {
            payload: "What was my original value? Reply with that value only.",
            issued: unix_now(),
            ..Shape {
                turn_id: Some("turn-2"),
                lifecycle: "enduring-turn",
                ..initial_shape
            }
        },
        capped,
    );
    let (turn_id, owner) = prepare(&state, &turn_operation, &turn);
    let execution = Permit::execution(&turn, "kvm-turn-execution").sign(&turn);
    let turn_model = Permit::model(&turn, "kvm-turn-model").sign(&turn);
    let (status, admitted) = post(
        &state,
        "start",
        Headers::permits(&execution, Some(&turn_model)),
        &json!({"id":turn_id,"owner":owner}),
    );
    assert_eq!(status, 202, "{admitted}");
    let (status, second) = read_until(
        &state,
        &turn_id,
        &turn,
        "kvm-turn",
        &["Succeeded", "Failed", "Refused", "Cancelled", "Uncertain"],
    );
    assert_eq!(
        (status, &second["phase"]),
        (200, &json!("Succeeded")),
        "{second}"
    );
    assert_eq!(second["output"], "violet");
    assert_eq!(second["turnId"], "turn-2");
    assert_eq!(second["parentId"], incarnation);
    assert_ne!(second["childId"], first["childId"]);
    assert_ne!(second["cellId"], first["cellId"]);
    assert!(second["receiptDigest"]
        .as_str()
        .unwrap()
        .starts_with("blake3:"));
    // Each turn's model call carried that turn's capability and decision, and
    // the second carried the retained parent's memory of the first.
    let seen = gateway.seen();
    assert_eq!(seen.len(), 3, "{seen:?}");
    assert_eq!(
        seen[1].0,
        format!("POST /v1/invoke HTTP/1.1 Bearer {initial_model}")
    );
    assert_eq!(seen[1].1["decision"], initial);
    assert_eq!(
        seen[2].0,
        format!("POST /v1/invoke HTTP/1.1 Bearer {turn_model}")
    );
    assert_eq!(seen[2].1["decision"], turn);
    for request in &seen[1..] {
        assert_eq!(request.1["request"]["max_tokens"], 2048, "{}", request.1);
    }
    assert!(
        seen[2].1["request"]["messages"]
            .to_string()
            .contains("My value is violet"),
        "{}",
        seen[2].1
    );
    assert_eq!(listed_parent(&state, &incarnation)["turns_total"], 2);
    permits.extend([execution, turn_model]);

    // Cleanup of the initial operation stops the parent; nothing can follow.
    let cleanup_decision = access_decision(&initial, "execution.cleanup");
    let cleanup = Permit::access(&cleanup_decision, "kvm-initial-cleanup").sign(&cleanup_decision);
    let (status, stopped) = post(
        &state,
        "cleanup",
        Headers::permits(&cleanup, None),
        &json!({"id":initial_id,"decision":cleanup_decision}),
    );
    assert_eq!(status, 200, "{stopped}");
    assert_eq!(stopped["phase"], "Cancelled");
    assert_eq!(stopped["cleanupConfirmed"], true);
    assert_eq!(listed_parent(&state, &incarnation)["status"], "Stopped");
    let (late_operation, late) = compose_requests(
        &worker_artifacts,
        Shape {
            turn_id: Some("turn-3"),
            lifecycle: "enduring-turn",
            issued: unix_now(),
            ..initial_shape
        },
        capped,
    );
    let (late_id, owner) = prepare(&state, &late_operation, &late);
    let execution = Permit::execution(&late, "kvm-late-execution").sign(&late);
    let late_model = Permit::model(&late, "kvm-late-model").sign(&late);
    let (status, refused) = post(
        &state,
        "start",
        Headers::permits(&execution, Some(&late_model)),
        &json!({"id":late_id,"owner":owner}),
    );
    assert_eq!(
        (status, refused["reason"].as_str()),
        (409, Some("AUTH_CONTEXT_LOST")),
        "{refused}"
    );
    assert_eq!(gateway.seen().len(), 3);
    permits.extend([execution, late_model, cleanup]);

    // Mediated means the node held no provider credential and kept no permit.
    let permits: Vec<&str> = permits.iter().map(String::as_str).collect();
    assert_never_stored(root, &permits);
    for standing in [
        "trusted-parent-models",
        "trusted-harness",
        "trusted-parent-launches",
    ] {
        assert!(!root.join(standing).exists(), "{standing}");
    }
    eprintln!("PASS: scoped one-shot and enduring parent over HTTP on KVM, model calls mediated by the gateway");
}
