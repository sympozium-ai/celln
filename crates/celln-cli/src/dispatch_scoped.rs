//! Operator-authenticated, receiver-owned one-shot tenancy integration.
//! Prepared public material is durable and immutable; permits are never stored.

use super::{
    current_node, execution_is_active, reply, Entry, ExecutionRecord, Reservation, ScopedOptions,
    State,
};
use crate::{
    tenancy_admission::{Claim, Error as AdmissionError, Fresh, Journal, Outcome},
    tenancy_credentials::{Context as ReceiverContext, Verifier},
    tenancy_model_context::ModelContext,
    tenancy_model_relay::{GatewayEndpoint, GatewayRelay},
};
use anyhow::{bail, Context, Result};
use celln_manifest::{tool_schema::ToolSchema, Hash};
use celln_spec::ExecutionRequest;
use celln_store::Store;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    fs::{self, File, OpenOptions},
    io::{BufReader, Read},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use warden::egress::{HttpBroker, HttpPolicy, JsonPostGrant, ModelProtocol};
use zeroize::Zeroizing;

// Logical guest-facing route only. The owned relay sends exclusively to the
// operator-configured gateway, which resolves the signed provider origin.
const MODEL_ALIAS: &str = "https://celln-model.invalid/v1/invoke";
const MAX_BODY: usize = 262144;
const MAX_PREPARED: usize = 768 * 1024;
const MAX_STATUS: usize = 96 * 1024;

pub(super) struct RequestMetadata<'a> {
    pub length: usize,
    pub bearer: Option<&'a str>,
    pub execution_permit: Option<&'a str>,
    pub model_permit: Option<&'a str>,
}

#[derive(Clone)]
struct GatewayConfig {
    origin: String,
    ca: Option<PathBuf>,
}

pub(super) struct ScopedState {
    operator_token_file: PathBuf,
    jwks_file: PathBuf,
    verifier: Verifier,
    admission: Arc<Journal>,
    root: PathBuf,
    gateway: Option<GatewayConfig>,
    operation_lock: Mutex<()>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PreparedRecord {
    version: u8,
    id: String,
    owner: String,
    operation: Value,
    decision: Value,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ScopedStatus {
    id: String,
    owner: String,
    phase: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    output: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    receipt_digest: Option<String>,
    cleanup_confirmed: bool,
}

impl ScopedState {
    pub(super) fn configure(
        root: &Path,
        options: ScopedOptions<'_>,
        probe: &crate::NodeProbeArgs,
    ) -> Result<Option<Arc<Self>>> {
        let configured = [
            options.operator_token_file.is_some(),
            options.jwks_file.is_some(),
            options.issuer.is_some(),
        ];
        if configured.iter().any(|v| *v) && !configured.iter().all(|v| *v) {
            bail!("scoped receiver requires --scoped-operator-token-file, --scoped-jwks-file and --scoped-issuer together");
        }
        if !configured[0] {
            return Ok(None);
        }
        let operator_token_file = options.operator_token_file.unwrap().to_owned();
        super::read_bearer_token(&operator_token_file)
            .context("reading scoped operator credential")?;
        let jwks_file = options.jwks_file.unwrap().to_owned();
        let jwks = read_bounded(&jwks_file, 65536, false).context("reading scoped JWKS")?;
        let verifier = Verifier::from_jwks(options.issuer.unwrap().to_owned(), &jwks)
            .map_err(|reason| anyhow::anyhow!(reason))?;
        let scoped_root = root.join("scoped");
        private_dir(&scoped_root)?;
        private_dir(&scoped_root.join("prepared"))?;
        private_dir(&scoped_root.join("status"))?;
        let admission = Journal::open(
            &scoped_root.join("admission"),
            usize::try_from(probe.max_cells.max(1))
                .unwrap_or(1)
                .saturating_mul(4096)
                .min(1_000_000),
        )
        .map_err(|_| anyhow::anyhow!("opening scoped admission journal"))?;
        let gateway = match options.gateway_origin {
            Some(origin) => {
                GatewayEndpoint::new(origin, options.gateway_ca.map(Path::to_owned))
                    .map_err(|_| anyhow::anyhow!("invalid scoped gateway configuration"))?;
                Some(GatewayConfig {
                    origin: origin.to_owned(),
                    ca: options.gateway_ca.map(Path::to_owned),
                })
            }
            None if options.gateway_ca.is_some() => {
                bail!("--scoped-gateway-ca requires --scoped-gateway-origin")
            }
            None => None,
        };
        Ok(Some(Arc::new(Self {
            operator_token_file,
            jwks_file,
            verifier,
            admission: Arc::new(admission),
            root: scoped_root,
            gateway,
            operation_lock: Mutex::new(()),
        })))
    }

    fn authenticate(&self, bearer: Option<&str>) -> Result<(), u16> {
        let expected = super::read_bearer_token(&self.operator_token_file).map_err(|_| 503u16)?;
        if !bearer.is_some_and(|got| super::constant_time_eq(got.as_bytes(), expected.as_bytes())) {
            return Err(401);
        }
        let jwks = read_bounded(&self.jwks_file, 65536, false).map_err(|_| 503u16)?;
        self.verifier.reload_jwks(&jwks).map_err(|_| 503u16)
    }

    fn prepared_path(&self, id: &str) -> Result<PathBuf> {
        Ok(self.root.join("prepared").join(id_hex(id)?))
    }

    fn status_path(&self, id: &str) -> Result<PathBuf> {
        Ok(self.root.join("status").join(id_hex(id)?))
    }

    fn load_prepared(&self, id: &str) -> Result<PreparedRecord> {
        let raw = read_bounded(&self.prepared_path(id)?, MAX_PREPARED, true)?;
        let record: PreparedRecord = serde_json::from_slice(&raw)?;
        if record.version != 1 || record.id != id || id_hex(&record.owner).is_err() {
            bail!("invalid prepared operation")
        }
        validate_prepared(&record.operation, &record.decision)?;
        Ok(record)
    }

    fn load_status(&self, id: &str) -> Result<Option<ScopedStatus>> {
        match read_bounded(&self.status_path(id)?, MAX_STATUS, true) {
            Ok(raw) => {
                let status: ScopedStatus = serde_json::from_slice(&raw)?;
                if status.id != id
                    || id_hex(&status.owner).is_err()
                    || !matches!(
                        status.phase.as_str(),
                        "Admitted"
                            | "Running"
                            | "Cancelling"
                            | "Succeeded"
                            | "Failed"
                            | "Refused"
                            | "Cancelled"
                    )
                    || status.output.as_ref().is_some_and(|v| v.len() > 65536)
                    || status.receipt_digest.as_ref().is_some_and(|v| {
                        v.strip_prefix("blake3:").map_or(true, |hex| {
                            hex.len() != 64
                                || !hex
                                    .bytes()
                                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                        })
                    })
                {
                    bail!("invalid scoped status")
                }
                Ok(Some(status))
            }
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
            {
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }
}

pub(super) fn handle(
    dispatcher: &State,
    scoped: &Arc<ScopedState>,
    stream: &mut std::net::TcpStream,
    reader: &mut BufReader<std::net::TcpStream>,
    method: &str,
    path: &str,
    metadata: RequestMetadata<'_>,
) -> Result<()> {
    if let Err(status) = scoped.authenticate(metadata.bearer) {
        return reply(
            stream,
            status,
            &json!({"error":if status == 401 {"unauthorized"} else {"scoped receiver unavailable"}}),
        );
    }
    if method != "POST" {
        return reply(stream, 404, &json!({"error":"not found"}));
    }
    if metadata.length > MAX_BODY {
        return reply(
            stream,
            413,
            &json!({"error":"scoped request body exceeds 256 KiB"}),
        );
    }
    let mut body = vec![0; metadata.length];
    reader.read_exact(&mut body)?;
    let body = match crate::tenancy_contract::canonical(&body) {
        Ok(body) => body,
        Err(_) => {
            return reply(
                stream,
                400,
                &json!({"error":"scoped request must be bounded unambiguous I-JSON"}),
            )
        }
    };
    match path {
        "/v1/scoped/prepare" => prepare(scoped, stream, &body),
        "/v1/scoped/start" => start(dispatcher, scoped, stream, &body, metadata),
        "/v1/scoped/read" => access(dispatcher, scoped, stream, &body, metadata, false),
        "/v1/scoped/cleanup" => access(dispatcher, scoped, stream, &body, metadata, true),
        _ => reply(stream, 404, &json!({"error":"not found"})),
    }
}

fn prepare(scoped: &ScopedState, stream: &mut std::net::TcpStream, body: &[u8]) -> Result<()> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Request {
        operation: Value,
        decision: Value,
    }
    let request: Request = match serde_json::from_slice(body) {
        Ok(value) => value,
        Err(_) => return reply(stream, 400, &json!({"error":"invalid scoped preparation"})),
    };
    if let Err(reason) = validate_prepared(&request.operation, &request.decision) {
        return reply(
            stream,
            422,
            &json!({"error":"scoped preparation refused","reason":reason.to_string()}),
        );
    }
    let id = match operation_id(&request.operation, &request.decision) {
        Ok(id) => id,
        Err(_) => return reply(stream, 422, &json!({"error":"scoped preparation refused"})),
    };
    let candidate = PreparedRecord {
        version: 1,
        id: id.clone(),
        owner: scoped.admission.owner().to_owned(),
        operation: request.operation,
        decision: request.decision,
    };
    let bytes = serde_json::to_vec(&candidate)?;
    if bytes.len() > MAX_PREPARED {
        return reply(
            stream,
            413,
            &json!({"error":"prepared operation exceeds receiver bound"}),
        );
    }
    let owner = match enroll_prepared(scoped, &candidate, &bytes) {
        Ok(owner) => owner,
        Err(EnrollError::Conflict) => {
            return reply(
                stream,
                409,
                &json!({"error":"operation identity already has different prepared material"}),
            )
        }
        Err(EnrollError::Unavailable) => {
            return reply(
                stream,
                503,
                &json!({"error":"durable scoped preparation unavailable"}),
            )
        }
    };
    reply(stream, 200, &json!({"id":id,"owner":owner}))
}

fn start(
    dispatcher: &State,
    scoped: &Arc<ScopedState>,
    stream: &mut std::net::TcpStream,
    body: &[u8],
    metadata: RequestMetadata<'_>,
) -> Result<()> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Request {
        id: String,
    }
    let request: Request = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return reply(stream, 400, &json!({"error":"invalid scoped start"})),
    };
    let _operation_lock = scoped
        .operation_lock
        .lock()
        .map_err(|_| anyhow::anyhow!("scoped operation lock unavailable"))?;
    let prepared = match scoped.load_prepared(&request.id) {
        Ok(v) => v,
        Err(_) => return reply(stream, 404, &json!({"error":"unknown prepared operation"})),
    };
    let execution_permit = match metadata.execution_permit {
        Some(v) => Zeroizing::new(v.to_owned()),
        None => return reply(stream, 401, &json!({"error":"execution permit required"})),
    };
    let external = external_request(&prepared.operation, &prepared.decision)?;
    let receiver = receiver_context(&prepared.operation, &prepared.decision, "execution.start")?;
    let decision = crate::tenancy_contract::canonical(&serde_json::to_vec(&prepared.decision)?)
        .map_err(|_| anyhow::anyhow!("invalid prepared decision"))?;
    if let Err(reason) = scoped
        .verifier
        .verify(&execution_permit, &decision, &receiver)
    {
        return reply(
            stream,
            401,
            &json!({"error":"scoped admission refused","reason":reason}),
        );
    }
    let existing_status = scoped.load_status(&request.id).ok().flatten();
    if prepared.owner != scoped.admission.owner() {
        if let Some(status) = existing_status.filter(|status| status.cleanup_confirmed) {
            return reply(stream, 200, &status);
        }
        return reply(
            stream,
            409,
            &ScopedStatus {
                id: request.id,
                owner: prepared.owner,
                phase: "Admitted".into(),
                reason: Some("AUTH_CONTEXT_LOST".into()),
                output: None,
                receipt_digest: None,
                cleanup_confirmed: false,
            },
        );
    }
    if let Some(status) = existing_status {
        return reply(
            stream,
            if status.cleanup_confirmed { 200 } else { 202 },
            &status,
        );
    }
    let claim = match scoped.admission.claim(
        &scoped.verifier,
        &execution_permit,
        &decision,
        &external,
        &receiver,
    ) {
        Ok(claim) => claim,
        Err(error) => return admission_reply(stream, error),
    };
    let fresh = match claim {
        Claim::Recovery(record) => {
            let status = scoped
                .load_status(&request.id)
                .ok()
                .flatten()
                .unwrap_or(ScopedStatus {
                    id: request.id,
                    owner: record.owner().to_owned(),
                    phase: "Admitted".into(),
                    reason: Some("original owner status is unavailable; replay refused".into()),
                    output: None,
                    receipt_digest: None,
                    cleanup_confirmed: false,
                });
            return reply(
                stream,
                if status.cleanup_confirmed { 200 } else { 202 },
                &status,
            );
        }
        Claim::Fresh(fresh) => fresh,
    };
    let timeout = prepared.operation["resolution"]["execution"]["runtimeLimits"]["timeoutMillis"]
        .as_u64()
        .unwrap_or(0);
    let control = match celln_control::Control::new(Duration::from_millis(timeout.max(1))) {
        Ok(v) => v,
        Err(_) => {
            let status = terminal_refusal(
                scoped,
                &fresh,
                &request.id,
                "invalid operation deadline".into(),
            );
            return reply(stream, 422, &status);
        }
    };
    let (native, broker) = match build_native(
        scoped,
        &prepared,
        &receiver,
        &execution_permit,
        metadata.model_permit,
        &control,
    ) {
        Ok(v) => v,
        Err(reason) => {
            let status = terminal_refusal(scoped, &fresh, &request.id, reason);
            return reply(stream, 422, &status);
        }
    };
    let record = ExecutionRecord {
        request_id: request.id.clone(),
        phase: "Admitted".into(),
        reason: None,
        output: None,
        receipt: None,
    };
    {
        let mut registry = dispatcher
            .executions
            .lock()
            .expect("dispatcher registry not poisoned");
        let node = current_node(dispatcher, &registry);
        if let crate::node::Admission::Refused { reason, .. } = crate::node::admit(&native, &node) {
            drop(registry);
            let status = terminal_refusal(
                scoped,
                &fresh,
                &request.id,
                format!("native admission refused: {reason:?}"),
            );
            return reply(stream, 503, &status);
        }
        let mut entry = Entry::new(record);
        entry.control = Some(control.clone());
        entry.reservation = Some(Reservation::for_request(&native));
        registry.insert(request.id.clone(), entry);
    }
    let status = ScopedStatus {
        id: request.id.clone(),
        owner: scoped.admission.owner().into(),
        phase: "Admitted".into(),
        reason: None,
        output: None,
        receipt_digest: None,
        cleanup_confirmed: false,
    };
    if persist_status(scoped, &status).is_err() {
        control.cancel();
        dispatcher.executions.lock().unwrap().remove(&request.id);
        let status = terminal_refusal(
            scoped,
            &fresh,
            &request.id,
            "durable result journal unavailable".into(),
        );
        return reply(stream, 503, &status);
    }
    let id = request.id;
    let worker_scoped = Arc::clone(scoped);
    let executions = Arc::clone(&dispatcher.executions);
    let root = dispatcher.root.clone();
    let motes = dispatcher.probe.mote_store.clone();
    let tools = dispatcher.probe.tool_store.clone();
    let worker_control = control.clone();
    let fresh_slot = Arc::new(Mutex::new(Some(fresh)));
    let worker_fresh = Arc::clone(&fresh_slot);
    let spawn = thread::Builder::new()
        .name("celln-scoped-one-shot".into())
        .spawn(move || {
            let fresh = worker_fresh
                .lock()
                .expect("scoped fresh claim not poisoned")
                .take()
                .expect("scoped fresh claim consumed once");
            worker_control.scope(|| {
                run_scoped(
                    worker_scoped,
                    executions,
                    fresh,
                    id,
                    native,
                    broker,
                    motes,
                    tools,
                    root,
                )
            });
        });
    if spawn.is_err() {
        let mut status = terminal_status(
            &status.id,
            scoped.admission.owner(),
            "Failed",
            Some("execution worker unavailable".into()),
            None,
        );
        status.cleanup_confirmed = true;
        let _ = persist_status(scoped.as_ref(), &status);
        super::update_execution(&dispatcher.executions, &status.id, |record| {
            record.phase = "Failed".into();
            record.reason = Some("execution worker unavailable".into());
        });
        if let Some(fresh) = fresh_slot
            .lock()
            .expect("scoped fresh claim not poisoned")
            .take()
        {
            let _ = scoped.admission.finish(&fresh, Outcome::Refused);
        }
        return reply(stream, 503, &status);
    }
    reply(stream, 202, &status)
}

fn run_scoped(
    scoped: Arc<ScopedState>,
    executions: super::Executions,
    fresh: Fresh,
    id: String,
    request: ExecutionRequest,
    broker: Option<HttpBroker>,
    motes: PathBuf,
    tools: PathBuf,
    root: PathBuf,
) {
    super::update_execution(&executions, &id, |r| r.phase = "Running".into());
    let launched = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        crate::dispatch::launch_scoped_declared(&request, &motes, &tools, &root, broker)
    }));
    let (phase, reason, output) = match launched {
        Ok(Ok((outcome, _))) => {
            let phase = if outcome.succeeded() {
                "Succeeded"
            } else if celln_control::current().and_then(|c| c.reason())
                == Some(celln_control::Stopped::Cancelled)
            {
                "Cancelled"
            } else {
                "Failed"
            };
            (
                phase,
                outcome.denial,
                outcome
                    .output
                    .map(|v| String::from_utf8_lossy(&v).into_owned()),
            )
        }
        Ok(Err(reason)) => {
            let phase = if celln_control::current().and_then(|c| c.reason())
                == Some(celln_control::Stopped::Cancelled)
            {
                "Cancelled"
            } else {
                "Failed"
            };
            (phase, Some(reason), None)
        }
        Err(_) => (
            "Failed",
            Some("execution worker panicked during teardown".into()),
            None,
        ),
    };
    let receipt_bytes = serde_json::to_vec(&json!({"id":id,"owner":scoped.admission.owner(),"phase":phase,"reason":reason,"output":output})).unwrap_or_default();
    let receipt_digest = Hash::of(&receipt_bytes).0;
    let status = ScopedStatus {
        id: id.clone(),
        owner: scoped.admission.owner().into(),
        phase: phase.into(),
        reason: reason.clone(),
        output: output.clone(),
        receipt_digest: Some(receipt_digest.clone()),
        cleanup_confirmed: true,
    };
    super::update_execution(&executions, &id, |record| {
        record.phase = phase.into();
        record.reason = reason;
        record.output = output;
    });
    let persisted = persist_status(&scoped, &status).is_ok();
    if persisted {
        let _ = scoped.admission.finish(
            &fresh,
            Outcome::Receipt {
                digest: receipt_digest,
            },
        );
    }
}

fn access(
    dispatcher: &State,
    scoped: &ScopedState,
    stream: &mut std::net::TcpStream,
    body: &[u8],
    metadata: RequestMetadata<'_>,
    cleanup: bool,
) -> Result<()> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Request {
        id: String,
        decision: Value,
    }
    let request: Request = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return reply(stream, 400, &json!({"error":"invalid scoped access"})),
    };
    let _operation_lock = if cleanup {
        Some(
            scoped
                .operation_lock
                .lock()
                .map_err(|_| anyhow::anyhow!("scoped operation lock unavailable"))?,
        )
    } else {
        None
    };
    let prepared = match scoped.load_prepared(&request.id) {
        Ok(v) => v,
        Err(_) => return reply(stream, 404, &json!({"error":"unknown prepared operation"})),
    };
    let permit = match metadata.execution_permit {
        Some(v) => Zeroizing::new(v.to_owned()),
        None => return reply(stream, 401, &json!({"error":"execution permit required"})),
    };
    let operation = if cleanup {
        "execution.cleanup"
    } else {
        "execution.read"
    };
    if validate_access_decision(&prepared.decision, &request.decision, operation).is_err() {
        return reply(
            stream,
            409,
            &json!({"error":"access decision changed original authority"}),
        );
    }
    let receiver = match receiver_context(&prepared.operation, &request.decision, operation) {
        Ok(value) => value,
        Err(_) => return reply(stream, 422, &json!({"error":"invalid scoped identity"})),
    };
    let decision = match serde_json::to_vec(&request.decision)
        .ok()
        .and_then(|raw| crate::tenancy_contract::canonical(&raw).ok())
    {
        Some(value) => value,
        None => return reply(stream, 400, &json!({"error":"invalid access decision"})),
    };
    let admission = match scoped
        .admission
        .access(&scoped.verifier, &permit, &decision, &receiver)
    {
        Ok(v) => v,
        Err(AdmissionError::Credential("AUTH_CONTEXT_LOST")) => {
            if let Ok(Some(status)) = scoped.load_status(&request.id) {
                if status.cleanup_confirmed {
                    return reply(stream, 200, &status);
                }
            }
            if cleanup && prepared.owner == scoped.admission.owner() {
                let status = terminal_status(
                    &request.id,
                    &prepared.owner,
                    "Cancelled",
                    Some("cancelled before native admission".into()),
                    None,
                );
                if persist_status(scoped, &status).is_err() {
                    return reply(
                        stream,
                        503,
                        &json!({"error":"scoped result journal unavailable"}),
                    );
                }
                return reply(stream, 200, &status);
            }
            return admission_reply(stream, AdmissionError::Credential("AUTH_CONTEXT_LOST"));
        }
        Err(e) => return admission_reply(stream, e),
    };
    if cleanup && admission.owner() == scoped.admission.owner() {
        if let Some(entry) = dispatcher.executions.lock().unwrap().get_mut(&request.id) {
            if execution_is_active(&entry.value) {
                if let Some(control) = &entry.control {
                    control.cancel();
                }
                entry.value.phase = "Cancelling".into();
                entry.value.reason = Some("cancellation requested; teardown pending".into());
                if let Ok(Some(mut status)) = scoped.load_status(&request.id) {
                    status.phase = "Cancelling".into();
                    status.reason = Some("cancellation requested; teardown pending".into());
                    status.cleanup_confirmed = false;
                    let _ = persist_status(scoped, &status);
                }
            }
        }
    }
    match scoped.load_status(&request.id) {
        Ok(Some(status)) => reply(
            stream,
            if status.cleanup_confirmed { 200 } else { 202 },
            &status,
        ),
        Ok(None) => reply(
            stream,
            202,
            &ScopedStatus {
                id: request.id,
                owner: admission.owner().into(),
                phase: if cleanup { "Cancelling" } else { "Admitted" }.into(),
                reason: Some("original owner status unavailable; replay refused".into()),
                output: None,
                receipt_digest: None,
                cleanup_confirmed: false,
            },
        ),
        Err(_) => reply(
            stream,
            503,
            &json!({"error":"scoped result journal unavailable"}),
        ),
    }
}

fn build_native(
    scoped: &ScopedState,
    prepared: &PreparedRecord,
    receiver: &ReceiverContext,
    execution_permit: &str,
    model_permit: Option<&str>,
    control: &celln_control::Control,
) -> Result<(ExecutionRequest, Option<HttpBroker>), String> {
    let execution = &prepared.operation["resolution"]["execution"];
    let profile = &execution["profileSpec"];
    let decision = &prepared.decision;
    validate_artifacts(scoped, execution, profile, decision)?;
    let tool_values = execution["tools"]
        .as_array()
        .ok_or("prepared tools missing")?;
    let decision_tools = decision["tools"]
        .as_array()
        .ok_or("decision tools missing")?;
    let mut tools = Vec::new();
    for (material, binding) in tool_values.iter().zip(decision_tools) {
        tools.push(native_tool(scoped, material, binding)?);
    }
    let provider =
        text(&decision["route"]["provider"], "route provider").map_err(|e| e.to_string())?;
    let config = if provider == "none" {
        if tools.len() != 1 || model_permit.is_some() {
            return Err("AUTH_PROTOCOL_UNSUPPORTED".into());
        }
        let value = json!({"contract":pilot::json_harness::DIRECT_CONTRACT,"tool":tools.remove(0),"arguments":text(&execution["payload"], "payload").map_err(|e| e.to_string())?});
        let typed: pilot::json_harness::DirectConfig =
            serde_json::from_value(value.clone()).map_err(|_| "AUTH_PROTOCOL_UNSUPPORTED")?;
        pilot::json_harness::validate_direct(&typed).map_err(|_| "AUTH_PROTOCOL_UNSUPPORTED")?;
        (value.to_string(), None)
    } else {
        let model_permit = model_permit.ok_or("AUTH_CRED_MALFORMED")?.to_owned();
        let gateway = scoped.gateway.as_ref().ok_or("AUTH_CONTEXT_LOST")?;
        let context = ModelContext::admit(
            &scoped.verifier,
            execution_permit.to_owned(),
            model_permit,
            &serde_json::to_vec(decision).map_err(|_| "AUTH_CRED_MALFORMED")?,
            receiver,
            control,
        )
        .map_err(str::to_owned)?;
        let route = &decision["route"];
        warden::egress::model_endpoint_target(MODEL_ALIAS, false)
            .map_err(|_| "AUTH_ROUTE_MISMATCH")?;
        let json_limits = profile["json"]
            .as_object()
            .ok_or("AUTH_PROTOCOL_UNSUPPORTED")?;
        let max_turns = u64v(&Value::Object(json_limits.clone())["maxTurns"], "maxTurns")?.min(
            u64v(&decision["budget"]["turnCap"]["requests"], "requests")?,
        );
        let value = json!({"contract":pilot::json_harness::CONTRACT,"task":execution["payload"],"system":execution["systemPrompt"],"url":MODEL_ALIAS,"model":route["model"],"tools":tools,"max_turns":max_turns,"max_calls":json_limits.get("maxCalls").and_then(Value::as_u64).ok_or("AUTH_PROTOCOL_UNSUPPORTED")?});
        let typed: pilot::json_harness::Config =
            serde_json::from_value(value.clone()).map_err(|_| "AUTH_PROTOCOL_UNSUPPORTED")?;
        pilot::json_harness::validate(&typed).map_err(|_| "AUTH_PROTOCOL_UNSUPPORTED")?;
        let protocol = match text(&route["protocol"], "protocol").map_err(|e| e.to_string())? {
            "openai-chat" => ModelProtocol::OpenaiChat,
            "anthropic-messages" => ModelProtocol::AnthropicMessages,
            _ => return Err("AUTH_PROTOCOL_UNSUPPORTED".into()),
        };
        let mut policy = HttpPolicy::new(vec![]);
        policy.max_requests = usize::try_from(u64v(
            &decision["budget"]["turnCap"]["requests"],
            "requests",
        )?)
        .map_err(|_| "AUTH_LIMIT_OUT_OF_RANGE")?;
        policy.max_response_bytes = 1 << 20;
        policy.json_posts.push(JsonPostGrant {
            protocol,
            url: MODEL_ALIAS.into(),
            bearer_token_file: PathBuf::new(),
            model: text(&route["model"], "model")
                .map_err(|e| e.to_string())?
                .into(),
            max_output_tokens: u64v(&decision["budget"]["turnCap"]["outputTokens"], "tokens")?,
            max_total_output_tokens: u64v(
                &decision["budget"]["turnCap"]["outputTokens"],
                "tokens",
            )?,
        });
        let relay = GatewayRelay::new(
            GatewayEndpoint::new(&gateway.origin, gateway.ca.clone())
                .map_err(|_| "AUTH_CONTEXT_LOST")?,
            context,
        );
        let broker =
            HttpBroker::new_mediated(policy, Box::new(relay)).map_err(|_| "AUTH_CONTEXT_LOST")?;
        (value.to_string(), Some(broker))
    };
    if config.0.len() > 65536 {
        return Err("AUTH_LIMIT_OUT_OF_RANGE".into());
    }
    let memory = tool_values.iter().zip(decision_tools).try_fold(
        u64v(&execution["runtimeLimits"]["memoryBytes"], "memory")?,
        |value, (_, binding)| {
            Ok::<_, String>(value.min(u64v(&binding["limits"]["memoryBytes"], "tool memory")?))
        },
    )?;
    let route_egress: Vec<String> = if provider == "none" {
        vec![]
    } else {
        vec!["https://celln-model.invalid".into()]
    };
    let native: ExecutionRequest = serde_json::from_value(json!({
        "apiVersion":"celln.dev/v1alpha1","id":prepared.id,
        "workload":{"id":prepared.id,"caller":format!("sympozium:{}:{}",receiver.cluster_id,receiver.namespace_uid)},
        "mote":{"hash":profile["mote"]["hash"]},
        "tools":[{"alias":profile["entryPoint"],"hash":profile["executable"]["hash"],"closure":{"hash":profile["closure"]["hash"]}}],
        "invocation":{"alias":profile["entryPoint"],"args":[config.0]},
        "capabilities":{"workspace":"none","egress":route_egress,"timeoutMs":execution["runtimeLimits"]["timeoutMillis"],"memoryBytes":memory,"outputBytes":execution["runtimeLimits"]["outputBytes"]},
        "execution":{"lane":"agent","requireHardwareIsolation":true}
    })).map_err(|_| "AUTH_PROTOCOL_UNSUPPORTED")?;
    if !native.problems().is_empty() {
        return Err("AUTH_PROTOCOL_UNSUPPORTED".into());
    }
    Ok((native, config.1))
}

fn validate_artifacts(
    scoped: &ScopedState,
    execution: &Value,
    profile: &Value,
    decision: &Value,
) -> Result<(), String> {
    if profile["contractVersion"] != pilot::json_harness::CONTRACT
        || profile["platform"] != "linux/amd64"
        || profile["lane"] != "agent"
        || !profile["lifecycles"]
            .as_array()
            .is_some_and(|v| v.iter().any(|item| item == "disposable-one-shot"))
        || execution["runtimeLimits"]["workspace"] != "none"
    {
        return Err("AUTH_PROTOCOL_UNSUPPORTED".into());
    }
    validate_runtime_resources(execution, profile)?;
    let decision_tools = decision["tools"]
        .as_array()
        .ok_or("decision tools missing")?;
    let materials = execution["tools"]
        .as_array()
        .ok_or("prepared tools missing")?;
    if materials.len() != decision_tools.len() {
        return Err("prepared tool count mismatch".into());
    }
    for (tool, binding) in materials.iter().zip(decision_tools) {
        let limits = &tool["spec"]["limits"];
        if limits["workspace"] != "none"
            || limits.get("artifacts").is_some_and(|v| !v.is_null())
            || limits.get("https").is_some_and(|v| !v.is_null())
            || limits["egress"].as_array().is_some_and(|v| !v.is_empty())
            || limits["inputs"].as_array().is_some_and(|v| !v.is_empty())
        {
            return Err("AUTH_PROTOCOL_UNSUPPORTED".into());
        }
        for (field, maximum) in [
            ("timeoutMillis", 30000),
            ("memoryBytes", 268435456),
            ("argumentBytes", 65536),
            ("outputBytes", 65536),
        ] {
            bounded_resource(&binding["limits"][field], &limits[field], maximum, field)?;
        }
    }
    let closure_hash =
        text(&profile["closure"]["hash"], "runtime closure").map_err(|e| e.to_string())?;
    let bytes = Store::open(scoped.root.parent().unwrap().join("closures"))
        .map_err(|_| "runtime closure unavailable")?
        .get_bounded(&Hash(closure_hash.into()), 262144)
        .map_err(|_| "runtime closure unavailable")?;
    let verified = crate::closure_policy::verify(&bytes, scoped.root.parent().unwrap())?;
    if verified.identity.0 != closure_hash
        || verified.signed.closure.entrypoint != profile["entryPoint"]
        || verified.signed.closure.members[&verified.signed.closure.entrypoint].hash
            != profile["executable"]["hash"]
    {
        return Err("prepared runtime closure mismatch".into());
    }
    let sources = &verified.signed.closure.sources;
    if (materials.is_empty() && sources.len() > 1)
        || (!materials.is_empty() && sources.len() != materials.len() + 1)
        || (sources.is_empty() && verified.signed.publisher != profile["publisherKey"])
    {
        return Err("prepared closure source count mismatch".into());
    }
    let policy_root = scoped.root.parent().unwrap();
    if let Some(source) = sources.first() {
        let runtime = crate::closure_policy::verify(source.descriptor.as_bytes(), policy_root)?;
        if runtime.identity.0 != source.hash
            || runtime.signed.publisher != profile["publisherKey"]
            || runtime.signed.closure.entrypoint != profile["entryPoint"]
            || runtime.signed.closure.members[&runtime.signed.closure.entrypoint].hash
                != profile["executable"]["hash"]
        {
            return Err("prepared runtime source mismatch".into());
        }
    }
    for (source, material) in sources.iter().skip(1).zip(materials) {
        let verified_source =
            crate::closure_policy::verify(source.descriptor.as_bytes(), policy_root)?;
        let signed = verified_source.signed;
        if verified_source.identity.0 != source.hash
            || source.hash != material["spec"]["closure"]["hash"]
            || signed.publisher != material["spec"]["publisherKey"]
            || signed.closure.entrypoint != material["spec"]["entryPoint"]
            || signed.closure.members[&signed.closure.entrypoint].hash
                != material["spec"]["executable"]["hash"]
        {
            return Err("prepared tool closure mismatch".into());
        }
    }
    Ok(())
}

fn validate_runtime_resources(execution: &Value, profile: &Value) -> Result<(), String> {
    for (field, maximum) in [
        ("timeoutMillis", 300000),
        ("memoryBytes", 268435456),
        ("taskBytes", 2048),
        ("outputBytes", 65536),
    ] {
        bounded_resource(
            &execution["runtimeLimits"][field],
            &profile["limits"][field],
            maximum,
            field,
        )?;
    }
    let task = text(&execution["payload"], "payload").map_err(|e| e.to_string())?;
    if task.is_empty()
        || task.as_bytes().contains(&0)
        || task.len() > u64v(&execution["runtimeLimits"]["taskBytes"], "taskBytes")? as usize
    {
        return Err("AUTH_LIMIT_OUT_OF_RANGE".into());
    }
    Ok(())
}

fn bounded_resource(
    requested: &Value,
    declared_ceiling: &Value,
    absolute_maximum: u64,
    field: &str,
) -> Result<(), String> {
    let requested = u64v(requested, field)?;
    let ceiling = u64v(declared_ceiling, field)?;
    if requested == 0 || ceiling == 0 || requested > ceiling || ceiling > absolute_maximum {
        return Err("AUTH_LIMIT_OUT_OF_RANGE".into());
    }
    Ok(())
}

fn native_tool(scoped: &ScopedState, material: &Value, binding: &Value) -> Result<Value, String> {
    let spec = &material["spec"];
    if spec["invocationABI"] != "celln.json-stdio/v1"
        || spec["lane"] != "tool"
        || spec["platform"] != "linux/amd64"
        || spec["executable"]["hash"] != binding["hash"]
    {
        return Err("AUTH_PROTOCOL_UNSUPPORTED".into());
    }
    let schemas = Store::open(scoped.root.parent().unwrap().join("tool-schemas"))
        .map_err(|_| "tool schema store unavailable")?;
    let schema = |reference: &Value| -> Result<Value, String> {
        let hash = text(&reference["hash"], "schema hash").map_err(|e| e.to_string())?;
        let bytes = schemas
            .get_bounded(
                &Hash(hash.into()),
                celln_manifest::tool_schema::MAX_SCHEMA_BYTES,
            )
            .map_err(|_| "tool schema unavailable or revision mismatch")?;
        ToolSchema::parse(&bytes, &Hash(hash.into())).map_err(|_| "tool schema invalid")?;
        let bytes = String::from_utf8(bytes).map_err(|_| "tool schema is not UTF-8")?;
        Ok(json!({"hash":hash,"bytes":bytes}))
    };
    Ok(
        json!({"name":material["name"],"path":spec["entryPoint"],"hash":binding["hash"],"description":spec["description"],"input_schema":schema(&spec["argumentsSchema"] )?,"output_schema":schema(&spec["resultSchema"] )?,"input_bytes":binding["limits"]["argumentBytes"],"output_bytes":binding["limits"]["outputBytes"],"timeout_ms":binding["limits"]["timeoutMillis"]}),
    )
}

#[derive(Debug, PartialEq, Eq)]
enum EnrollError {
    Conflict,
    Unavailable,
}

fn enroll_prepared(
    scoped: &ScopedState,
    candidate: &PreparedRecord,
    bytes: &[u8],
) -> std::result::Result<String, EnrollError> {
    let _lock = scoped
        .operation_lock
        .lock()
        .map_err(|_| EnrollError::Unavailable)?;
    let path = scoped
        .prepared_path(&candidate.id)
        .map_err(|_| EnrollError::Unavailable)?;
    match read_bounded(&path, MAX_PREPARED, true) {
        Ok(existing) => {
            let existing: PreparedRecord =
                serde_json::from_slice(&existing).map_err(|_| EnrollError::Unavailable)?;
            if existing.id != candidate.id
                || existing.operation != candidate.operation
                || existing.decision != candidate.decision
            {
                return Err(EnrollError::Conflict);
            }
            Ok(existing.owner)
        }
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
        {
            write_new(&path, bytes).map_err(|_| EnrollError::Unavailable)?;
            Ok(candidate.owner.clone())
        }
        Err(_) => Err(EnrollError::Unavailable),
    }
}

fn validate_prepared(operation: &Value, final_decision: &Value) -> Result<()> {
    reject_secret_material(operation)?;
    reject_secret_material(final_decision)?;
    if operation["apiVersion"] != "sympozium.ai/celln-prepared-operation-v1" {
        bail!("unsupported prepared operation")
    }
    let execution = &operation["resolution"]["execution"];
    let base = &operation["resolution"]["decision"];
    if !execution.is_object()
        || base["apiVersion"] != "celln.sympozium.ai/authorisation-decision-v1"
        || final_decision["apiVersion"] != base["apiVersion"]
        || final_decision["lifecycle"] != "one-shot"
        || final_decision["operation"] != "execution.start"
    {
        bail!("unsupported scoped decision")
    }
    let source = &execution["source"];
    if source["clusterId"] != final_decision["clusterId"]
        || source["namespace"] != final_decision["run"]["namespace"]
        || source["namespaceUid"] != final_decision["run"]["namespaceUid"]
        || source["runUid"] != final_decision["run"]["uid"]
        || source["runSpecSha256"] != final_decision["run"]["specSha256"]
    {
        bail!("prepared source identity mismatch")
    }
    let mut allowed = base.clone();
    let base_credential = &execution["credentialSourceRef"];
    let final_credential = &final_decision["route"]["credentialSource"];
    if !base_credential.is_null() {
        if final_credential["kind"] != base_credential["kind"]
            || final_credential["secretName"] != base_credential["secretName"]
            || final_credential["secretKey"] != base_credential["secretKey"]
            || final_credential["secretUid"]
                .as_str()
                .map_or(true, str::is_empty)
        {
            bail!("gateway credential UID pin mismatch")
        }
        allowed["route"]["credentialSource"] = final_credential.clone();
    } else if !final_credential.is_null() {
        bail!("unexpected gateway credential pin")
    }
    if allowed != *final_decision {
        bail!("final decision changed prepared authority")
    }
    let profile_digest = digest_value(&execution["profileSpec"])?;
    let runtime_digest = digest_value(
        &json!({"wrapperSpec":execution["wrapperSpec"],"profileName":execution["profileName"],"profileUid":execution["profileUid"],"profileDigest":profile_digest}),
    )?;
    if final_decision["runtime"]["specSha256"] != runtime_digest
        || final_decision["runtime"]["revision"] != execution["profileSpec"]["revision"]
    {
        bail!("prepared runtime identity mismatch")
    }
    let materials = execution["tools"]
        .as_array()
        .context("prepared tools missing")?;
    let bindings = final_decision["tools"]
        .as_array()
        .context("decision tools missing")?;
    if materials.len() != bindings.len() {
        bail!("prepared tool count mismatch")
    }
    for (material, binding) in materials.iter().zip(bindings) {
        if material["name"] != binding["name"]
            || material["spec"]["revision"] != binding["revision"]
            || material["spec"]["executable"]["hash"] != binding["hash"]
        {
            bail!("prepared ordered tool identity mismatch")
        }
    }
    let external = external_request(operation, final_decision)?;
    if final_decision["requestDigest"] != crate::tenancy_contract::digest(&external) {
        bail!("prepared request digest mismatch")
    }
    Ok(())
}

fn validate_access_decision(original: &Value, access: &Value, operation: &str) -> Result<()> {
    let mut expected = original.clone();
    expected["operation"] = Value::String(operation.into());
    expected["windows"] = access["windows"].clone();
    if expected != *access {
        bail!("access decision changed original authority")
    }
    Ok(())
}

fn receiver_context(
    operation: &Value,
    decision: &Value,
    expected_operation: &str,
) -> Result<ReceiverContext> {
    let source = &operation["resolution"]["execution"]["source"];
    Ok(ReceiverContext {
        now: now(),
        expected_audience: "celln-execution".into(),
        expected_operation: expected_operation.into(),
        cluster_id: text(&source["clusterId"], "cluster")?.into(),
        namespace: text(&source["namespace"], "namespace")?.into(),
        namespace_uid: text(&source["namespaceUid"], "namespace UID")?.into(),
        run_uid: text(&source["runUid"], "run UID")?.into(),
        run_spec_sha256: text(&source["runSpecSha256"], "run digest")?.into(),
        parent: decision["parent"].clone(),
        request_digest: text(&decision["requestDigest"], "request digest")?.into(),
        route: decision["route"].clone(),
        budget_id: text(&decision["budget"]["budgetId"], "budget")?.into(),
        seen_admission_jti: false,
    })
}

fn external_request(operation: &Value, decision: &Value) -> Result<Vec<u8>> {
    let material = &operation["resolution"]["execution"];
    let mut value = json!({"apiVersion":"celln.sympozium.ai/execution-request-v1","operation":decision["operation"],"payload":material["payload"],"runUid":material["source"]["runUid"]});
    if let Some(parent) = decision.get("parent").filter(|v| !v.is_null()) {
        value["parentIncarnation"] = parent["incarnation"].clone();
        if !parent["turnId"].is_null() {
            value["turnId"] = parent["turnId"].clone();
        }
    }
    crate::tenancy_contract::canonical(&serde_json::to_vec(&value)?)
        .map_err(|_| anyhow::anyhow!("invalid external request"))
}

fn operation_id(operation: &Value, decision: &Value) -> Result<String> {
    let source = &operation["resolution"]["execution"]["source"];
    let tuple = json!([
        "celln.scoped-operation/v1",
        source["clusterId"],
        source["namespaceUid"],
        source["runUid"],
        decision["parent"]["incarnation"],
        decision["parent"]["turnId"]
    ]);
    Ok(crate::tenancy_contract::digest(
        &crate::tenancy_contract::canonical(&serde_json::to_vec(&tuple)?)
            .map_err(anyhow::Error::msg)?,
    ))
}

fn digest_value(value: &Value) -> Result<String> {
    Ok(crate::tenancy_contract::digest(
        &crate::tenancy_contract::canonical(&serde_json::to_vec(value)?)
            .map_err(anyhow::Error::msg)?,
    ))
}
fn text<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value.as_str().with_context(|| format!("missing {field}"))
}
fn u64v(value: &Value, field: &str) -> Result<u64, String> {
    value.as_u64().ok_or_else(|| format!("invalid {field}"))
}
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .min(i64::MAX as u64) as i64
}

fn admission_reply(stream: &mut std::net::TcpStream, error: AdmissionError) -> Result<()> {
    let (status, reason) = match error {
        AdmissionError::Credential(r) => (401, r),
        AdmissionError::RequestConflict => (409, "AUTH_REQUEST_BINDING_MISMATCH"),
        AdmissionError::Capacity => (503, "AUTH_CAPACITY"),
        AdmissionError::BudgetExhausted => (429, "AUTH_BUDGET_EXHAUSTED"),
        AdmissionError::Busy => (409, "AUTH_BUSY"),
        AdmissionError::Fenced => (409, "AUTH_CONTEXT_LOST"),
        AdmissionError::Unavailable => (503, "AUTH_CONTEXT_LOST"),
    };
    reply(
        stream,
        status,
        &json!({"error":"scoped admission refused","reason":reason}),
    )
}

fn terminal_refusal(scoped: &ScopedState, fresh: &Fresh, id: &str, reason: String) -> ScopedStatus {
    let status = terminal_status(id, scoped.admission.owner(), "Refused", Some(reason), None);
    let _ = persist_status(scoped, &status);
    let _ = scoped.admission.finish(fresh, Outcome::Refused);
    status
}
fn terminal_status(
    id: &str,
    owner: &str,
    phase: &str,
    reason: Option<String>,
    output: Option<String>,
) -> ScopedStatus {
    ScopedStatus {
        id: id.into(),
        owner: owner.into(),
        phase: phase.into(),
        reason,
        output,
        receipt_digest: None,
        cleanup_confirmed: true,
    }
}

fn private_dir(path: &Path) -> Result<()> {
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e.into()),
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
    {
        bail!("scoped state directory is not private")
    }
    Ok(())
}

fn read_bounded(path: &Path, max: usize, private: bool) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || (private
            && (metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0))
    {
        bail!("scoped state file is not private")
    }
    file.take((max + 1) as u64).read_to_end(&mut bytes)?;
    if bytes.len() > max {
        bail!("bounded file exceeds limit")
    }
    Ok(bytes)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    use std::io::Write;
    file.write_all(bytes)?;
    file.sync_all()?;
    File::open(path.parent().unwrap())?.sync_all()?;
    Ok(())
}

fn persist_status(scoped: &ScopedState, status: &ScopedStatus) -> Result<()> {
    let bytes = serde_json::to_vec(status)?;
    if bytes.len() > MAX_STATUS {
        bail!("scoped status exceeds bound")
    }
    let path = scoped.status_path(&status.id)?;
    let mut staged = tempfile::NamedTempFile::new_in(path.parent().unwrap())?;
    use std::io::Write;
    staged.write_all(&bytes)?;
    staged.flush()?;
    staged.as_file().sync_all()?;
    staged.persist(path)?;
    File::open(scoped.root.join("status"))?.sync_all()?;
    Ok(())
}

fn id_hex(id: &str) -> Result<&str> {
    let value = id.strip_prefix("sha256:").context("invalid scoped id")?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        bail!("invalid scoped id")
    }
    Ok(value)
}

fn reject_secret_material(value: &Value) -> Result<()> {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                if matches!(
                    key.as_str(),
                    "token" | "bearer" | "password" | "apiKey" | "secretValue" | "credentialFile"
                ) {
                    bail!("prepared operation contains credential material")
                }
                reject_secret_material(value)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                reject_secret_material(value)?;
            }
        }
        _ => {}
    }
    Ok(())
}

use std::os::unix::fs::PermissionsExt;

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (Value, Value) {
        let profile = json!({
            "revision":"v1","contractVersion":"celln.json-tools/v1",
            "executable":{"hash":Hash::of(b"runtime").0},
            "closure":{"hash":Hash::of(b"runtime-closure").0},
            "mote":{"hash":Hash::of(b"mote").0},
            "publisherKey":"a".repeat(64),"entryPoint":"/runtime",
            "platform":"linux/amd64","lane":"agent","lifecycles":["disposable-one-shot"],
            "limits":{"timeoutMillis":30000,"memoryBytes":67108864,"taskBytes":2048,"outputBytes":65536,"workspace":"none"},
            "json":{"maxTurns":2,"maxCalls":1}
        });
        let wrapper = json!({"cellnProfileRef":{"name":"runtime","revision":"v1"},"image":"","contractVersion":"v1"});
        let runtime_digest = digest_value(&json!({
            "wrapperSpec":wrapper,"profileName":"runtime","profileUid":"profile-uid",
            "profileDigest":digest_value(&profile).unwrap()
        }))
        .unwrap();
        let source = json!({"clusterId":"cluster","namespace":"tenant","namespaceUid":"namespace-uid","runName":"run","runUid":"run-uid","runSpecSha256":format!("sha256:{}","1".repeat(64))});
        let tool_spec = json!({
            "revision":"v1","description":"fixture tool","supportOwner":"test","publisherKey":"b".repeat(64),
            "executable":{"hash":Hash::of(b"tool").0},"closure":{"hash":Hash::of(b"tool-closure").0},
            "entryPoint":"/tool","invocationABI":"celln.json-stdio/v1",
            "argumentsSchema":{"hash":Hash::of(b"input-schema").0},"resultSchema":{"hash":Hash::of(b"output-schema").0},
            "platform":"linux/amd64","lane":"tool","limits":{"timeoutMillis":1000,"memoryBytes":67108864,"argumentBytes":1024,"outputBytes":1024,"workspace":"none","effects":"none"}
        });
        let material = json!({
            "source":source,"wrapperSpec":wrapper,"profileName":"runtime","profileUid":"profile-uid","profileSpec":profile,
            "tools":[{"name":"tool","uid":"tool-uid","spec":tool_spec}],
            "runtimeLimits":{"timeoutMillis":30000,"memoryBytes":67108864,"taskBytes":2048,"outputBytes":65536,"workspace":"none"},
            "payload":"{\"value\":1}","systemPrompt":"fixture","modelConnectionName":"","credentialSourceRef":null
        });
        let mut decision = json!({
            "apiVersion":"celln.sympozium.ai/authorisation-decision-v1","kind":"CellnAuthorisationDecision","clusterId":"cluster",
            "run":{"namespace":"tenant","namespaceUid":"namespace-uid","name":"run","uid":"run-uid","specSha256":format!("sha256:{}","1".repeat(64))},
            "subject":{"kind":"AgentRun","namespace":"tenant","name":"run","uid":"run-uid","specSha256":format!("sha256:{}","1".repeat(64))},
            "operation":"execution.start","lifecycle":"one-shot","parent":null,
            "runtime":{"name":"runtime","uid":"runtime-uid","revision":"v1","specSha256":runtime_digest},
            "agent":{"kind":"Agent","namespace":"tenant","name":"agent","uid":"agent-uid","specSha256":format!("sha256:{}","2".repeat(64))},
            "policy":{"profile":"default","revision":"v1","digest":format!("sha256:{}","3".repeat(64))},
            "tools":[{"name":"tool","revision":"v1","hash":Hash::of(b"tool").0,"limits":{"timeoutMillis":1000,"memoryBytes":67108864,"argumentBytes":1024,"outputBytes":1024,"workspace":"none","effects":"none","artifacts":null,"https":null}}],
            "route":{"modelConnectionUid":null,"modelConnectionSpecSha256":"","provider":"none","protocol":"none","model":"","endpointOrigin":"","auth":"none","streaming":false,"credentialSource":null},
            "budget":{"budgetId":"budget","runCap":{"requests":1,"outputTokens":1},"turnCap":{"requests":1,"outputTokens":1},"maxTurns":1,"parentDeadlineUnix":0,"turnDeadlineUnix":2000000000},
            "windows":{"issuedAt":1900000000,"notBefore":1900000000,"admissionDeadline":1900000060},"requestDigest":""
        });
        let mut operation = json!({"apiVersion":"sympozium.ai/celln-prepared-operation-v1","resolution":{"execution":material,"decision":decision,"readSet":[]},"resolveRequest":{}});
        let request = external_request(&operation, &decision).unwrap();
        decision["requestDigest"] = json!(crate::tenancy_contract::digest(&request));
        operation["resolution"]["decision"] = decision.clone();
        (operation, decision)
    }

    #[test]
    fn preparation_binds_independent_source_runtime_tools_and_external_request() {
        let (operation, decision) = fixture();
        validate_prepared(&operation, &decision).unwrap();
        let mut forged = decision.clone();
        forged["run"]["uid"] = json!("inline-claimed-other-run");
        assert!(validate_prepared(&operation, &forged).is_err());
        let mut changed = decision;
        changed["budget"]["turnCap"]["requests"] = json!(2);
        assert!(validate_prepared(&operation, &changed).is_err());
    }

    #[test]
    fn only_gateway_credential_uid_pin_may_change_the_prepared_decision() {
        let (mut operation, mut decision) = fixture();
        let reference = json!({"kind":"Secret","secretName":"provider","secretKey":"token"});
        operation["resolution"]["execution"]["credentialSourceRef"] = reference.clone();
        decision["route"]["credentialSource"] = json!({"kind":"Secret","secretUid":"secret-uid","secretName":"provider","secretKey":"token"});
        validate_prepared(&operation, &decision).unwrap();
        decision["route"]["endpointOrigin"] = json!("https://changed.invalid/v1");
        assert!(validate_prepared(&operation, &decision).is_err());
    }

    #[test]
    fn stable_operation_identity_forces_conflicting_repreparation_to_collide() {
        let (operation, decision) = fixture();
        let id = operation_id(&operation, &decision).unwrap();
        let mut conflicting = operation.clone();
        conflicting["resolution"]["execution"]["payload"] = json!("different");
        assert_eq!(id, operation_id(&conflicting, &decision).unwrap());
    }

    #[test]
    fn runtime_resources_cannot_exceed_the_enrolled_profile() {
        let (mut operation, _) = fixture();
        let execution = &mut operation["resolution"]["execution"];
        let profile = execution["profileSpec"].clone();
        validate_runtime_resources(execution, &profile).unwrap();
        execution["runtimeLimits"]["memoryBytes"] = json!(67108865u64);
        assert!(validate_runtime_resources(execution, &profile).is_err());
    }

    #[test]
    fn scoped_receiver_is_disabled_or_fails_closed_on_partial_operator_config() {
        let root = tempfile::tempdir().unwrap();
        let probe = crate::NodeProbeArgs {
            node_name: "test".into(),
            mote_store: root.path().join("motes"),
            tool_store: root.path().join("tools"),
            max_cells: 1,
            memory_bytes: 67108864,
            egress_slots: 0,
        };
        assert!(ScopedState::configure(
            root.path(),
            ScopedOptions {
                operator_token_file: None,
                jwks_file: None,
                issuer: None,
                gateway_origin: None,
                gateway_ca: None
            },
            &probe
        )
        .unwrap()
        .is_none());
        assert!(ScopedState::configure(
            root.path(),
            ScopedOptions {
                operator_token_file: Some(Path::new("missing")),
                jwks_file: None,
                issuer: None,
                gateway_origin: None,
                gateway_ca: None
            },
            &probe
        )
        .is_err());
    }

    fn test_scoped(root: &Path) -> ScopedState {
        private_dir(&root.join("scoped")).unwrap();
        private_dir(&root.join("scoped/prepared")).unwrap();
        private_dir(&root.join("scoped/status")).unwrap();
        let jwks =
            include_bytes!("../../../tests/fixtures/celln-authorisation/v1/signing/test-jwks.json");
        ScopedState {
            operator_token_file: root.join("unused-token"),
            jwks_file: root.join("unused-jwks"),
            verifier: Verifier::from_jwks("sympozium-control-plane".into(), jwks).unwrap(),
            admission: Arc::new(Journal::open(&root.join("scoped/admission"), 16).unwrap()),
            root: root.join("scoped"),
            gateway: None,
            operation_lock: Mutex::new(()),
        }
    }

    #[test]
    fn durable_enrollment_preserves_owner_epoch_and_rejects_conflicting_reprepare() {
        let root = tempfile::tempdir().unwrap();
        let first = test_scoped(root.path());
        let (operation, decision) = fixture();
        let id = operation_id(&operation, &decision).unwrap();
        let initial = PreparedRecord {
            version: 1,
            id,
            owner: first.admission.owner().into(),
            operation: operation.clone(),
            decision: decision.clone(),
        };
        let initial_bytes = serde_json::to_vec(&initial).unwrap();
        assert_eq!(
            enroll_prepared(&first, &initial, &initial_bytes).unwrap(),
            first.admission.owner()
        );

        let second = test_scoped(root.path());
        assert_ne!(first.admission.owner(), second.admission.owner());
        let mut recovered = initial.clone();
        recovered.owner = second.admission.owner().into();
        assert_eq!(
            enroll_prepared(
                &second,
                &recovered,
                &serde_json::to_vec(&recovered).unwrap()
            )
            .unwrap(),
            first.admission.owner()
        );

        let mut conflicting_operation = operation;
        let mut conflicting_decision = decision;
        conflicting_operation["resolution"]["execution"]["payload"] = json!("different");
        let digest = crate::tenancy_contract::digest(
            &external_request(&conflicting_operation, &conflicting_decision).unwrap(),
        );
        conflicting_decision["requestDigest"] = json!(digest);
        conflicting_operation["resolution"]["decision"] = conflicting_decision.clone();
        let conflicting = PreparedRecord {
            operation: conflicting_operation,
            decision: conflicting_decision,
            ..recovered
        };
        assert_eq!(
            enroll_prepared(
                &second,
                &conflicting,
                &serde_json::to_vec(&conflicting).unwrap()
            ),
            Err(EnrollError::Conflict)
        );
    }
}
