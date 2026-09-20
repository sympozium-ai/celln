//! Operator-authenticated, receiver-owned native tenancy integration.
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
    collections::{BTreeMap, HashMap},
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

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ParentTemplate {
    api_version: String,
    request: ExecutionRequest,
    /// Logical host reservation selected by the operator. This is checked by
    /// ParentRegistry; it is not represented as a physical RSS guarantee.
    reserved_memory_bytes: u64,
}

struct PendingTurn {
    control: celln_control::Control,
    broker: HttpBroker,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct NativeProvenance {
    parent_incarnation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    turn_id: Option<String>,
    parent_id: String,
    child_id: String,
    cell_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    execution: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    substrate: Option<Value>,
}

struct EnduringContext {
    principal: String,
    incarnation: Hash,
    worker_binding: Hash,
    pending: Arc<Mutex<BTreeMap<String, PendingTurn>>>,
    active: Arc<Mutex<BTreeMap<String, celln_control::Control>>>,
    results: Arc<Mutex<BTreeMap<String, NativeProvenance>>>,
}

pub(super) struct ScopedState {
    operator_token_file: PathBuf,
    jwks_file: PathBuf,
    verifier: Verifier,
    admission: Arc<Journal>,
    root: PathBuf,
    gateway: Option<GatewayConfig>,
    parent_template: Option<ParentTemplate>,
    enduring: Mutex<HashMap<String, Arc<EnduringContext>>>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    parent_incarnation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    turn_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    parent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    child_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cell_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    execution: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    substrate: Option<Value>,
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
        if !configured[0]
            && (options.gateway_origin.is_some()
                || options.gateway_ca.is_some()
                || options.parent_request_file.is_some())
        {
            bail!("scoped gateway/parent configuration requires the scoped receiver credentials");
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
        let parent_template = match options.parent_request_file {
            Some(path) => {
                if gateway.is_none() {
                    bail!("scoped enduring parent template requires the mediated gateway");
                }
                let raw = read_bounded(path, 262144, false)
                    .context("reading scoped parent request template")?;
                reject_secret_material(
                    &serde_json::from_slice(&raw).context("parsing scoped parent template")?,
                )?;
                let template: ParentTemplate = serde_json::from_slice(&raw)
                    .context("parsing scoped parent request template")?;
                validate_parent_template(&template).map_err(anyhow::Error::msg)?;
                for directory in ["parent-issuance", "trusted-parent-permits"] {
                    operator_dir(&root.join(directory))?;
                }
                Some(template)
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
            parent_template,
            enduring: Mutex::new(HashMap::new()),
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
                            | "Uncertain"
                    )
                    || status.output.as_ref().is_some_and(|v| v.len() > 65536)
                    || status
                        .parent_incarnation
                        .as_ref()
                        .is_some_and(|v| !blake(v))
                    || status.parent_id.as_ref().is_some_and(|v| !blake(v))
                    || status.child_id.as_ref().is_some_and(|v| !blake(v))
                    || status
                        .turn_id
                        .as_ref()
                        .is_some_and(|v| v.is_empty() || v.len() > 128)
                    || status
                        .cell_id
                        .as_ref()
                        .is_some_and(|v| v.is_empty() || v.len() > 256)
                    || status.execution.as_ref().is_some_and(|v| {
                        serde_json::to_vec(v).map_or(true, |raw| raw.len() > 65536)
                    })
                    || status.substrate.as_ref().is_some_and(|v| {
                        serde_json::to_vec(v).map_or(true, |raw| raw.len() > 65536)
                    })
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
        owner: String,
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
    let launch_operation = text(&prepared.decision["operation"], "operation")?;
    if !matches!(launch_operation, "execution.start" | "execution.turn") {
        return reply(
            stream,
            422,
            &json!({"error":"invalid scoped launch operation"}),
        );
    }
    let receiver = receiver_context(&prepared.operation, &prepared.decision, launch_operation)?;
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
    let model_route = prepared.decision["route"]["provider"] != "none";
    if model_route {
        let Some(model_permit) = metadata.model_permit else {
            return reply(
                stream,
                401,
                &json!({"error":"scoped admission refused","reason":"AUTH_CRED_MALFORMED"}),
            );
        };
        let mut model_receiver = receiver.clone();
        model_receiver.expected_operation = "model.invoke".into();
        model_receiver.expected_audience = "sympozium-model-gateway".into();
        if let Err(reason) = scoped
            .verifier
            .verify(model_permit, &decision, &model_receiver)
        {
            return reply(
                stream,
                401,
                &json!({"error":"scoped admission refused","reason":reason}),
            );
        }
    } else if metadata.model_permit.is_some() {
        return reply(
            stream,
            401,
            &json!({"error":"scoped admission refused","reason":"AUTH_ROUTE_MISMATCH"}),
        );
    }
    // Pin the epoch returned by /prepare after full credential verification
    // but before duplicate lookup or any native launch side effect.
    if request.owner != prepared.owner || request.owner != scoped.admission.owner() {
        return reply(
            stream,
            409,
            &json!({"error":"scoped admission refused","reason":"AUTH_CONTEXT_LOST"}),
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
                phase: "Uncertain".into(),
                reason: Some("AUTH_CONTEXT_LOST".into()),
                output: None,
                receipt_digest: None,
                cleanup_confirmed: false,
                parent_incarnation: prepared.decision["parent"]["incarnation"]
                    .as_str()
                    .map(str::to_owned),
                turn_id: prepared.decision["parent"]["turnId"]
                    .as_str()
                    .map(str::to_owned),
                parent_id: None,
                child_id: None,
                cell_id: None,
                execution: None,
                substrate: None,
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
                    phase: "Uncertain".into(),
                    reason: Some("original owner status is unavailable; replay refused".into()),
                    output: None,
                    receipt_digest: None,
                    cleanup_confirmed: false,
                    parent_incarnation: prepared.decision["parent"]["incarnation"]
                        .as_str()
                        .map(str::to_owned),
                    turn_id: prepared.decision["parent"]["turnId"]
                        .as_str()
                        .map(str::to_owned),
                    parent_id: None,
                    child_id: None,
                    cell_id: None,
                    execution: None,
                    substrate: None,
                });
            return reply(
                stream,
                if status.cleanup_confirmed { 200 } else { 202 },
                &status,
            );
        }
        Claim::Fresh(fresh) => fresh,
    };
    let control = match operation_control(&prepared) {
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
    if prepared.decision["lifecycle"] != "one-shot" {
        return start_enduring(
            dispatcher, scoped, stream, prepared, fresh, native, broker, control,
        );
    }
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
        if broker.is_some() && node.egress_slots == 0 {
            drop(registry);
            let status = terminal_refusal(scoped, &fresh, &request.id, "AUTH_CAPACITY".into());
            return reply(stream, 503, &status);
        }
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
        let mut reservation = Reservation::for_request(&native);
        reservation.egress_slots = u32::from(broker.is_some());
        entry.reservation = Some(reservation);
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
        parent_incarnation: None,
        turn_id: None,
        parent_id: None,
        child_id: None,
        cell_id: None,
        execution: None,
        substrate: None,
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

fn operation_control(prepared: &PreparedRecord) -> Result<celln_control::Control, String> {
    let deadline = prepared.decision["budget"]["turnDeadlineUnix"]
        .as_i64()
        .ok_or("invalid operation deadline")?;
    let remaining_seconds = (deadline as i128) - (now() as i128);
    if remaining_seconds <= 0 {
        return Err("AUTH_WORK_DEADLINE_EXPIRED".into());
    }
    let remaining = Duration::from_secs(
        u64::try_from(remaining_seconds).map_err(|_| "invalid operation deadline")?,
    );
    let configured = Duration::from_millis(
        prepared.operation["resolution"]["execution"]["runtimeLimits"]["timeoutMillis"]
            .as_u64()
            .ok_or("invalid runtime timeout")?
            .max(1),
    );
    celln_control::Control::new(configured.min(remaining))
        .map_err(|_| "invalid operation deadline".into())
}

fn parent_scope(prepared: &PreparedRecord) -> Result<String, String> {
    let source = &prepared.operation["resolution"]["execution"]["source"];
    serde_json::to_string(&json!([
        "celln.scoped-parent/v1",
        text(&source["clusterId"], "cluster").map_err(|e| e.to_string())?,
        text(&source["namespaceUid"], "namespace UID").map_err(|e| e.to_string())?
    ]))
    .map_err(|_| "invalid parent scope".into())
}

fn native_json_config(
    prepared: &PreparedRecord,
    tools: &[Value],
    enduring: bool,
) -> Result<Value, String> {
    let execution = &prepared.operation["resolution"]["execution"];
    let limits = &execution["profileSpec"]["json"];
    let max_turns = u64v(&limits["maxTurns"], "maxTurns")?.min(u64v(
        &prepared.decision["budget"]["turnCap"]["requests"],
        "requests",
    )?);
    // One shared adapter: the provider origin is never a guest destination,
    // including retained workers and subsequent mailbox turns.
    Ok(json!({"contract":pilot::json_harness::CONTRACT,
        "task":if enduring {Value::String(String::new())} else {execution["payload"].clone()},
        "system":execution["systemPrompt"],"url":MODEL_ALIAS,"model":prepared.decision["route"]["model"],
        "tools":tools,"max_turns":max_turns,"max_calls":u64v(&limits["maxCalls"],"maxCalls")?,
        "require_tool_call":limits.get("requireToolCall").cloned().unwrap_or(Value::Bool(false))
    }))
}

fn local_turn_id(prepared: &PreparedRecord) -> Result<String, String> {
    if let Some(turn) = prepared.decision["parent"]["turnId"].as_str() {
        return Ok(turn.into());
    }
    let hex = id_hex(&prepared.id).map_err(|_| "invalid initial operation identity")?;
    Ok(format!("initial_{}", &hex[..48]))
}

#[allow(clippy::too_many_arguments)]
fn start_enduring(
    dispatcher: &State,
    scoped: &Arc<ScopedState>,
    stream: &mut std::net::TcpStream,
    prepared: PreparedRecord,
    fresh: Fresh,
    worker: ExecutionRequest,
    broker: Option<HttpBroker>,
    control: celln_control::Control,
) -> Result<()> {
    let lifecycle = text(&prepared.decision["lifecycle"], "lifecycle")?;
    let incarnation = Hash(
        text(
            &prepared.decision["parent"]["incarnation"],
            "parent incarnation",
        )?
        .into(),
    );
    let principal = worker.workload.caller.clone();
    let turn_id = local_turn_id(&prepared).map_err(anyhow::Error::msg)?;
    let broker = match broker {
        Some(broker) if broker.is_mediated() => broker,
        _ => {
            let status = prepared_refusal(
                scoped,
                &fresh,
                &prepared,
                "AUTH_PROTOCOL_UNSUPPORTED".into(),
            );
            return reply(stream, 422, &status);
        }
    };
    let worker_config: pilot::json_harness::Config = worker
        .invocation
        .as_ref()
        .and_then(|_| {
            let execution = &prepared.operation["resolution"]["execution"];
            let tools = execution["tools"]
                .as_array()?
                .iter()
                .zip(prepared.decision["tools"].as_array()?)
                .map(|(material, binding)| native_tool(scoped, material, binding).ok())
                .collect::<Option<Vec<_>>>()?;
            serde_json::from_value(native_json_config(&prepared, &tools, true).ok()?).ok()
        })
        .ok_or_else(|| anyhow::anyhow!("invalid enduring worker template"))?;
    let worker_binding =
        crate::dispatch::parent_create::scoped::worker_binding(&worker, &worker_config)
            .map_err(anyhow::Error::msg)?;

    if lifecycle == "enduring-turn" {
        let context = scoped
            .enduring
            .lock()
            .map_err(|_| anyhow::anyhow!("enduring owner registry unavailable"))?
            .get(&incarnation.0)
            .cloned();
        let Some(context) = context else {
            let status = uncertain_status(&prepared, "AUTH_CONTEXT_LOST");
            let _ = persist_status(scoped, &status);
            return reply(stream, 409, &status);
        };
        if context.principal != principal || context.worker_binding != worker_binding {
            let status = prepared_refusal(
                scoped,
                &fresh,
                &prepared,
                "AUTH_REQUEST_BINDING_MISMATCH".into(),
            );
            return reply(stream, 409, &status);
        }
        return submit_enduring_turn(
            dispatcher, scoped, stream, prepared, fresh, context, turn_id, broker, control, false,
        );
    }
    if lifecycle != "enduring-initial" {
        let status = prepared_refusal(scoped, &fresh, &prepared, "AUTH_LIFECYCLE_INVALID".into());
        return reply(stream, 422, &status);
    }
    let template = match scoped.parent_template.clone() {
        Some(template) => template,
        None => {
            let status = prepared_refusal(
                scoped,
                &fresh,
                &prepared,
                "AUTH_PROTOCOL_UNSUPPORTED".into(),
            );
            return reply(stream, 503, &status);
        }
    };
    let source = &prepared.operation["resolution"]["execution"]["source"];
    let scope = parent_scope(&prepared).map_err(anyhow::Error::msg)?;
    let expected =
        warden::parent_permit::run_incarnation(&scope, text(&source["runUid"], "run UID")?)?;
    if expected != incarnation {
        let status = prepared_refusal(
            scoped,
            &fresh,
            &prepared,
            "AUTH_PARENT_TURN_MISMATCH".into(),
        );
        return reply(stream, 409, &status);
    }
    let parent_deadline = prepared.decision["budget"]["parentDeadlineUnix"]
        .as_i64()
        .ok_or_else(|| anyhow::anyhow!("invalid parent deadline"))?;
    let parent_remaining = (parent_deadline as i128) - (now() as i128);
    if parent_remaining <= 0 {
        let status = prepared_refusal(
            scoped,
            &fresh,
            &prepared,
            "AUTH_WORK_DEADLINE_EXPIRED".into(),
        );
        return reply(stream, 422, &status);
    }
    let reserved_memory_bytes = template.reserved_memory_bytes;
    let mut parent = template.request;
    parent.id = format!("scoped-parent-{}", &incarnation.0[7..]);
    parent.workload.id = parent.id.clone();
    parent.workload.caller = principal.clone();
    let parent_remaining_ms = u64::try_from(parent_remaining)
        .ok()
        .and_then(|v| v.checked_mul(1000))
        .ok_or_else(|| anyhow::anyhow!("invalid parent deadline"))?;
    parent.capabilities.timeout_ms = parent
        .capabilities
        .timeout_ms
        .min(parent_remaining_ms)
        .max(1);
    let binding = warden::parent_permit::Binding {
        principal: principal.clone(),
        incarnation: incarnation.clone(),
        parent_configuration: parent
            .configuration_binding(celln_spec::ConfigurationRole::Parent)
            .map_err(anyhow::Error::msg)?,
        worker_configuration: worker_binding.clone(),
        parent_memory_bytes: parent.capabilities.memory_bytes,
        child_memory_bytes: worker.capabilities.memory_bytes,
        lifetime_ms: parent.capabilities.timeout_ms,
        turn_timeout_ms: worker.capabilities.timeout_ms,
        max_turns: prepared.decision["budget"]["maxTurns"]
            .as_u64()
            .and_then(|v| usize::try_from(v).ok())
            .ok_or_else(|| anyhow::anyhow!("invalid enduring turn limit"))?,
        turn_model_requests: prepared.decision["budget"]["turnCap"]["requests"]
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("invalid turn budget"))?,
        turn_output_tokens: prepared.decision["budget"]["turnCap"]["outputTokens"]
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("invalid turn budget"))?,
        total_model_requests: prepared.decision["budget"]["runCap"]["requests"]
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("invalid run budget"))?,
        total_output_tokens: prepared.decision["budget"]["runCap"]["outputTokens"]
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("invalid run budget"))?,
    };
    let reservation_floor = binding
        .parent_memory_bytes
        .checked_add(binding.child_memory_bytes)
        .and_then(|bytes| bytes.checked_mul(2))
        .ok_or_else(|| anyhow::anyhow!("parent reservation overflow"))?;
    if reserved_memory_bytes <= reservation_floor {
        let status = prepared_refusal(scoped, &fresh, &prepared, "AUTH_CAPACITY".into());
        return reply(stream, 503, &status);
    }
    if control.check().is_err() {
        let status = prepared_refusal(
            scoped,
            &fresh,
            &prepared,
            "AUTH_WORK_DEADLINE_EXPIRED".into(),
        );
        return reply(stream, 422, &status);
    }
    // Share the one-shot/legacy parent admission lock until the scoped owner's
    // memory, child-cell and broker reservation is visible in ParentRegistry.
    let registry = dispatcher.executions.lock().unwrap();
    {
        let node = current_node(dispatcher, &registry);
        if node.live_cells.saturating_add(2) > node.max_cells
            || reserved_memory_bytes > node.memory_bytes
            || node.egress_slots == 0
        {
            drop(registry);
            let status = prepared_refusal(scoped, &fresh, &prepared, "AUTH_CAPACITY".into());
            return reply(stream, 503, &status);
        }
        for request in [&parent, &worker] {
            if let crate::node::Admission::Refused { reason, .. } =
                crate::node::admit(request, &node)
            {
                drop(registry);
                let status = prepared_refusal(
                    scoped,
                    &fresh,
                    &prepared,
                    format!("native admission refused: {reason:?}"),
                );
                return reply(stream, 503, &status);
            }
        }
    }
    // This local permit is derived only after the independent durable scoped
    // claim above. It contains no model credential and is immediately consumed
    // by the retained owner factory.
    let intent = Hash::of(&serde_json::to_vec(&json!({
        "apiVersion":"celln.scoped-parent-intent/v1","operation":prepared.operation,
        "decision":prepared.decision,"parent":parent,"workerBinding":worker_binding
    }))?);
    let permit = match warden::parent_permit::issue_for_run(
        &dispatcher.root,
        &scope,
        text(&source["runUid"], "run UID")?,
        &intent,
        binding.clone(),
        Duration::from_millis(300_000),
    ) {
        Ok(permit) => permit,
        Err(_) => {
            let status = prepared_refusal(
                scoped,
                &fresh,
                &prepared,
                "native parent permit issuance unavailable".into(),
            );
            return reply(stream, 503, &status);
        }
    };
    let permit = match permit.publish(&dispatcher.root) {
        Ok(permit) => permit,
        Err(_) => {
            let status = prepared_refusal(
                scoped,
                &fresh,
                &prepared,
                "native parent permit publication unavailable".into(),
            );
            return reply(stream, 503, &status);
        }
    };
    let pending = Arc::new(Mutex::new(BTreeMap::<String, PendingTurn>::new()));
    let active = Arc::new(Mutex::new(BTreeMap::<String, celln_control::Control>::new()));
    let results = Arc::new(Mutex::new(BTreeMap::<String, NativeProvenance>::new()));
    let supply_pending = Arc::clone(&pending);
    let supply_active = Arc::clone(&active);
    let result_active = Arc::clone(&active);
    let result_sink = Arc::clone(&results);
    let supply_incarnation = incarnation.clone();
    let result_incarnation = incarnation.clone();
    let brokers: crate::dispatch::parent_create::scoped::Brokers = Box::new(move |turn| {
        if turn.parent != supply_incarnation {
            return Err("reserved turn belongs to another parent".into());
        }
        let pending = supply_pending
            .lock()
            .map_err(|_| "scoped turn broker registry unavailable")?
            .remove(&turn.request.turn_id)
            .ok_or("fresh scoped broker unavailable for reserved turn")?;
        let parent_control =
            celln_control::current().ok_or("scoped broker factory requires exact child control")?;
        let remaining = if pending.control.check().is_err() {
            Duration::ZERO
        } else {
            pending.control.remaining()
        };
        let child_control = parent_control
            .child(remaining)
            .map_err(|_| "invalid absolute turn deadline")?;
        supply_active
            .lock()
            .map_err(|_| "scoped active turn registry unavailable")?
            .insert(turn.request.turn_id.clone(), pending.control);
        Ok(crate::dispatch::parent_create::scoped::ScopedTurnBroker {
            broker: pending.broker,
            control: child_control,
        })
    });
    let result_callback: crate::dispatch::parent_create::scoped::Results =
        Box::new(move |turn, outcome| {
            if turn.parent != result_incarnation {
                return Err("native child result belongs to another parent".into());
            }
            result_active
                .lock()
                .map_err(|_| "scoped active turn registry unavailable")?
                .remove(&turn.request.turn_id);
            if outcome.cell_id.is_empty()
                || outcome.execution.is_none()
                || outcome.substrate.is_none()
            {
                return Err("native child provenance is incomplete".into());
            }
            let provenance = NativeProvenance {
                parent_incarnation: turn.parent.0.clone(),
                turn_id: Some(turn.request.turn_id.clone()),
                parent_id: turn.parent.0.clone(),
                child_id: turn.child.0.clone(),
                cell_id: outcome.cell_id.clone(),
                execution: outcome
                    .execution
                    .as_ref()
                    .and_then(|v| serde_json::to_value(v).ok()),
                substrate: outcome
                    .substrate
                    .as_ref()
                    .and_then(|v| serde_json::to_value(v).ok()),
            };
            result_sink
                .lock()
                .map_err(|_| "scoped turn result registry unavailable")?
                .insert(turn.request.turn_id.clone(), provenance);
            Ok(())
        });
    let plan = crate::dispatch::parent_create::scoped::Plan {
        parent,
        worker,
        template: worker_config,
        permit,
        binding: binding.clone(),
    };
    let factory = match crate::dispatch::parent_create::scoped::claim(
        dispatcher.root.clone(),
        plan,
        &principal,
        brokers,
        result_callback,
    ) {
        Ok(factory) => factory,
        Err(reason) => {
            let status = uncertain_parent_refusal(scoped, &fresh, &prepared, reason);
            return reply(stream, 503, &status);
        }
    };
    if control.check().is_err() {
        let status = prepared_refusal(
            scoped,
            &fresh,
            &prepared,
            "AUTH_WORK_DEADLINE_EXPIRED".into(),
        );
        return reply(stream, 422, &status);
    }
    let context = Arc::new(EnduringContext {
        principal: principal.clone(),
        incarnation: incarnation.clone(),
        worker_binding,
        pending,
        active,
        results,
    });
    scoped
        .enduring
        .lock()
        .map_err(|_| anyhow::anyhow!("enduring owner registry unavailable"))?
        .insert(incarnation.0.clone(), Arc::clone(&context));
    if let Err(reason) = dispatcher.parents.spawn_admitted_with_child_broker(
        &principal,
        &incarnation,
        Duration::from_millis(binding.lifetime_ms),
        reserved_memory_bytes,
        factory,
    ) {
        scoped.enduring.lock().unwrap().remove(&incarnation.0);
        let status = uncertain_parent_refusal(scoped, &fresh, &prepared, reason);
        return reply(stream, 503, &status);
    }
    drop(registry);
    submit_enduring_turn(
        dispatcher, scoped, stream, prepared, fresh, context, turn_id, broker, control, true,
    )
}

#[allow(clippy::too_many_arguments)]
fn submit_enduring_turn(
    dispatcher: &State,
    scoped: &Arc<ScopedState>,
    stream: &mut std::net::TcpStream,
    prepared: PreparedRecord,
    fresh: Fresh,
    context: Arc<EnduringContext>,
    turn_id: String,
    broker: HttpBroker,
    control: celln_control::Control,
    initial: bool,
) -> Result<()> {
    if control.check().is_err() {
        if initial
            && dispatcher
                .parents
                .stop(&context.principal, &context.incarnation)
                .is_err()
        {
            let status = uncertain_status(
                &prepared,
                "initial deadline expired and retained parent teardown is unconfirmed",
            );
            let _ = persist_status(scoped, &status);
            return reply(stream, 503, &status);
        }
        let status = prepared_refusal(
            scoped,
            &fresh,
            &prepared,
            "AUTH_WORK_DEADLINE_EXPIRED".into(),
        );
        return reply(stream, 422, &status);
    }
    let child = Hash::of(
        &serde_json::to_vec(&(&context.incarnation.0, &turn_id))
            .map_err(|_| anyhow::anyhow!("invalid child identity"))?,
    );
    let replaced = context
        .pending
        .lock()
        .map_err(|_| anyhow::anyhow!("scoped turn broker registry unavailable"))?
        .insert(turn_id.clone(), PendingTurn { control, broker });
    if replaced.is_some() {
        let status = uncertain_status(&prepared, "fresh turn broker identity already occupied");
        let _ = persist_status(scoped, &status);
        return reply(stream, 409, &status);
    }
    let status = ScopedStatus {
        id: prepared.id.clone(),
        owner: scoped.admission.owner().into(),
        phase: "Admitted".into(),
        reason: None,
        output: None,
        receipt_digest: None,
        cleanup_confirmed: false,
        parent_incarnation: Some(context.incarnation.0.clone()),
        turn_id: prepared.decision["parent"]["turnId"]
            .as_str()
            .map(str::to_owned),
        parent_id: Some(context.incarnation.0.clone()),
        child_id: Some(child.0),
        cell_id: None,
        execution: None,
        substrate: None,
    };
    if persist_status(scoped, &status).is_err() {
        context.pending.lock().unwrap().remove(&turn_id);
        let status = prepared_refusal(
            scoped,
            &fresh,
            &prepared,
            "durable result journal unavailable".into(),
        );
        return reply(stream, 503, &status);
    }
    let envelope = serde_json::to_vec(&json!({
        "kind":"turn","apiVersion":pilot::parent_harness::VERSION,
        "turnId":turn_id,"message":prepared.operation["resolution"]["execution"]["payload"]
    }))?;
    let response =
        match dispatcher
            .parents
            .submit(&context.principal, &context.incarnation, &envelope)
        {
            Ok(response) => response,
            Err(reason) => {
                context.pending.lock().unwrap().remove(&turn_id);
                let status = uncertain_status(&prepared, &reason);
                let _ = persist_status(scoped, &status);
                return reply(stream, 409, &status);
            }
        };
    let id = prepared.id.clone();
    let worker_scoped = Arc::clone(scoped);
    let worker_context = Arc::clone(&context);
    let failed_prepared = prepared.clone();
    let fresh_slot = Arc::new(Mutex::new(Some(fresh)));
    let worker_fresh = Arc::clone(&fresh_slot);
    let spawn = thread::Builder::new()
        .name("celln-scoped-enduring-turn".into())
        .spawn(move || {
            let fresh = worker_fresh
                .lock()
                .expect("enduring fresh claim not poisoned")
                .take()
                .expect("enduring fresh claim consumed once");
            finish_enduring_turn(
                worker_scoped,
                worker_context,
                fresh,
                prepared,
                turn_id,
                response,
                initial,
            )
        });
    if spawn.is_err() {
        let status = uncertain_status(
            &failed_prepared,
            "enduring result worker unavailable after accepted parent submission",
        );
        let _ = persist_status(scoped, &status);
        // Keep the fresh claim unfinished: the retained owner may still execute
        // the accepted command after this local observation failure.
        drop(fresh_slot.lock().ok().and_then(|mut slot| slot.take()));
        return reply(stream, 503, &status);
    }
    reply(stream, 202, &ScopedStatus { id, ..status })
}

fn finish_enduring_turn(
    scoped: Arc<ScopedState>,
    context: Arc<EnduringContext>,
    fresh: Fresh,
    prepared: PreparedRecord,
    turn_id: String,
    response: std::sync::mpsc::Receiver<Result<Vec<u8>, String>>,
    initial: bool,
) {
    let response = response.recv();
    if let Ok(mut active) = context.active.lock() {
        active.remove(&turn_id);
    }
    let provenance = context
        .results
        .lock()
        .ok()
        .and_then(|mut r| r.remove(&turn_id));
    let (phase, reason, output, cleanup_confirmed) = match response {
        Ok(Ok(bytes)) => match serde_json::from_slice::<Value>(&bytes) {
            Ok(value) if value["kind"] == "completed" && value["turnId"] == turn_id => {
                let succeeded = value["succeeded"].as_bool().unwrap_or(false);
                (
                    if succeeded {
                        if initial {
                            "Running"
                        } else {
                            "Succeeded"
                        }
                    } else if initial {
                        "Failed"
                    } else {
                        "Cancelled"
                    },
                    if succeeded {
                        None
                    } else {
                        Some("native child did not commit a successful result".into())
                    },
                    value["answer"].as_str().map(str::to_owned),
                    !initial,
                )
            }
            _ => (
                "Uncertain",
                Some("invalid retained parent result".into()),
                None,
                false,
            ),
        },
        Ok(Err(reason)) => (
            if provenance.is_some() {
                "Failed"
            } else {
                "Uncertain"
            },
            Some(reason),
            None,
            provenance.is_some() && !initial,
        ),
        Err(_) => (
            "Uncertain",
            Some("retained parent owner result lost".into()),
            None,
            false,
        ),
    };
    let receipt_digest = provenance.as_ref().and_then(|native| {
        serde_json::to_vec(&json!({
            "apiVersion":"celln.scoped-native-receipt/v1","operationId":prepared.id,
            "owner":scoped.admission.owner(),"phase":phase,"native":native
        }))
        .ok()
        .map(|bytes| Hash::of(&bytes).0)
    });
    let reserved_child =
        Hash::of(&serde_json::to_vec(&(&context.incarnation.0, &turn_id)).unwrap_or_default()).0;
    let status = ScopedStatus {
        id: prepared.id.clone(),
        owner: scoped.admission.owner().into(),
        phase: phase.into(),
        reason,
        output,
        receipt_digest: receipt_digest.clone(),
        cleanup_confirmed,
        parent_incarnation: Some(context.incarnation.0.clone()),
        turn_id: prepared.decision["parent"]["turnId"]
            .as_str()
            .map(str::to_owned),
        parent_id: provenance
            .as_ref()
            .map(|p| p.parent_id.clone())
            .or_else(|| Some(context.incarnation.0.clone())),
        child_id: Some(
            provenance
                .as_ref()
                .map(|p| p.child_id.clone())
                .unwrap_or(reserved_child),
        ),
        cell_id: provenance.as_ref().map(|p| p.cell_id.clone()),
        execution: provenance.as_ref().and_then(|p| p.execution.clone()),
        substrate: provenance.as_ref().and_then(|p| p.substrate.clone()),
    };
    if persist_status(&scoped, &status).is_ok() {
        if let Some(digest) = receipt_digest {
            let _ = scoped.admission.finish(&fresh, Outcome::Receipt { digest });
        }
    }
}

fn uncertain_status(prepared: &PreparedRecord, reason: &str) -> ScopedStatus {
    ScopedStatus {
        id: prepared.id.clone(),
        owner: prepared.owner.clone(),
        phase: "Uncertain".into(),
        reason: Some(reason.into()),
        output: None,
        receipt_digest: None,
        cleanup_confirmed: false,
        parent_incarnation: prepared.decision["parent"]["incarnation"]
            .as_str()
            .map(str::to_owned),
        turn_id: prepared.decision["parent"]["turnId"]
            .as_str()
            .map(str::to_owned),
        parent_id: prepared.decision["parent"]["incarnation"]
            .as_str()
            .map(str::to_owned),
        child_id: None,
        cell_id: None,
        execution: None,
        substrate: None,
    }
}

fn model_completion(transcript: &str) -> std::result::Result<String, String> {
    let mut answer = None;
    for raw in transcript
        .lines()
        .filter_map(|line| line.strip_prefix("CELLN_HARNESS_EVENT "))
    {
        crate::tenancy_contract::canonical(raw.as_bytes())
            .map_err(|_| "invalid model completion event")?;
        let event: Value =
            serde_json::from_str(raw).map_err(|_| "invalid model completion event")?;
        if event["type"] == "completed" {
            let value = event["answer"].as_str().ok_or("missing model answer")?;
            if answer.is_some()
                || value.trim().is_empty()
                || value.len() > 65536
                || value.contains('\0')
            {
                return Err("invalid or duplicate model completion".into());
            }
            answer = Some(value.to_owned());
        }
    }
    answer.ok_or_else(|| "missing model completion".into())
}

#[allow(clippy::too_many_arguments)]
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
    let model_backed = broker.is_some();
    let launched = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        crate::dispatch::launch_scoped_declared(&request, &motes, &tools, &root, broker)
    }));
    let (mut phase, mut reason, mut output, execution, substrate, cell_id, cleanup_confirmed) =
        match launched {
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
                let execution = outcome
                    .execution
                    .as_ref()
                    .and_then(|value| serde_json::to_value(value).ok());
                let substrate = outcome
                    .substrate
                    .as_ref()
                    .and_then(|value| serde_json::to_value(value).ok());
                (
                    phase,
                    outcome.denial,
                    outcome
                        .output
                        .map(|v| String::from_utf8_lossy(&v).into_owned()),
                    execution,
                    substrate,
                    Some(outcome.cell_id),
                    true,
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
                (phase, Some(reason), None, None, None, None, true)
            }
            Err(_) => (
                "Uncertain",
                Some("execution worker panicked; native teardown is unconfirmed".into()),
                None,
                None,
                None,
                None,
                false,
            ),
        };
    if phase == "Succeeded" && model_backed {
        match model_completion(output.as_deref().unwrap_or("")) {
            Ok(answer) => output = Some(answer),
            Err(error) => {
                phase = "Failed";
                reason = Some(error);
                output = None;
            }
        }
    }
    if phase == "Succeeded"
        && (cell_id.as_deref().map_or(true, str::is_empty)
            || execution.is_none()
            || substrate.is_none())
    {
        phase = "Failed";
        reason = Some("native execution provenance is incomplete".into());
    }
    let receipt = cell_id
        .as_ref()
        .filter(|cell_id| !cell_id.is_empty())
        .and_then(|cell_id| {
            if execution.is_none() || substrate.is_none() {
                return None;
            }
            Some(json!({
                "apiVersion":"celln.scoped-native-receipt/v1", "operationId":id,
                "owner":scoped.admission.owner(), "cellId":cell_id,
                "execution":execution, "substrate":substrate, "phase":phase
            }))
        });
    let receipt_digest = receipt.as_ref().and_then(|receipt| {
        serde_json::to_vec(receipt)
            .ok()
            .map(|bytes| Hash::of(&bytes).0)
    });
    let status = ScopedStatus {
        id: id.clone(),
        owner: scoped.admission.owner().into(),
        phase: phase.into(),
        reason: reason.clone(),
        output: output.clone(),
        receipt_digest: receipt_digest.clone(),
        cleanup_confirmed,
        parent_incarnation: None,
        turn_id: None,
        parent_id: None,
        child_id: None,
        cell_id,
        execution,
        substrate,
    };
    super::update_execution(&executions, &id, |record| {
        record.phase = phase.into();
        record.reason = reason;
        record.output = output;
    });
    let persisted = persist_status(&scoped, &status).is_ok();
    if persisted && cleanup_confirmed {
        if let Some(receipt_digest) = receipt_digest {
            let _ = scoped.admission.finish(
                &fresh,
                Outcome::Receipt {
                    digest: receipt_digest,
                },
            );
        } else {
            let _ = scoped.admission.finish(&fresh, Outcome::Refused);
        }
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
    let enrolled_decision = match serde_json::to_vec(&prepared.decision)
        .ok()
        .and_then(|raw| crate::tenancy_contract::canonical(&raw).ok())
    {
        Some(value) => value,
        None => return reply(stream, 503, &json!({"error":"invalid durable enrollment"})),
    };
    let enrolled_request = match external_request(&prepared.operation, &prepared.decision) {
        Ok(value) => value,
        Err(_) => return reply(stream, 503, &json!({"error":"invalid durable enrollment"})),
    };
    let admission = match scoped.admission.access(
        &scoped.verifier,
        &permit,
        &decision,
        &receiver,
        crate::tenancy_admission::Enrollment {
            decision: &enrolled_decision,
            request: &enrolled_request,
            owner: &prepared.owner,
        },
    ) {
        Ok(v) => v,
        Err(AdmissionError::Credential("AUTH_CONTEXT_LOST")) => {
            if let Ok(Some(status)) = scoped.load_status(&request.id) {
                if status.cleanup_confirmed {
                    return reply(stream, 200, &status);
                }
            }
            return admission_reply(stream, AdmissionError::Credential("AUTH_CONTEXT_LOST"));
        }
        Err(e) => return admission_reply(stream, e),
    };
    if cleanup && admission.outcome() == Some(&Outcome::NeverStarted) {
        let status = never_started_status(&prepared);
        // This status carries no native receipt or provenance: the durable
        // admission outcome proves only that no Fresh handle was ever returned.
        if persist_status(scoped, &status).is_err() {
            return reply(
                stream,
                503,
                &json!({"error":"scoped result journal unavailable"}),
            );
        }
        return reply(stream, 200, &status);
    }
    // An authenticated, already-confirmed terminal result is immutable cleanup
    // evidence. Do not replace a pre-creation refusal with an absent-parent
    // stop error, nor manufacture a new teardown attempt after completion.
    if cleanup {
        if let Ok(Some(status)) = scoped.load_status(&request.id) {
            if status.id == request.id
                && status.owner == admission.owner()
                && status.cleanup_confirmed
            {
                return reply(stream, 200, &status);
            }
        }
    }
    if cleanup
        && prepared.decision["lifecycle"] == "enduring-initial"
        && admission.outcome() == Some(&Outcome::Refused)
        && admission.fenced()
    {
        let parent = Hash(
            prepared.decision["parent"]["incarnation"]
                .as_str()
                .unwrap_or_default()
                .into(),
        );
        let principal = format!(
            "sympozium:{}:{}",
            receiver.cluster_id, receiver.namespace_uid
        );
        if warden::parent_journal::fence_uncreated(
            &dispatcher.root.join("parent-journal"),
            &parent,
            &principal,
        )
        .unwrap_or(false)
        {
            let mut status = terminal_status(
                &request.id,
                admission.owner(),
                "Refused",
                Some("parent never created; incarnation permanently fenced".into()),
                None,
            );
            status.parent_incarnation = Some(parent.0);
            if persist_status(scoped, &status).is_err() {
                return reply(
                    stream,
                    503,
                    &json!({"error":"cleanup publication unconfirmed"}),
                );
            }
            return reply(stream, 200, &status);
        }
    }
    if admission.owner() != scoped.admission.owner() {
        let historical = prepared.decision["lifecycle"] != "one-shot"
            && prepared.decision["parent"]["incarnation"]
                .as_str()
                .map(|parent| {
                    let principal = format!(
                        "sympozium:{}:{}",
                        receiver.cluster_id, receiver.namespace_uid
                    );
                    warden::parent_journal::historical_teardown(
                        &dispatcher.root,
                        &Hash(parent.into()),
                        &principal,
                    )
                    .unwrap_or(false)
                })
                .unwrap_or(false);
        if let Ok(Some(mut status)) = scoped.load_status(&request.id) {
            if cleanup && historical {
                status.phase = "Cancelled".into();
                status.reason = Some("original native owner process teardown confirmed".into());
                status.cleanup_confirmed = true;
                let _ = persist_status(scoped, &status);
            } else if !status.cleanup_confirmed {
                status.phase = "Uncertain".into();
                status.reason = Some("original receiver owner context is unavailable".into());
                let _ = persist_status(scoped, &status);
            }
        }
    }
    if cleanup && admission.owner() == scoped.admission.owner() {
        let lifecycle = prepared.decision["lifecycle"].as_str().unwrap_or_default();
        if lifecycle == "enduring-initial" {
            let incarnation = Hash(
                prepared.decision["parent"]["incarnation"]
                    .as_str()
                    .unwrap_or_default()
                    .into(),
            );
            let principal = format!(
                "sympozium:{}:{}",
                receiver.cluster_id, receiver.namespace_uid
            );
            if let Some(context) = scoped
                .enduring
                .lock()
                .ok()
                .and_then(|owners| owners.get(&incarnation.0).cloned())
            {
                if let Ok(mut pending) = context.pending.lock() {
                    for turn in pending.values() {
                        turn.control.cancel();
                    }
                    pending.clear();
                }
                if let Ok(active) = context.active.lock() {
                    for control in active.values() {
                        control.cancel();
                    }
                }
            }
            let stopped = dispatcher.parents.stop(&principal, &incarnation);
            if let Ok(Some(mut status)) = scoped.load_status(&request.id) {
                status.phase = if stopped.is_ok() {
                    "Cancelled"
                } else {
                    "Uncertain"
                }
                .into();
                status.reason = Some(if stopped.is_ok() {
                    "retained parent and descendants stopped".into()
                } else {
                    "retained parent teardown unconfirmed".into()
                });
                status.cleanup_confirmed = stopped.is_ok();
                let _ = persist_status(scoped, &status);
            }
        } else if lifecycle == "enduring-turn" {
            let incarnation = Hash(
                prepared.decision["parent"]["incarnation"]
                    .as_str()
                    .unwrap_or_default()
                    .into(),
            );
            let turn = prepared.decision["parent"]["turnId"]
                .as_str()
                .unwrap_or_default()
                .to_owned();
            let principal = format!(
                "sympozium:{}:{}",
                receiver.cluster_id, receiver.namespace_uid
            );
            if let Some(context) = scoped
                .enduring
                .lock()
                .ok()
                .and_then(|owners| owners.get(&incarnation.0).cloned())
            {
                let pending = context
                    .pending
                    .lock()
                    .ok()
                    .and_then(|p| p.get(&turn).map(|pending| pending.control.clone()));
                if let Some(control) = pending.as_ref() {
                    control.cancel();
                }
                if let Some(control) = context
                    .active
                    .lock()
                    .ok()
                    .and_then(|active| active.get(&turn).cloned())
                {
                    control.cancel();
                }
                if pending.is_none() {
                    let child =
                        Hash::of(&serde_json::to_vec(&(&incarnation.0, &turn)).unwrap_or_default());
                    let identity = warden::parent_child_control::Identity {
                        parent: incarnation.clone(),
                        turn: turn.clone(),
                        child,
                    };
                    let _ = dispatcher.parents.cancel_child(&principal, &identity);
                }
            }
            if let Ok(Some(mut status)) = scoped.load_status(&request.id) {
                if !status.cleanup_confirmed {
                    status.phase = "Cancelling".into();
                    status.reason =
                        Some("exact child cancellation requested; teardown pending".into());
                    let _ = persist_status(scoped, &status);
                }
            }
        } else if let Some(entry) = dispatcher.executions.lock().unwrap().get_mut(&request.id) {
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
    if prepared.decision["lifecycle"] == "enduring-initial" {
        let incarnation = Hash(
            prepared.decision["parent"]["incarnation"]
                .as_str()
                .unwrap_or_default()
                .into(),
        );
        let principal = format!(
            "sympozium:{}:{}",
            receiver.cluster_id, receiver.namespace_uid
        );
        let owner_status = dispatcher.parents.status(&principal, &incarnation);
        if matches!(
            &owner_status,
            Ok(warden::parent_registry::Status::ContextLost)
                | Ok(warden::parent_registry::Status::TeardownUncertain)
        ) {
            if let Ok(Some(mut status)) = scoped.load_status(&request.id) {
                if !status.cleanup_confirmed {
                    status.phase = "Uncertain".into();
                    status.reason = Some("original retained parent owner is unavailable".into());
                    let _ = persist_status(scoped, &status);
                }
            }
        } else if matches!(&owner_status, Ok(warden::parent_registry::Status::Stopping)) {
            if let Ok(Some(mut status)) = scoped.load_status(&request.id) {
                if !status.cleanup_confirmed {
                    status.phase = "Cancelling".into();
                    status.reason = Some("retained parent teardown pending".into());
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
                parent_incarnation: prepared.decision["parent"]["incarnation"]
                    .as_str()
                    .map(str::to_owned),
                turn_id: prepared.decision["parent"]["turnId"]
                    .as_str()
                    .map(str::to_owned),
                parent_id: None,
                child_id: None,
                cell_id: None,
                execution: None,
                substrate: None,
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
    let enduring = decision["lifecycle"] != "one-shot";
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
    if enduring && provider == "none" {
        return Err("AUTH_PROTOCOL_UNSUPPORTED".into());
    }
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
        let value = native_json_config(prepared, &tools, enduring)?;
        let typed: pilot::json_harness::Config =
            serde_json::from_value(value.clone()).map_err(|_| "AUTH_PROTOCOL_UNSUPPORTED")?;
        if enduring {
            pilot::turn_worker::Template::new(typed.clone())
                .map_err(|_| "AUTH_PROTOCOL_UNSUPPORTED")?;
        } else {
            pilot::json_harness::validate(&typed).map_err(|_| "AUTH_PROTOCOL_UNSUPPORTED")?;
        }
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
            // The gateway owns the provider request; no host-pinned fields.
            parameters: Default::default(),
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
    // The owned broker is the sole transport authority. Never turn its logical
    // guest endpoint into a legacy standing egress grant in the native request.
    let route_egress: Vec<String> = vec![];
    let native: ExecutionRequest = serde_json::from_value(json!({
        "apiVersion":"celln.dev/v1alpha1","id":if enduring {format!("scoped-worker-{}", &decision["parent"]["incarnation"].as_str().ok_or("AUTH_PARENT_TURN_MISMATCH")?[7..])} else {prepared.id.clone()},
        "workload":{"id":if enduring {format!("scoped-worker-{}", &decision["parent"]["incarnation"].as_str().ok_or("AUTH_PARENT_TURN_MISMATCH")?[7..])} else {prepared.id.clone()},"caller":format!("sympozium:{}:{}",receiver.cluster_id,receiver.namespace_uid)},
        "mote":{"hash":profile["mote"]["hash"]},
        "tools":[{"alias":profile["entryPoint"],"hash":profile["executable"]["hash"],"closure":{"hash":profile["closure"]["hash"]}}],
        "invocation":{"alias":profile["entryPoint"],"args":if enduring {json!([])} else {json!([config.0.clone()])}},
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
    let required_lifecycle = if decision["lifecycle"] == "one-shot" {
        "disposable-one-shot"
    } else {
        "enduring"
    };
    if profile["contractVersion"] != pilot::json_harness::CONTRACT
        || profile["platform"] != "linux/amd64"
        || profile["lane"] != "agent"
        || !profile["lifecycles"]
            .as_array()
            .is_some_and(|v| v.iter().any(|item| item == required_lifecycle))
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
    {
        bail!("unsupported scoped decision")
    }
    match (
        final_decision["lifecycle"].as_str(),
        final_decision["operation"].as_str(),
    ) {
        (Some("one-shot"), Some("execution.start"))
            if final_decision["parent"].is_null() && execution.get("turnUid").is_none() => {}
        (Some("enduring-initial"), Some("execution.start"))
            if final_decision["parent"]["incarnation"].as_str().is_some()
                && final_decision["parent"]["turnId"].is_null()
                && execution.get("turnUid").is_none() => {}
        (Some("enduring-turn"), Some("execution.turn"))
            if final_decision["parent"]["incarnation"].as_str().is_some()
                && final_decision["parent"]["turnId"].as_str().is_some()
                && execution["turnUid"] == final_decision["parent"]["turnId"] => {}
        _ => bail!("unsupported scoped lifecycle operation"),
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

fn uncertain_parent_refusal(
    scoped: &ScopedState,
    fresh: &Fresh,
    prepared: &PreparedRecord,
    _reason: String,
) -> ScopedStatus {
    // Claim/registry errors can refer to a pre-existing or partially published
    // owner. Refusal alone never proves that owner's VM has been destroyed.
    let status = uncertain_status(
        prepared,
        "parent claim refused; original ownership and teardown unconfirmed",
    );
    let _ = scoped.admission.finish(fresh, Outcome::Refused);
    let _ = persist_status(scoped, &status);
    status
}

fn prepared_refusal(
    scoped: &ScopedState,
    fresh: &Fresh,
    prepared: &PreparedRecord,
    reason: String,
) -> ScopedStatus {
    let mut status = terminal_status(
        &prepared.id,
        scoped.admission.owner(),
        "Refused",
        Some(reason),
        None,
    );
    status.parent_incarnation = prepared.decision["parent"]["incarnation"]
        .as_str()
        .map(str::to_owned);
    status.turn_id = prepared.decision["parent"]["turnId"]
        .as_str()
        .map(str::to_owned);
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
        parent_incarnation: None,
        turn_id: None,
        parent_id: None,
        child_id: None,
        cell_id: None,
        execution: None,
        substrate: None,
    }
}

fn never_started_status(prepared: &PreparedRecord) -> ScopedStatus {
    let mut status = terminal_status(
        &prepared.id,
        &prepared.owner,
        "Cancelled",
        Some("never started; permanently fenced".into()),
        None,
    );
    status.parent_incarnation = prepared.decision["parent"]["incarnation"]
        .as_str()
        .map(str::to_owned);
    status.turn_id = prepared.decision["parent"]["turnId"]
        .as_str()
        .map(str::to_owned);
    status
}

fn validate_parent_template(template: &ParentTemplate) -> Result<(), String> {
    let request = &template.request;
    if template.api_version != "celln.scoped-parent-template/v1"
        || request.id != "$parent"
        || request.workload.id != "$parent"
        || request.workload.caller != "$principal"
        || template.reserved_memory_bytes == 0
        || request.harness.is_some()
        || request.forge.is_some()
        || !request.inputs.is_empty()
        || !request.capabilities.egress.is_empty()
        || request.capabilities.workspace != celln_spec::WorkspaceAccess::None
        || request.execution.lane != celln_spec::RequestedLane::Agent
        || !request.execution.require_hardware_isolation
        || request.tools.len() != 1
        || request.tools[0].closure.is_none()
        || !request
            .invocation
            .as_ref()
            .is_some_and(|i| i.args.is_empty())
        || !request.problems().is_empty()
    {
        return Err("invalid operator scoped parent request template".into());
    }
    let floor = request
        .capabilities
        .memory_bytes
        .checked_mul(2)
        .ok_or("operator parent reservation overflow")?;
    if template.reserved_memory_bytes <= floor {
        return Err("operator parent reservation omits retained substrate overhead".into());
    }
    Ok(())
}

fn operator_dir(path: &Path) -> Result<()> {
    match fs::create_dir(path) {
        Ok(()) => File::open(path.parent().unwrap())?.sync_all()?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o022 != 0
    {
        bail!("operator parent authority directory is not protected")
    }
    Ok(())
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

fn blake(value: &str) -> bool {
    value.strip_prefix("blake3:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
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
#[path = "dispatch_scoped_http_tests.rs"]
pub(super) mod http_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scoped_model_result_requires_one_unambiguous_completion() {
        let valid = "CELLN_HARNESS_EVENT {\"type\":\"completed\",\"answer\":\"CELLN\"}\n";
        assert_eq!(model_completion(valid).unwrap(), "CELLN");
        assert!(model_completion(&(valid.to_owned() + valid)).is_err());
        assert!(model_completion("CELLN_HARNESS_EVENT {\"type\":\"completed\",\"answer\":\"first\",\"answer\":\"second\"}\n").is_err());
        assert!(model_completion("CELLN_HARNESS_EVENT {\"type\":\"model\"}\n").is_err());
    }

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
    fn preparation_accepts_only_correlated_enduring_root_and_turn_shapes() {
        let (mut operation, mut decision) = fixture();
        let scope = r#"["celln.scoped-parent/v1","cluster","namespace-uid"]"#;
        let incarnation = warden::parent_permit::run_incarnation(scope, "run-uid")
            .unwrap()
            .0;
        decision["lifecycle"] = json!("enduring-initial");
        decision["parent"] = json!({"incarnation":incarnation,"turnId":null});
        decision["budget"]["maxTurns"] = json!(2);
        decision["budget"]["parentDeadlineUnix"] = json!(2_000_000_100i64);
        decision["requestDigest"] = json!(crate::tenancy_contract::digest(
            &external_request(&operation, &decision).unwrap()
        ));
        operation["resolution"]["decision"] = decision.clone();
        validate_prepared(&operation, &decision).unwrap();

        decision["lifecycle"] = json!("enduring-turn");
        decision["operation"] = json!("execution.turn");
        decision["parent"]["turnId"] = json!("turn-uid");
        operation["resolution"]["execution"]["turnUid"] = json!("turn-uid");
        decision["requestDigest"] = json!(crate::tenancy_contract::digest(
            &external_request(&operation, &decision).unwrap()
        ));
        operation["resolution"]["decision"] = decision.clone();
        validate_prepared(&operation, &decision).unwrap();
        operation["resolution"]["execution"]["turnUid"] = json!("other");
        assert!(validate_prepared(&operation, &decision).is_err());
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
    fn scoped_control_uses_remaining_absolute_turn_deadline() {
        let (operation, mut decision) = fixture();
        decision["budget"]["turnDeadlineUnix"] = json!(now() + 2);
        let prepared = PreparedRecord {
            version: 1,
            id: operation_id(&operation, &decision).unwrap(),
            owner: format!("sha256:{}", "a".repeat(64)),
            operation,
            decision,
        };
        let control = operation_control(&prepared).unwrap();
        assert!(control.remaining() <= Duration::from_secs(2));
        assert!(control.remaining() < Duration::from_secs(30));
    }

    #[test]
    fn never_started_cleanup_keeps_enrollment_owner_without_native_provenance() {
        let (operation, decision) = fixture();
        let prepared = PreparedRecord {
            version: 1,
            id: operation_id(&operation, &decision).unwrap(),
            owner: format!("sha256:{}", "a".repeat(64)),
            operation,
            decision,
        };
        let status = never_started_status(&prepared);
        assert_eq!(status.owner, prepared.owner);
        assert_eq!(status.phase, "Cancelled");
        assert_eq!(
            status.reason.as_deref(),
            Some("never started; permanently fenced")
        );
        assert!(status.cleanup_confirmed);
        assert!(status.receipt_digest.is_none());
        assert!(status.parent_id.is_none());
        assert!(status.child_id.is_none());
        assert!(status.cell_id.is_none());
        assert!(status.execution.is_none());
        assert!(status.substrate.is_none());
    }

    #[test]
    fn both_guest_adapters_use_only_the_mediated_alias() {
        let (mut operation, mut decision) = fixture();
        operation["resolution"]["execution"]["profileSpec"]["json"] =
            json!({"maxTurns":8,"maxCalls":2,"requireToolCall":true});
        operation["resolution"]["execution"]["payload"] = json!("task");
        decision["route"]["endpointOrigin"] = json!("https://private-provider.example/path");
        decision["budget"]["turnCap"]["requests"] = json!(2);
        let prepared = PreparedRecord {
            version: 1,
            id: String::new(),
            owner: String::new(),
            operation,
            decision,
        };
        for enduring in [false, true] {
            let config = native_json_config(&prepared, &[], enduring).unwrap();
            assert_eq!(config["url"], MODEL_ALIAS);
            assert!(!config.to_string().contains("private-provider"));
            assert_eq!(config["require_tool_call"], true);
            assert_eq!(config["max_turns"], 2);
            assert_eq!(config["task"], if enduring { "" } else { "task" });
        }
    }

    #[test]
    fn parent_scope_and_incarnation_match_the_cross_language_tuple() {
        let (mut operation, mut decision) = fixture();
        decision["lifecycle"] = json!("enduring-initial");
        decision["parent"] = json!({"incarnation":Hash::of(b"placeholder").0,"turnId":null});
        operation["resolution"]["decision"] = decision.clone();
        let prepared = PreparedRecord {
            version: 1,
            id: operation_id(&operation, &decision).unwrap(),
            owner: format!("sha256:{}", "a".repeat(64)),
            operation,
            decision,
        };
        let scope = parent_scope(&prepared).unwrap();
        assert_eq!(
            scope,
            r#"["celln.scoped-parent/v1","cluster","namespace-uid"]"#
        );
        let actual = warden::parent_permit::run_incarnation(&scope, "run-uid").unwrap();
        let expected = Hash::of(
            &serde_json::to_vec(&("celln.parent-run-incarnation/v1", scope.as_str(), "run-uid"))
                .unwrap(),
        );
        assert_eq!(actual, expected);
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
                gateway_ca: None,
                parent_request_file: None
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
                gateway_ca: None,
                parent_request_file: None
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
            parent_template: None,
            enduring: Mutex::new(HashMap::new()),
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
