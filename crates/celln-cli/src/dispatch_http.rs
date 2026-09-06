//! Authenticated local dispatcher for real Celln execution requests.
//!
//! This service is intentionally a Celln process, not a Kubernetes Job
//! wrapper. `POST /v1/executions` admits a `celln.dev/v1alpha1`
//! `ExecutionRequest`, resolves or forges the declared program, runs it in a
//! real sealed cell, and returns a validated `ExecutionReceipt`.

use crate::NodeProbeArgs;
use anyhow::{bail, Context, Result};
use celln_spec::{
    ExecutionOutput, ExecutionPhase, ExecutionReceipt, ExecutionRequest, ResolvedExecution,
};
use celln_store::Store;
use serde::Serialize;
use std::collections::{BTreeSet, HashMap};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Hard caps on the hand-rolled HTTP parsing below. Neither the request line
/// nor any single header nor the header block as a whole is length-checked
/// by `BufReader::read_line` on its own — an unbounded line keeps allocating
/// until the peer stops sending, which is a memory/CPU DoS vector for a
/// network-facing service authenticated by a single bearer token.
pub(crate) const MAX_REQUEST_LINE: usize = 8 * 1024;
pub(crate) const MAX_HEADER_LINE: usize = 8 * 1024;
pub(crate) const MAX_HEADER_COUNT: usize = 64;

/// How long a finished execution record is kept before it is evicted on the
/// next insert. The registry is otherwise unbounded — every unique id a
/// caller submits stays in memory for the life of the process.
const RECORD_TTL: Duration = Duration::from_secs(3600);

/// Read one line with a hard byte cap, so a peer that never sends `\n`
/// cannot grow the buffer without bound. Shared with `router.rs`, which
/// parses the same hand-rolled HTTP framing.
pub(crate) fn read_bounded_line(reader: &mut impl BufRead, cap: usize) -> Result<String> {
    let mut line = String::new();
    loop {
        let mut byte = [0u8; 1];
        match reader.read(&mut byte)? {
            0 => break,
            1 => {
                line.push(byte[0] as char);
                if byte[0] == b'\n' {
                    break;
                }
                if line.len() >= cap {
                    bail!("line exceeds {cap} bytes");
                }
            }
            _ => unreachable!(),
        }
    }
    Ok(line)
}

/// Read and discard headers, enforcing a cap on both line length and count.
/// Returns the parsed `Content-Length`, and the raw `Authorization` header
/// value if the caller wants it.
fn read_headers(reader: &mut impl BufRead) -> Result<(usize, Option<String>)> {
    let mut length = 0usize;
    let mut authorization = None;
    let mut count = 0usize;
    loop {
        let header = read_bounded_line(reader, MAX_HEADER_LINE)?;
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        count += 1;
        if count > MAX_HEADER_COUNT {
            bail!("too many headers (max {MAX_HEADER_COUNT})");
        }
        if let Some(value) = header.strip_prefix("Authorization: Bearer ") {
            authorization = Some(value.to_owned());
        }
        if let Some(value) = header.strip_prefix("Content-Length: ") {
            length = value.parse().context("invalid Content-Length")?;
        }
    }
    Ok((length, authorization))
}

/// A registry entry tagged with its insertion time, so a background sweep
/// can evict entries older than [`RECORD_TTL`]. The registry is otherwise
/// unbounded for the life of the process.
struct Entry<T> {
    at: Instant,
    value: T,
    control: Option<celln_control::Control>,
}

impl<T> Entry<T> {
    fn new(value: T) -> Self {
        Entry {
            at: Instant::now(),
            value,
            control: None,
        }
    }
}

fn evict_expired(registry: &mut HashMap<String, Entry<ExecutionRecord>>) {
    let now = Instant::now();
    registry.retain(|_, entry| {
        execution_is_active(&entry.value) || now.duration_since(entry.at) < RECORD_TTL
    });
}

/// One `celln.dev/v1alpha1` execution in flight or finished on this node.
/// This is the dispatcher's own bookkeeping, not the wire receipt — it has
/// room for a human-readable reason a receipt does not.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionRecord {
    pub request_id: String,
    pub phase: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The bounded text output, as a convenience for a caller that just
    /// wants the result — the receipt itself only ever carries a content
    /// hash, deliberately: it is an immutable wire contract, not a place to
    /// smuggle in a human-readable field. This is that field, kept in the
    /// dispatcher's own wrapper instead.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt: Option<ExecutionReceipt>,
}

type Executions = Arc<Mutex<HashMap<String, Entry<ExecutionRecord>>>>;

struct State {
    token: String,
    egress_policy: EgressPolicy,
    root: PathBuf,
    probe: NodeProbeArgs,
    executions: Executions,
}

#[derive(Debug)]
struct EgressPolicy {
    allow_hosts: BTreeSet<String>,
}

impl EgressPolicy {
    fn new(allow_hosts: &[String]) -> Result<Self> {
        let mut normalized = BTreeSet::new();
        for host in allow_hosts {
            let host = host.to_ascii_lowercase();
            if host.is_empty()
                || !host
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
            {
                bail!(
                    "invalid --allow-egress-host {host:?}: expected one exact hostname without a scheme, port, path, or wildcard"
                );
            }
            normalized.insert(host);
        }
        Ok(Self {
            allow_hosts: normalized,
        })
    }

    fn check(&self, request: &ExecutionRequest) -> Result<()> {
        for destination in &request.capabilities.egress {
            // ExecutionRequest::problems() validates the HTTPS-only shape
            // before this host policy runs. Keep this check fail-closed too,
            // so it remains safe if called independently later.
            let host = destination
                .strip_prefix("https://")
                .filter(|host| !host.is_empty())
                .context("egress destination is not a named HTTPS host")?;
            if !self.allow_hosts.contains(&host.to_ascii_lowercase()) {
                bail!(
                    "egress destination {destination:?} is outside this dispatcher's host allowlist"
                );
            }
        }
        Ok(())
    }
}

/// Parse and validate the exact address that will be passed to `bind`.
///
/// Accepting a hostname here would require DNS resolution. Resolving once for
/// policy and again inside `TcpListener::bind` creates a check/use gap in which
/// the two answers can differ, so the dispatcher deliberately requires a
/// numeric IP socket address at this security boundary.
fn validate_listen(listen: &str, unsafe_non_loopback: bool) -> Result<(SocketAddr, bool)> {
    let address: SocketAddr = listen.parse().with_context(|| {
        format!(
            "invalid dispatcher listen address {listen:?}; use a numeric IP socket address such as 127.0.0.1:8787 or [::1]:8787"
        )
    })?;
    let non_loopback = !address.ip().is_loopback();
    if non_loopback && !unsafe_non_loopback {
        bail!(
            "refusing non-loopback dispatcher bind {listen:?}; use --unsafe-non-loopback only behind a TLS-terminating reverse proxy"
        );
    }
    Ok((address, non_loopback))
}

fn execution_is_active(record: &ExecutionRecord) -> bool {
    !matches!(
        record.phase.as_str(),
        "Succeeded" | "Failed" | "Refused" | "Cancelled"
    )
}

pub fn serve(
    listen: &str,
    unsafe_non_loopback: bool,
    token_file: &Path,
    allow_egress_hosts: &[String],
    root: PathBuf,
    probe: &NodeProbeArgs,
) -> Result<u8> {
    let (listen_address, non_loopback) = validate_listen(listen, unsafe_non_loopback)?;
    let egress_policy = EgressPolicy::new(allow_egress_hosts)?;
    let token = std::fs::read_to_string(token_file)
        .with_context(|| format!("reading dispatcher token {}", token_file.display()))?
        .trim()
        .to_owned();
    if token.len() < 24 {
        bail!("dispatcher token must contain at least 24 non-whitespace bytes");
    }
    let listener = TcpListener::bind(listen_address)
        .with_context(|| format!("binding dispatcher {listen_address}"))?;
    let state = Arc::new(State {
        token,
        egress_policy,
        root,
        probe: probe.clone(),
        executions: Arc::new(Mutex::new(HashMap::new())),
    });
    if non_loopback {
        eprintln!(
            "WARNING: dispatcher is exposed on a non-loopback address and provides no TLS; a TLS-terminating reverse proxy is required"
        );
    }
    eprintln!("celln dispatcher listening on {listen_address}");
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let state = Arc::clone(&state);
                thread::spawn(move || {
                    if let Err(error) = handle(stream, &state) {
                        eprintln!("dispatcher request failed: {error:#}");
                    }
                });
            }
            Err(error) => eprintln!("dispatcher accept failed: {error}"),
        }
    }
    Ok(crate::exit::OK)
}

fn handle(mut stream: TcpStream, state: &State) -> Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let request_line = read_bounded_line(&mut reader, MAX_REQUEST_LINE)?;
    let Some((method, path)) = request_line.trim_end().split_once(' ') else {
        return reply(
            &mut stream,
            400,
            &serde_json::json!({"error":"malformed request line"}),
        );
    };
    let path = path
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_owned();
    let method = method.to_owned();
    let (length, authorization) = read_headers(&mut reader)?;
    let authorized = authorization
        .is_some_and(|value| constant_time_eq(value.as_bytes(), state.token.as_bytes()));
    let is_public_health_check = method == "GET" && path == "/v1/health";
    if !authorized && !is_public_health_check {
        return reply(
            &mut stream,
            401,
            &serde_json::json!({"error":"unauthorized"}),
        );
    }
    match (method.as_str(), path.as_str()) {
        ("GET", "/v1/health") => {
            let has_kvm = Path::new("/dev/kvm").exists();
            let motes = Path::new("/var/lib/celln/motes");
            let tools = Path::new("/var/lib/celln/tools");
            reply(
                &mut stream,
                200,
                &serde_json::json!({
                    "ok": has_kvm,
                    "kvm": has_kvm,
                    "mote_store": motes.exists() && motes.read_dir().map(|mut d| d.next().is_some()).unwrap_or(false),
                    "tool_store": tools.exists() && tools.read_dir().map(|mut d| d.next().is_some()).unwrap_or(false),
                }),
            )
        }
        ("POST", "/v1/executions") => {
            if length > 64 * 1024 {
                return reply(
                    &mut stream,
                    413,
                    &serde_json::json!({"error":"request body exceeds 64 KiB"}),
                );
            }
            let mut body = vec![0; length];
            reader.read_exact(&mut body)?;
            let request: ExecutionRequest =
                match serde_json::from_slice(&body).context("parsing execution request") {
                    Ok(request) => request,
                    Err(error) => {
                        return reply(
                            &mut stream,
                            400,
                            &serde_json::json!({"error": error.to_string()}),
                        )
                    }
                };
            let problems = request.problems();
            if !problems.is_empty() {
                return reply(
                    &mut stream,
                    400,
                    &serde_json::json!({"error": "invalid execution request", "problems": problems}),
                );
            }
            if let Err(reason) = crate::dispatch::check_supported_authority(&request) {
                return reply(
                    &mut stream,
                    422,
                    &serde_json::json!({"error": "request refused", "reason": "unsupported", "detail": reason}),
                );
            }
            let control = celln_control::Control::new(Duration::from_millis(
                request.capabilities.timeout_ms,
            ))?;
            if let Err(error) = state.egress_policy.check(&request) {
                return reply(
                    &mut stream,
                    403,
                    &serde_json::json!({
                        "error": "egress policy refused execution request",
                        "reason": error.to_string(),
                    }),
                );
            }
            let record = ExecutionRecord {
                request_id: request.id.clone(),
                phase: "Admitting".into(),
                reason: None,
                output: None,
                receipt: None,
            };
            let mut registry = state
                .executions
                .lock()
                .expect("dispatcher registry not poisoned");
            if let Some(existing) = registry.get(&request.id) {
                return reply(&mut stream, 202, &existing.value);
            }
            evict_expired(&mut registry);

            // Reserve capacity while holding the same lock used to insert the
            // execution. Without this atomic check, a burst can admit every
            // request before any worker has created its cell. Registry entries
            // cover pre-cell work such as forging too, so accepted work cannot
            // overcommit the node while waiting to launch.
            let reserved_cells: u32 = registry
                .values()
                .filter(|entry| execution_is_active(&entry.value))
                .count()
                .try_into()
                .unwrap_or(u32::MAX);
            let other_live_cells =
                crate::cells::live_count_excluding_pid(&state.root, Some(std::process::id()));
            let live_cells = reserved_cells.saturating_add(other_live_cells);
            let node = crate::node::NodeEligibility::from_probe(&state.probe, live_cells);
            if let crate::node::Admission::Refused { reason, .. } =
                crate::node::admit(&request, &node)
            {
                let status = if reason == crate::node::RefusalCode::AtCapacity {
                    503
                } else {
                    422
                };
                return reply(
                    &mut stream,
                    status,
                    &serde_json::json!({
                        "error": if status == 503 { "node at capacity" } else { "request refused" },
                        "reason": reason,
                    }),
                );
            }
            let mut entry = Entry::new(record.clone());
            entry.control = Some(control.clone());
            registry.insert(request.id.clone(), entry);
            drop(registry);
            let worker_executions = Arc::clone(&state.executions);
            let probe = state.probe.clone();
            let root = state.root.clone();
            thread::spawn(move || {
                control.scope(|| {
                    let id = request.id.clone();
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        run_execution(request, Arc::clone(&worker_executions), probe, root)
                    }));
                    if result.is_err() {
                        fail_execution(
                            &worker_executions,
                            &id,
                            "execution worker panicked during cleanup".into(),
                        );
                    }
                })
            });
            reply(&mut stream, 202, &record)
        }
        ("POST", path) if path.starts_with("/v1/executions/") && path.ends_with("/cancel") => {
            let id = &path["/v1/executions/".len()..path.len() - "/cancel".len()];
            let mut registry = state
                .executions
                .lock()
                .expect("dispatcher registry not poisoned");
            let Some(entry) = registry.get_mut(id) else {
                return reply(
                    &mut stream,
                    404,
                    &serde_json::json!({"error": "unknown execution"}),
                );
            };
            if execution_is_active(&entry.value) {
                if let Some(control) = &entry.control {
                    control.cancel();
                }
                entry.value.phase = "Cancelling".into();
                entry.value.reason = Some("cancellation requested; cleanup pending".into());
                // Reservation remains live until the worker has unwound all
                // subprocesses, VM handles and preparation state.
                reply(&mut stream, 202, &entry.value)
            } else {
                reply(&mut stream, 200, &entry.value)
            }
        }
        ("GET", path) if path.starts_with("/v1/executions/") => {
            let id = path.trim_start_matches("/v1/executions/");
            let registry = state
                .executions
                .lock()
                .expect("dispatcher registry not poisoned");
            match registry.get(id) {
                Some(entry) => reply(&mut stream, 200, &entry.value),
                None => reply(
                    &mut stream,
                    404,
                    &serde_json::json!({"error":"unknown execution"}),
                ),
            }
        }
        _ => reply(&mut stream, 404, &serde_json::json!({"error":"not found"})),
    }
}

fn update_execution(executions: &Executions, id: &str, f: impl FnOnce(&mut ExecutionRecord)) {
    if let Some(entry) = executions
        .lock()
        .expect("dispatcher registry not poisoned")
        .get_mut(id)
    {
        f(&mut entry.value);
        if let Some(reason) = entry.control.as_ref().and_then(|c| c.reason()) {
            if !execution_is_active(&entry.value) {
                let phase = match reason {
                    celln_control::Stopped::Cancelled => ExecutionPhase::Cancelled,
                    celln_control::Stopped::Deadline => ExecutionPhase::Failed,
                };
                entry.value.phase = format!("{phase:?}");
                entry.value.reason = Some(reason.to_string());
                if let Some(receipt) = &mut entry.value.receipt {
                    receipt.phase = phase;
                }
            } else if reason == celln_control::Stopped::Cancelled {
                entry.value.phase = "Cancelling".into();
            }
        }
        if !execution_is_active(&entry.value) {
            entry.at = Instant::now();
        }
    }
}

fn fail_execution(executions: &Executions, id: &str, reason: String) {
    update_execution(executions, id, |record| {
        record.phase = "Failed".into();
        record.reason = Some(reason);
    });
}

/// Admit, then resolve-or-forge and launch, a `celln.dev/v1alpha1` execution
/// request, then record the terminal [`ExecutionReceipt`]. Either way the
/// program that runs is exact bytes with a real hash by the time it's
/// sealed — for a declared request, `resolve_bundle` proved those bytes
/// match what was declared; for a forge request, `dispatch::forge` just
/// wrote and admitted them. Neither path treats a task string or a name as
/// authority.
fn run_execution(
    request: ExecutionRequest,
    executions: Executions,
    probe: NodeProbeArgs,
    root: PathBuf,
) {
    if let Err(error) = celln_control::check() {
        return fail_execution(&executions, &request.id, error.to_string());
    }
    // Defense in depth: direct callers must refuse before model invocations,
    // store access or runtime preparation, not only at the HTTP boundary.
    if let Err(reason) = crate::dispatch::check_supported_authority(&request) {
        update_execution(&executions, &request.id, |record| {
            record.phase = "Refused".into();
            record.reason = Some(reason);
        });
        return;
    }
    let started_at = crate::dispatch::now_rfc3339();
    if let Err(error) = crate::dispatch::inputs::resolve(&request, &root) {
        return fail_execution(&executions, &request.id, error);
    }
    let assay_root = root.join("assay");

    // Declared launch consumes operator-pinned substrate bytes. Forge remains
    // a separately identified host-prepared path, with no declared mote claim.
    let (mote, program_hash, outcome) = if let Some(forge_request) = &request.forge {
        update_execution(&executions, &request.id, |record| {
            record.phase = "Forging".into()
        });
        let forged = match crate::dispatch::forge(
            forge_request,
            &assay_root,
            request.capabilities.timeout_ms.div_ceil(1000),
        ) {
            Ok(forged) => forged,
            Err(error) => return fail_execution(&executions, &request.id, error),
        };
        let runtime_root = match crate::agent::runtime_root() {
            Ok(path) => path,
            Err(error) => return fail_execution(&executions, &request.id, error.to_string()),
        };
        update_execution(&executions, &request.id, |record| {
            record.phase = "Running".into()
        });
        let outcome = match crate::dispatch::launch(
            &request,
            crate::agent::ALIAS,
            &[],
            &forged.bytes,
            &runtime_root,
            &assay_root,
            &root,
        ) {
            Ok(outcome) => outcome,
            Err(error) => return fail_execution(&executions, &request.id, error),
        };
        (None, forged.hash, outcome)
    } else {
        update_execution(&executions, &request.id, |record| {
            record.phase = "Resolving".into()
        });
        let (outcome, resolved) = match crate::dispatch::launch_declared(
            &request,
            &probe.mote_store,
            &probe.tool_store,
            &root,
        ) {
            Ok(result) => result,
            Err(error) => return fail_execution(&executions, &request.id, error),
        };
        (Some(resolved.bundle_hash), resolved.program_hash, outcome)
    };

    let output = outcome.output.as_deref().filter(|bytes| !bytes.is_empty());
    let (phase, stored_output, reason) = collect_result(&outcome, &root.join("outputs"));
    let receipt = ExecutionReceipt {
        api_version: "celln.dev/v1alpha1".into(),
        request_id: request.id.clone(),
        phase,
        node: probe.node_name.clone(),
        cell_id: outcome.cell_id,
        resolved: ResolvedExecution {
            mote,
            tools: vec![program_hash],
            inputs: outcome.input_hashes,
        },
        output: stored_output,
        started_at,
        completed_at: crate::dispatch::now_rfc3339(),
    };
    let output_text = output.map(|bytes| String::from_utf8_lossy(bytes).into_owned());
    update_execution(&executions, &request.id, |record| {
        record.phase = format!("{:?}", receipt.phase);
        record.reason = reason;
        record.output = output_text;
        record.receipt = Some(receipt.clone());
    });
}

/// Guest success and output persistence are separate facts. A silent exit 0
/// succeeds with no output object; nonzero exits keep their bounded output.
fn collect_result(
    outcome: &crate::dispatch::LaunchOutcome,
    output_root: &Path,
) -> (ExecutionPhase, Option<ExecutionOutput>, Option<String>) {
    let mut reason = outcome.denial.clone();
    let stored = outcome
        .output
        .as_deref()
        .filter(|bytes| !bytes.is_empty())
        .map(|bytes| {
            Store::open(output_root)
                .and_then(|store| store.put(bytes))
                .map(|hash| ExecutionOutput {
                    hash: hash.0,
                    media_type: "application/octet-stream".into(),
                    bytes: bytes.len() as u64,
                })
        })
        .transpose();
    match stored {
        Ok(output) => (
            if outcome.succeeded() {
                ExecutionPhase::Succeeded
            } else {
                ExecutionPhase::Failed
            },
            output,
            reason,
        ),
        Err(_) => {
            // Keep local paths and filesystem diagnostics out of the wire.
            let prefix = reason.take().map(|s| format!("{s}; ")).unwrap_or_default();
            (
                ExecutionPhase::Failed,
                None,
                Some(format!("{prefix}output persistence failed")),
            )
        }
    }
}

fn reply(stream: &mut TcpStream, status: u16, body: &impl Serialize) -> Result<()> {
    let body = serde_json::to_vec(body)?;
    write!(stream, "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len())?;
    stream.write_all(&body)?;
    Ok(())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn lifecycle_state(root: &Path) -> State {
        State {
            token: "test-token-at-least-24-bytes".into(),
            egress_policy: EgressPolicy::new(&[]).unwrap(),
            root: root.into(),
            probe: NodeProbeArgs {
                node_name: "test".into(),
                mote_store: root.join("motes"),
                tool_store: root.join("tools"),
                max_cells: 1,
                memory_bytes: 268435456,
                egress_slots: 0,
            },
            executions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn cancel_http(state: &State, id: &str, token: &str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let (server, _) = listener.accept().unwrap();
        write!(client, "POST /v1/executions/{id}/cancel HTTP/1.1\r\nAuthorization: Bearer {token}\r\nContent-Length: 0\r\n\r\n").unwrap();
        handle(server, state).unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        response
    }

    #[test]
    fn cancellation_is_authenticated_idempotent_and_reserves_until_cleanup() {
        let work = tempfile::tempdir().unwrap();
        let state = lifecycle_state(work.path());
        let control = celln_control::Control::new(Duration::from_secs(60)).unwrap();
        let mut entry = Entry::new(empty_record("running"));
        entry.control = Some(control.clone());
        state
            .executions
            .lock()
            .unwrap()
            .insert("running".into(), entry);
        assert!(cancel_http(&state, "running", "wrong").starts_with("HTTP/1.1 401"));
        assert!(control.reason().is_none());
        for _ in 0..2 {
            let response = cancel_http(&state, "running", &state.token);
            assert!(response.starts_with("HTTP/1.1 202"));
            assert!(response.contains("Cancelling"));
            assert!(execution_is_active(
                &state.executions.lock().unwrap()["running"].value
            ));
        }
        assert_eq!(control.reason(), Some(celln_control::Stopped::Cancelled));
        // Worker cleanup, not the HTTP request, publishes the terminal state.
        fail_execution(&state.executions, "running", "worker unwound".into());
        assert!(!execution_is_active(
            &state.executions.lock().unwrap()["running"].value
        ));
        let response = cancel_http(&state, "running", &state.token);
        assert!(response.starts_with("HTTP/1.1 200"));
        assert!(response.contains("Cancelled"));
        assert!(cancel_http(&state, "absent", &state.token).starts_with("HTTP/1.1 404"));
    }

    #[test]
    fn deadline_wins_a_terminal_success_race() {
        let work = tempfile::tempdir().unwrap();
        let state = lifecycle_state(work.path());
        let mut entry = Entry::new(empty_record("expired"));
        entry.control = Some(celln_control::Control::new(Duration::ZERO).unwrap());
        state
            .executions
            .lock()
            .unwrap()
            .insert("expired".into(), entry);
        update_execution(&state.executions, "expired", |record| {
            record.phase = "Succeeded".into()
        });
        let registry = state.executions.lock().unwrap();
        let record = &registry["expired"].value;
        assert_eq!(record.phase, "Failed");
        assert_eq!(
            record.reason.as_deref(),
            Some("execution deadline exceeded")
        );
    }

    #[test]
    fn unsupported_forge_authority_is_refused_without_side_effects() {
        let mut request = request_with_egress(&[]);
        request.capabilities.workspace = celln_spec::WorkspaceAccess::ReadWrite;
        request.inputs.push(celln_spec::ExecutionInput {
            name: "oversized".into(),
            hash: celln_manifest::Hash::of(b"data").0,
            media_type: "text/plain".into(),
            bytes: 65537,
        });
        let work = tempfile::tempdir().unwrap();
        let root = work.path().join("must-not-be-created");
        let executions: Executions = Arc::new(Mutex::new(HashMap::new()));
        executions.lock().unwrap().insert(
            request.id.clone(),
            Entry::new(ExecutionRecord {
                request_id: request.id.clone(),
                phase: "Admitting".into(),
                reason: None,
                output: None,
                receipt: None,
            }),
        );
        let probe = NodeProbeArgs {
            node_name: "test".into(),
            mote_store: root.join("motes"),
            tool_store: root.join("tools"),
            max_cells: 1,
            memory_bytes: 268435456,
            egress_slots: 0,
        };
        run_execution(
            request.clone(),
            Arc::clone(&executions),
            probe,
            root.clone(),
        );
        let registry = executions.lock().unwrap();
        let record = &registry[&request.id].value;
        assert_eq!(record.phase, "Refused");
        assert!(record.reason.as_deref().unwrap().contains("input budget"));
        assert!(record.receipt.is_none());
        assert!(!execution_is_active(record));
        assert!(!root.exists());
    }

    #[test]
    fn http_unsupported_authority_returns_422_without_reserving_capacity() {
        let mut request = request_with_egress(&[]);
        request.capabilities.workspace = celln_spec::WorkspaceAccess::ReadOnly;
        request.inputs.push(celln_spec::ExecutionInput {
            name: "oversized".into(),
            hash: celln_manifest::Hash::of(b"data").0,
            media_type: "text/plain".into(),
            bytes: 65537,
        });
        let work = tempfile::tempdir().unwrap();
        let root = work.path().join("unused");
        let state = State {
            token: "test-token-at-least-24-bytes".into(),
            egress_policy: EgressPolicy::new(&[]).unwrap(),
            root: root.clone(),
            probe: NodeProbeArgs {
                node_name: "test".into(),
                mote_store: root.join("motes"),
                tool_store: root.join("tools"),
                max_cells: 1,
                memory_bytes: 268435456,
                egress_slots: 0,
            },
            executions: Arc::new(Mutex::new(HashMap::new())),
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let (server, _) = listener.accept().unwrap();
        let body = serde_json::to_string(&request).unwrap();
        write!(client, "POST /v1/executions HTTP/1.1\r\nAuthorization: Bearer {}\r\nContent-Length: {}\r\n\r\n{}", state.token, body.len(), body).unwrap();
        handle(server, &state).unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 422"), "{response}");
        assert!(response.contains("input budget"));
        assert!(state.executions.lock().unwrap().is_empty());
        assert!(!root.exists());
    }

    #[test]
    fn receipt_phase_tracks_exit_and_output_storage_independently() {
        let work = tempfile::tempdir().unwrap();
        let mut outcome = crate::dispatch::LaunchOutcome {
            input_hashes: Vec::new(),
            cell_id: "cell".into(),
            output: Some(vec![]),
            denial: None,
            exit_code: Some(0),
            signal: None,
            timed_out: false,
        };
        let (phase, output, reason) = collect_result(&outcome, work.path());
        assert_eq!(phase, ExecutionPhase::Succeeded);
        assert!(output.is_none() && reason.is_none());
        outcome.exit_code = Some(7);
        outcome.denial = Some("guest exited with code 7".into());
        outcome.output = Some(b"failure detail".to_vec());
        let (phase, output, reason) = collect_result(&outcome, work.path());
        assert_eq!(phase, ExecutionPhase::Failed);
        let output = output.unwrap();
        assert_eq!(
            Store::open(work.path())
                .unwrap()
                .get(&celln_manifest::Hash(output.hash))
                .unwrap(),
            b"failure detail"
        );
        assert_eq!(reason, outcome.denial);
        let blocked = work.path().join("not-a-directory");
        std::fs::write(&blocked, b"blocked").unwrap();
        outcome.exit_code = Some(0);
        outcome.denial = None;
        let (phase, output, reason) = collect_result(&outcome, &blocked);
        assert_eq!(phase, ExecutionPhase::Failed);
        assert!(output.is_none());
        assert_eq!(reason.as_deref(), Some("output persistence failed"));
    }

    fn request_with_egress(destinations: &[&str]) -> ExecutionRequest {
        let mut request: ExecutionRequest =
            serde_json::from_str(include_str!("../../../examples/execution/forge-task.json"))
                .expect("example request parses");
        request.capabilities.egress = destinations
            .iter()
            .map(|value| (*value).to_owned())
            .collect();
        request
    }

    #[test]
    fn non_loopback_bind_requires_explicit_unsafe_opt_in() {
        assert!(!validate_listen("127.0.0.1:8787", false).unwrap().1);
        assert!(!validate_listen("[::1]:8787", false).unwrap().1);

        let error = validate_listen("0.0.0.0:8787", false).unwrap_err();
        assert!(error.to_string().contains("--unsafe-non-loopback"));
        assert!(error.to_string().contains("TLS-terminating reverse proxy"));
        assert!(validate_listen("0.0.0.0:8787", true).unwrap().1);
    }

    #[test]
    fn listen_policy_binds_the_exact_numeric_address_it_validated() {
        let (address, _) = validate_listen("127.0.0.1:8787", false).unwrap();
        assert_eq!(address, "127.0.0.1:8787".parse().unwrap());

        let error = validate_listen("localhost:8787", false).unwrap_err();
        assert!(error.to_string().contains("numeric IP socket address"));
    }

    #[test]
    fn host_egress_policy_refuses_a_request_selected_destination() {
        let policy = EgressPolicy::new(&["api.example.com".to_owned()]).unwrap();
        policy
            .check(&request_with_egress(&["https://api.example.com"]))
            .expect("operator-approved host is allowed");

        let error = policy
            .check(&request_with_egress(&["https://metadata.example"]))
            .unwrap_err();
        assert!(error.to_string().contains("https://metadata.example"));
        assert!(error.to_string().contains("outside"));
    }

    #[test]
    fn empty_host_egress_policy_is_deny_all() {
        let policy = EgressPolicy::new(&[]).unwrap();
        assert!(policy.check(&request_with_egress(&[])).is_ok());
        assert!(policy
            .check(&request_with_egress(&["https://api.example.com"]))
            .is_err());
    }

    #[test]
    fn constant_time_eq_matches_equal_bytes_and_rejects_different_lengths() {
        assert!(constant_time_eq(b"same-token", b"same-token"));
        assert!(!constant_time_eq(b"same-token", b"different-token"));
        assert!(!constant_time_eq(b"short", b"a-longer-value"));
    }

    #[test]
    fn read_bounded_line_stops_at_newline() {
        let mut cursor = Cursor::new(b"hello world\r\nrest".to_vec());
        let line = read_bounded_line(&mut cursor, 1024).expect("reads a line");
        assert_eq!(line, "hello world\r\n");
    }

    #[test]
    fn read_bounded_line_refuses_a_line_with_no_terminator_within_the_cap() {
        // A peer that never sends `\n` must not be able to grow the buffer
        // without bound — this is the DoS vector the cap exists to close.
        let mut cursor = Cursor::new(vec![b'a'; 10_000]);
        assert!(read_bounded_line(&mut cursor, 64).is_err());
    }

    #[test]
    fn read_headers_rejects_more_than_the_maximum_header_count() {
        let mut raw = String::new();
        for i in 0..(MAX_HEADER_COUNT + 1) {
            raw.push_str(&format!("X-Header-{i}: v\r\n"));
        }
        raw.push_str("\r\n");
        let mut cursor = Cursor::new(raw.into_bytes());
        assert!(read_headers(&mut cursor).is_err());
    }

    #[test]
    fn read_headers_extracts_content_length_and_authorization() {
        let mut cursor = Cursor::new(
            b"Content-Length: 42\r\nAuthorization: Bearer secret-token\r\n\r\n".to_vec(),
        );
        let (length, authorization) = read_headers(&mut cursor).expect("parses headers");
        assert_eq!(length, 42);
        assert_eq!(authorization.as_deref(), Some("secret-token"));
    }

    fn empty_record(id: &str) -> ExecutionRecord {
        ExecutionRecord {
            request_id: id.to_owned(),
            phase: "Running".into(),
            reason: None,
            output: None,
            receipt: None,
        }
    }

    #[test]
    fn evict_expired_removes_only_entries_past_the_ttl() {
        let mut registry: HashMap<String, Entry<ExecutionRecord>> = HashMap::new();
        registry.insert(
            "stale".into(),
            Entry {
                at: Instant::now() - RECORD_TTL - Duration::from_secs(1),
                value: ExecutionRecord {
                    phase: "Succeeded".into(),
                    ..empty_record("stale")
                },
                control: None,
            },
        );
        registry.insert("fresh".into(), Entry::new(empty_record("fresh")));
        registry.insert(
            "old-active".into(),
            Entry {
                at: Instant::now() - RECORD_TTL - Duration::from_secs(1),
                value: empty_record("old-active"),
                control: None,
            },
        );

        evict_expired(&mut registry);

        assert!(!registry.contains_key("stale"));
        assert!(registry.contains_key("fresh"));
        assert!(registry.contains_key("old-active"));
    }

    #[test]
    fn only_non_terminal_executions_consume_capacity() {
        for phase in ["Admitting", "Forging", "Resolving", "Running"] {
            let mut record = empty_record("active");
            record.phase = phase.into();
            assert!(execution_is_active(&record), "{phase} must reserve a slot");
        }
        for phase in ["Succeeded", "Failed", "Refused"] {
            let mut record = empty_record("terminal");
            record.phase = phase.into();
            assert!(
                !execution_is_active(&record),
                "{phase} must release its slot"
            );
        }
    }

    #[test]
    fn rfc3339_utc_matches_a_known_instant() {
        // 2026-08-07T12:00:00Z, spot-checked against `date -u -d @1786190400`.
        assert_eq!(
            crate::dispatch::rfc3339_utc(1_786_104_000),
            "2026-08-07T12:00:00Z"
        );
        // The Unix epoch itself.
        assert_eq!(crate::dispatch::rfc3339_utc(0), "1970-01-01T00:00:00Z");
    }
}
