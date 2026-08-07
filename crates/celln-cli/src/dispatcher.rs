//! Authenticated local dispatcher for real Celln agent actions.
//!
//! This service is intentionally a Celln process, not a Kubernetes Job
//! wrapper. Every submitted action is executed by the existing KVM/Pilot path.
//! It is the first transport seam; immutable bundle/receipt publication remains
//! a separate required stage before upstream controllers may claim completion.

use crate::agent::Backend;
use crate::NodeProbeArgs;
use anyhow::{bail, Context, Result};
use celln_spec::{
    ExecutionOutput, ExecutionPhase, ExecutionReceipt, ExecutionRequest, ResolvedExecution,
};
use celln_store::Store;
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
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

/// How long a finished action/execution record is kept before it is evicted
/// on the next insert. Registries are otherwise unbounded — every unique id
/// a caller submits stays in memory for the life of the process.
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmitAction {
    pub id: String,
    pub task: String,
    #[serde(default)]
    pub backend: Option<Backend>,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default = "default_timeout")]
    pub timeout: u64,
    #[serde(default)]
    pub allow_hosts: Vec<String>,
}

fn default_timeout() -> u64 {
    90
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActionStatus {
    pub id: String,
    pub phase: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cell_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub program_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// A registry entry tagged with its insertion time, so a background sweep
/// can evict entries older than [`RECORD_TTL`]. Registries are otherwise
/// unbounded for the life of the process.
struct Entry<T> {
    at: Instant,
    value: T,
}

impl<T> Entry<T> {
    fn new(value: T) -> Self {
        Entry {
            at: Instant::now(),
            value,
        }
    }
}

fn evict_expired<T>(registry: &mut HashMap<String, Entry<T>>) {
    let now = Instant::now();
    registry.retain(|_, entry| now.duration_since(entry.at) < RECORD_TTL);
}

type Actions = Arc<Mutex<HashMap<String, Entry<ActionStatus>>>>;

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt: Option<ExecutionReceipt>,
}

type Executions = Arc<Mutex<HashMap<String, Entry<ExecutionRecord>>>>;

struct State {
    token: String,
    root: PathBuf,
    probe: NodeProbeArgs,
    actions: Actions,
    executions: Executions,
}

pub fn serve(listen: &str, token_file: &Path, root: PathBuf, probe: &NodeProbeArgs) -> Result<u8> {
    let token = std::fs::read_to_string(token_file)
        .with_context(|| format!("reading dispatcher token {}", token_file.display()))?
        .trim()
        .to_owned();
    if token.len() < 24 {
        bail!("dispatcher token must contain at least 24 non-whitespace bytes");
    }
    let listener =
        TcpListener::bind(listen).with_context(|| format!("binding dispatcher {listen}"))?;
    let state = Arc::new(State {
        token,
        root,
        probe: probe.clone(),
        actions: Arc::new(Mutex::new(HashMap::new())),
        executions: Arc::new(Mutex::new(HashMap::new())),
    });
    eprintln!("celln dispatcher listening on {listen}");
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
    if !authorized && !(method == "GET" && path == "/v1/health") {
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
        ("POST", "/v1/actions") => {
            if length > 64 * 1024 {
                return reply(
                    &mut stream,
                    413,
                    &serde_json::json!({"error":"request body exceeds 64 KiB"}),
                );
            }
            let mut body = vec![0; length];
            reader.read_exact(&mut body)?;
            let action: SubmitAction =
                serde_json::from_slice(&body).context("parsing action request")?;
            if action.id.trim().is_empty() || action.task.trim().is_empty() {
                return reply(
                    &mut stream,
                    400,
                    &serde_json::json!({"error":"id and task are required"}),
                );
            }
            let status = ActionStatus {
                id: action.id.clone(),
                phase: "Pending".into(),
                cell_id: None,
                program_hash: None,
                output: None,
                output_hash: None,
                output_bytes: None,
                error: None,
            };
            let mut registry = state
                .actions
                .lock()
                .expect("dispatcher registry not poisoned");
            if let Some(existing) = registry.get(&action.id) {
                return reply(&mut stream, 202, &existing.value);
            }
            evict_expired(&mut registry);
            registry.insert(action.id.clone(), Entry::new(status.clone()));
            drop(registry);
            let worker_actions = Arc::clone(&state.actions);
            let root = state.root.clone();
            thread::spawn(move || run_action(action, worker_actions, root));
            reply(&mut stream, 202, &status)
        }
        ("GET", path) if path.starts_with("/v1/actions/") => {
            let id = path.trim_start_matches("/v1/actions/");
            let registry = state
                .actions
                .lock()
                .expect("dispatcher registry not poisoned");
            match registry.get(id) {
                Some(entry) => reply(&mut stream, 200, &entry.value),
                None => reply(
                    &mut stream,
                    404,
                    &serde_json::json!({"error":"unknown action"}),
                ),
            }
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
            let record = ExecutionRecord {
                request_id: request.id.clone(),
                phase: "Admitting".into(),
                reason: None,
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
            registry.insert(request.id.clone(), Entry::new(record.clone()));
            drop(registry);
            let worker_executions = Arc::clone(&state.executions);
            let probe = state.probe.clone();
            let root = state.root.clone();
            thread::spawn(move || run_execution(request, worker_executions, probe, root));
            reply(&mut stream, 202, &record)
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

fn run_action(action: SubmitAction, actions: Actions, root: PathBuf) {
    update(&actions, &action.id, |status| {
        status.phase = "Admitting".into()
    });
    let current = match std::env::current_exe() {
        Ok(path) => path,
        Err(error) => return fail(&actions, &action.id, error.to_string()),
    };
    let mut command = Command::new(current);
    command.arg("--root").arg(&root).arg("--json").arg("agent");
    if let Some(backend) = action.backend {
        command.arg("--agent").arg(
            backend
                .to_possible_value()
                .expect("backend value")
                .get_name(),
        );
    }
    if let Some(model) = action.model {
        command.arg("--model").arg(model);
    }
    command.arg("--timeout").arg(action.timeout.to_string());
    for host in action.allow_hosts {
        command.arg("--allow-host").arg(host);
    }
    command
        .arg(action.task)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = match command.output() {
        Ok(output) => output,
        Err(error) => return fail(&actions, &action.id, error.to_string()),
    };
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let Ok(event) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        match event.get("event").and_then(|value| value.as_str()) {
            Some("cell_started") => update(&actions, &action.id, |status| {
                status.phase = "Running".into();
                status.cell_id = event
                    .get("cellId")
                    .and_then(|value| value.as_str())
                    .map(str::to_owned);
            }),
            Some("agent_forged") => update(&actions, &action.id, |status| {
                status.program_hash = event
                    .get("hash")
                    .and_then(|value| value.as_str())
                    .map(str::to_owned);
            }),
            Some("agent_output") => update(&actions, &action.id, |status| {
                status.output = event
                    .get("stdout")
                    .and_then(|value| value.as_str())
                    .map(str::to_owned);
            }),
            _ => {}
        }
    }
    if output.status.success() {
        if let Err(error) = persist_output(&actions, &action.id, &root) {
            return fail(&actions, &action.id, error.to_string());
        }
        update(&actions, &action.id, |status| {
            status.phase = "Succeeded".into()
        });
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        fail(
            &actions,
            &action.id,
            if stderr.is_empty() {
                format!("agent exited {}", output.status)
            } else {
                stderr
            },
        );
    }
}

/// Persist bounded output if the process produced any. A process that exits
/// 0 but never emits an `agent_output` event (a genuinely empty result, or a
/// line the parser above didn't recognise) is still a success — it is not
/// grounds to overwrite the phase a caller may already be polling as
/// terminal.
fn persist_output(actions: &Actions, id: &str, root: &Path) -> Result<()> {
    let output = actions
        .lock()
        .expect("dispatcher registry not poisoned")
        .get(id)
        .and_then(|entry| entry.value.output.clone());
    let Some(output) = output else {
        return Ok(());
    };
    let store = Store::open(root.join("outputs"))?;
    let hash = store.put(output.as_bytes())?;
    update(actions, id, |status| {
        status.output_hash = Some(hash.0);
        status.output_bytes = Some(output.len() as u64);
    });
    Ok(())
}

fn update(actions: &Actions, id: &str, f: impl FnOnce(&mut ActionStatus)) {
    if let Some(entry) = actions
        .lock()
        .expect("dispatcher registry not poisoned")
        .get_mut(id)
    {
        f(&mut entry.value);
    }
}

fn fail(actions: &Actions, id: &str, error: String) {
    update(actions, id, |status| {
        status.phase = "Failed".into();
        status.error = Some(error);
    });
}

fn update_execution(executions: &Executions, id: &str, f: impl FnOnce(&mut ExecutionRecord)) {
    if let Some(entry) = executions
        .lock()
        .expect("dispatcher registry not poisoned")
        .get_mut(id)
    {
        f(&mut entry.value);
    }
}

fn fail_execution(executions: &Executions, id: &str, reason: String) {
    update_execution(executions, id, |record| {
        record.phase = "Failed".into();
        record.reason = Some(reason);
    });
}

/// Admit, resolve, and launch a `celln.dev/v1alpha1` execution request, then
/// record the terminal [`ExecutionReceipt`]. This is the hermetic path: the
/// program that runs is the exact bytes `resolve_bundle` proved match the
/// request's declared hash, not code a model was asked to write.
fn run_execution(
    request: ExecutionRequest,
    executions: Executions,
    probe: NodeProbeArgs,
    root: PathBuf,
) {
    let started_at = crate::dispatch::now_rfc3339();
    let node = crate::node::NodeEligibility::from_probe(&probe);
    match crate::node::admit(&request, &node) {
        crate::node::Admission::Refused { reason, .. } => {
            update_execution(&executions, &request.id, |record| {
                record.phase = "Refused".into();
                record.reason = Some(format!("{reason:?}"));
            });
            return;
        }
        crate::node::Admission::Accepted { .. } => {}
    }

    update_execution(&executions, &request.id, |record| {
        record.phase = "Resolving".into()
    });
    let resolved =
        match crate::dispatch::resolve_bundle(&request, &probe.mote_store, &probe.tool_store) {
            Ok(resolved) => resolved,
            Err(error) => return fail_execution(&executions, &request.id, error),
        };

    update_execution(&executions, &request.id, |record| {
        record.phase = "Running".into()
    });
    let runtime_root = match crate::agent::runtime_root() {
        Ok(path) => path,
        Err(error) => return fail_execution(&executions, &request.id, error.to_string()),
    };
    let assay_root = root.join("assay");
    let outcome = match crate::dispatch::launch(
        &request,
        &resolved,
        &probe.tool_store,
        &runtime_root,
        &assay_root,
        &root,
    ) {
        Ok(outcome) => outcome,
        Err(error) => return fail_execution(&executions, &request.id, error),
    };

    let output = outcome.output.as_deref().filter(|bytes| !bytes.is_empty());
    let stored_output = output.and_then(|bytes| {
        Store::open(root.join("outputs"))
            .and_then(|store| store.put(bytes))
            .ok()
            .map(|hash| ExecutionOutput {
                hash: hash.0,
                media_type: "application/octet-stream".into(),
                bytes: bytes.len() as u64,
            })
    });
    let phase = if stored_output.is_some() {
        ExecutionPhase::Succeeded
    } else {
        ExecutionPhase::Failed
    };
    let receipt = ExecutionReceipt {
        api_version: "celln.dev/v1alpha1".into(),
        request_id: request.id.clone(),
        phase,
        node: probe.node_name.clone(),
        cell_id: outcome.cell_id,
        resolved: ResolvedExecution {
            mote: resolved.bundle_hash,
            tools: vec![resolved.program_hash],
            inputs: request
                .inputs
                .iter()
                .map(|input| input.hash.clone())
                .collect(),
        },
        output: stored_output,
        started_at,
        completed_at: crate::dispatch::now_rfc3339(),
    };
    update_execution(&executions, &request.id, |record| {
        record.phase = format!("{:?}", receipt.phase);
        record.reason = outcome.denial.clone();
        record.receipt = Some(receipt.clone());
    });
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

    fn empty_status(id: &str) -> ActionStatus {
        ActionStatus {
            id: id.to_owned(),
            phase: "Running".into(),
            cell_id: None,
            program_hash: None,
            output: None,
            output_hash: None,
            output_bytes: None,
            error: None,
        }
    }

    #[test]
    fn persist_output_leaves_a_successful_action_alone_when_there_was_no_bounded_output() {
        // A process that exits 0 without an `agent_output` event (e.g. a
        // genuinely empty result) must not be turned into a Failed action —
        // that was the bug: only a Store error should ever fail here.
        let root = tempfile::tempdir().expect("tempdir");
        let actions: Actions = Arc::new(Mutex::new(HashMap::new()));
        actions
            .lock()
            .unwrap()
            .insert("run-1".into(), Entry::new(empty_status("run-1")));

        let result = persist_output(&actions, "run-1", root.path());
        assert!(result.is_ok(), "{result:?}");

        let registry = actions.lock().unwrap();
        let status = &registry.get("run-1").unwrap().value;
        assert_eq!(
            status.phase, "Running",
            "persist_output must not touch phase"
        );
        assert!(status.output_hash.is_none());
        assert!(status.error.is_none());
    }

    #[test]
    fn persist_output_stores_and_hashes_real_output() {
        let root = tempfile::tempdir().expect("tempdir");
        let actions: Actions = Arc::new(Mutex::new(HashMap::new()));
        let mut status = empty_status("run-2");
        status.output = Some("hello from the cell".into());
        actions
            .lock()
            .unwrap()
            .insert("run-2".into(), Entry::new(status));

        persist_output(&actions, "run-2", root.path()).expect("persists");

        let registry = actions.lock().unwrap();
        let status = &registry.get("run-2").unwrap().value;
        assert!(status.output_hash.is_some());
        assert_eq!(
            status.output_bytes,
            Some("hello from the cell".len() as u64)
        );
    }

    #[test]
    fn evict_expired_removes_only_entries_past_the_ttl() {
        let mut registry: HashMap<String, Entry<ActionStatus>> = HashMap::new();
        registry.insert(
            "stale".into(),
            Entry {
                at: Instant::now() - RECORD_TTL - Duration::from_secs(1),
                value: empty_status("stale"),
            },
        );
        registry.insert("fresh".into(), Entry::new(empty_status("fresh")));

        evict_expired(&mut registry);

        assert!(!registry.contains_key("stale"));
        assert!(registry.contains_key("fresh"));
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
