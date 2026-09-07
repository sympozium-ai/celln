//! Authenticated local dispatcher for real Celln execution requests.
//!
//! This service is intentionally a Celln process, not a Kubernetes Job
//! wrapper. `POST /v1/executions` admits a `celln.dev/v1alpha1`
//! `ExecutionRequest`, resolves or forges the declared program, runs it in a
//! real sealed cell, and returns a validated `ExecutionReceipt`.

use crate::NodeProbeArgs;
#[path = "dispatch_audit.rs"]
mod audit;
#[cfg(all(test, target_os = "linux"))]
#[path = "dispatch_harness_tests.rs"]
mod harness_tests;
#[path = "dispatch_journal.rs"]
mod journal;
use anyhow::{bail, Context, Result};
use celln_spec::{
    ExecutionOutput, ExecutionPhase, ExecutionReceipt, ExecutionRequest, ResolvedExecution,
};
use celln_store::Store;
use serde::{Deserialize, Serialize};
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

/// Terminal memory-cache TTL only. Durable records/tombstones are not expired;
/// new admission stops at the journal's bounded record capacity.
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

/// A registry entry with terminal cache age. Admission sweeps expired terminal
/// entries only after persistence; active or unpersisted records remain live.
struct Entry<T> {
    at: Instant,
    value: T,
    control: Option<celln_control::Control>,
    reservation: Option<Reservation>,
    audit: Option<audit::Audit>,
    journal_root: Option<PathBuf>,
}

impl<T> Entry<T> {
    fn new(value: T) -> Self {
        Entry {
            at: Instant::now(),
            value,
            control: None,
            reservation: None,
            audit: None,
            journal_root: None,
        }
    }
}

fn evict_expired(registry: &mut HashMap<String, Entry<ExecutionRecord>>) {
    let now = Instant::now();
    registry.retain(|_, entry| {
        execution_is_active(&entry.value)
            || now.duration_since(entry.at) < RECORD_TTL
            || entry.journal_root.as_ref().is_some_and(|root| {
                !journal::read(root, &entry.value.request_id)
                    .is_ok_and(|snapshot| snapshot.is_some_and(|s| !execution_is_active(&s.record)))
            })
    });
}

/// One `celln.dev/v1alpha1` execution in flight or finished on this node.
/// This is the dispatcher's own bookkeeping, not the wire receipt — it has
/// room for a human-readable reason a receipt does not.
#[derive(Debug, Clone, Serialize, Deserialize)]
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

/// Reserve the full declared guest RAM and one synchronous broker per cell
/// with egress. Destinations share that broker; they are not concurrent slots.
#[derive(Clone, Copy)]
struct Reservation {
    memory_bytes: u64,
    egress_slots: u32,
}

impl Reservation {
    fn for_request(request: &ExecutionRequest) -> Self {
        Self {
            memory_bytes: request.capabilities.memory_bytes,
            egress_slots: u32::from(!request.capabilities.egress.is_empty()),
        }
    }
}

fn apply_reservations(
    node: &mut crate::node::NodeEligibility,
    registry: &HashMap<String, Entry<ExecutionRecord>>,
    other_live_cells: u32,
) {
    node.live_cells = other_live_cells;
    // Legacy/other-process records do not carry resource declarations. Do
    // not invent spare capacity when a live owner's usage is unknown.
    if other_live_cells != 0 {
        node.memory_bytes = 0;
        node.egress_slots = 0;
    }
    for entry in registry
        .values()
        .filter(|entry| execution_is_active(&entry.value))
    {
        node.live_cells = node.live_cells.saturating_add(1);
        if let Some(reservation) = entry.reservation {
            node.memory_bytes = node.memory_bytes.saturating_sub(reservation.memory_bytes);
            node.egress_slots = node.egress_slots.saturating_sub(reservation.egress_slots);
        } else {
            node.memory_bytes = 0;
            node.egress_slots = 0;
        }
    }
}

fn current_node(
    state: &State,
    registry: &HashMap<String, Entry<ExecutionRecord>>,
) -> crate::node::NodeEligibility {
    let mut node = crate::node::NodeEligibility::from_probe(&state.probe, 0);
    let other = crate::cells::live_count_excluding_pid(&state.root, Some(std::process::id()));
    apply_reservations(&mut node, registry, other);
    node
}

struct State {
    token_file: PathBuf,
    #[cfg(test)]
    token: String,
    egress_policy: EgressPolicy,
    root: PathBuf,
    probe: NodeProbeArgs,
    executions: Executions,
}

/// Reopen the path each time: projected Secrets replace symlinks during rotation.
/// Bound the read and never include credential bytes in diagnostics.
pub(crate) fn read_bearer_token(path: &Path) -> Result<String> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(4097)
        .read_to_end(&mut bytes)?;
    let token = std::str::from_utf8(&bytes)?.trim();
    if bytes.len() > 4096 || token.len() < 24 || !token.bytes().all(|b| b.is_ascii_graphic()) {
        bail!("invalid bearer credential");
    }
    Ok(token.to_owned())
}

impl State {
    fn credential(&self) -> Result<String> {
        #[cfg(test)]
        if self.token_file.as_os_str().is_empty() {
            return Ok(self.token.clone());
        }
        read_bearer_token(&self.token_file)
    }
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
    read_bearer_token(token_file).context("reading dispatcher credential")?;
    // Reservations are process-local. Two dispatchers must not independently
    // advertise the same state root's capacity while neither has a cell yet.
    let _ownership = own_dispatch_root(&root)?;
    journal::prepare(&root)?;
    let listener = TcpListener::bind(listen_address)
        .with_context(|| format!("binding dispatcher {listen_address}"))?;
    let state = Arc::new(State {
        token_file: token_file.to_owned(),
        #[cfg(test)]
        token: String::new(),
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

fn own_dispatch_root(root: &Path) -> Result<std::fs::File> {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        std::fs::create_dir_all(root)?;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(root.join("dispatcher.lock"))?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            bail!("dispatcher state root is already owned or cannot be locked");
        }
        Ok(file)
    }
    #[cfg(not(unix))]
    {
        let _ = root;
        bail!("dispatcher ownership locking is unsupported on this host")
    }
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
    let is_public_health_check = method == "GET" && path == "/v1/health";
    if !is_public_health_check {
        let token = match state.credential() {
            Ok(token) => token,
            Err(_) => {
                return reply(
                    &mut stream,
                    503,
                    &serde_json::json!({"error":"dispatcher credential unavailable"}),
                );
            }
        };
        let authorized =
            authorization.is_some_and(|value| constant_time_eq(value.as_bytes(), token.as_bytes()));
        if !authorized {
            return reply(
                &mut stream,
                401,
                &serde_json::json!({"error":"unauthorized"}),
            );
        }
    }
    match (method.as_str(), path.as_str()) {
        ("GET", "/v1/capabilities") => {
            let registry = state
                .executions
                .lock()
                .expect("dispatcher registry not poisoned");
            let report =
                crate::capabilities::DispatcherCapabilities::new(current_node(state, &registry));
            reply(&mut stream, 200, &serde_json::to_value(report)?)
        }
        ("GET", "/v1/node") => {
            let registry = state
                .executions
                .lock()
                .expect("dispatcher registry not poisoned");
            let node = current_node(state, &registry);
            #[cfg(target_os = "linux")]
            let warm = crate::dispatch::warm::availability();
            #[cfg(not(target_os = "linux"))]
            let warm: Option<Vec<String>> = None;
            reply(
                &mut stream,
                200,
                &serde_json::json!({
                    "node": node, "warm": warm, "availability_is_advisory": true,
                    "preflight_only": true,
                    "configured_memory_bytes": state.probe.memory_bytes,
                    "configured_egress_slots": state.probe.egress_slots,
                }),
            )
        }
        ("GET", "/v1/health") => {
            let registry = state
                .executions
                .lock()
                .expect("dispatcher registry not poisoned");
            let node = current_node(state, &registry);
            reply(
                &mut stream,
                200,
                &serde_json::json!({
                    "ok": node.eligible(),
                    "kvm": node.kvm,
                    "mote_store": node.mote_store,
                    "tool_store": node.tool_store,
                    "node": node,
                    "configured_memory_bytes": state.probe.memory_bytes,
                    "configured_egress_slots": state.probe.egress_slots,
                    "preflight_only": true,
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
            match journal::read(&state.root, &request.id) {
                Ok(Some(snapshot)) => {
                    if snapshot.request_hash != celln_manifest::Hash::of(&body).0 {
                        return reply(
                            &mut stream,
                            409,
                            &serde_json::json!({"error":"execution id already bound to different request bytes"}),
                        );
                    }
                    if let Some(existing) = registry.get(&request.id) {
                        if execution_is_active(&existing.value) {
                            return reply(&mut stream, 202, &existing.value);
                        }
                        return reply_entry(&mut stream, existing, false);
                    }
                    return reply_snapshot(&mut stream, snapshot, false);
                }
                Ok(None) => {}
                Err(_) => {
                    return reply(
                        &mut stream,
                        503,
                        &serde_json::json!({"error":"execution journal unavailable; do not replay"}),
                    )
                }
            }
            if let Some(existing) = registry.get(&request.id) {
                return reply(&mut stream, 202, &existing.value);
            }
            evict_expired(&mut registry);

            // Reserve capacity while holding the same lock used to insert the
            // execution. Without this atomic check, a burst can admit every
            // request before any worker has created its cell. Registry entries
            // cover pre-cell work such as forging too, so accepted work cannot
            // overcommit the node while waiting to launch.
            let node = current_node(state, &registry);
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
            entry.reservation = Some(Reservation::for_request(&request));
            entry.audit = Some(audit::Audit::new(&request, &state.probe.node_name));
            if journal::claim(
                &state.root,
                &body,
                &entry.value,
                entry.audit.as_ref().unwrap(),
            )
            .is_err()
            {
                return reply(
                    &mut stream,
                    503,
                    &serde_json::json!({"error":"durable admission unavailable; retry same id"}),
                );
            }
            entry.journal_root = Some(state.root.clone());
            registry.insert(request.id.clone(), entry);
            drop(registry);
            let worker_executions = Arc::clone(&state.executions);
            let probe = state.probe.clone();
            let root = state.root.clone();
            let worker = thread::Builder::new().spawn(move || {
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
            if worker.is_err() {
                fail_execution(
                    &state.executions,
                    &record.request_id,
                    "execution worker unavailable".into(),
                );
                return reply(
                    &mut stream,
                    503,
                    &serde_json::json!({"error": "execution worker unavailable"}),
                );
            }
            reply(&mut stream, 202, &record)
        }
        ("POST", path) if path.starts_with("/v1/executions/") && path.ends_with("/cancel") => {
            let id = &path["/v1/executions/".len()..path.len() - "/cancel".len()];
            let mut registry = state
                .executions
                .lock()
                .expect("dispatcher registry not poisoned");
            let Some(entry) = registry.get_mut(id) else {
                return reply_archived(&mut stream, state, id, false);
            };
            if execution_is_active(&entry.value) {
                if let Some(control) = &entry.control {
                    control.cancel();
                }
                entry.value.phase = "Cancelling".into();
                entry.value.reason = Some("cancellation requested; cleanup pending".into());
                if let Some(audit) = &mut entry.audit {
                    audit.phase("Cancelling");
                }
                // Reservation remains live until the worker has unwound all
                // subprocesses, VM handles and preparation state.
                reply(&mut stream, 202, &entry.value)
            } else {
                reply_entry(&mut stream, entry, false)
            }
        }
        ("GET", path) if path.starts_with("/v1/executions/") && path.ends_with("/audit") => {
            let id = &path["/v1/executions/".len()..path.len() - "/audit".len()];
            let registry = state
                .executions
                .lock()
                .expect("dispatcher registry not poisoned");
            match registry.get(id) {
                Some(entry) => reply_entry(&mut stream, entry, true),
                None => reply_archived(&mut stream, state, id, true),
            }
        }
        ("GET", path) if path.starts_with("/v1/executions/") => {
            let id = path.trim_start_matches("/v1/executions/");
            let registry = state
                .executions
                .lock()
                .expect("dispatcher registry not poisoned");
            match registry.get(id) {
                Some(entry) => reply_entry(&mut stream, entry, false),
                None => reply_archived(&mut stream, state, id, false),
            }
        }
        _ => reply(&mut stream, 404, &serde_json::json!({"error":"not found"})),
    }
}

fn persist_terminal(entry: &Entry<ExecutionRecord>) -> Result<()> {
    if !execution_is_active(&entry.value) {
        if let Some(root) = &entry.journal_root {
            journal::complete(
                root,
                &entry.value,
                entry.audit.as_ref().context("missing audit")?,
            )?;
        }
    }
    Ok(())
}

fn reply_entry(stream: &mut TcpStream, entry: &Entry<ExecutionRecord>, audit: bool) -> Result<()> {
    if persist_terminal(entry).is_err() {
        return reply(
            stream,
            503,
            &serde_json::json!({"error":"terminal record not durable; do not replay"}),
        );
    }
    if audit {
        match &entry.audit {
            Some(value) => reply(stream, 200, value),
            None => reply(
                stream,
                404,
                &serde_json::json!({"error":"unknown execution audit"}),
            ),
        }
    } else {
        reply(stream, 200, &entry.value)
    }
}

fn reply_snapshot(stream: &mut TcpStream, snapshot: journal::Snapshot, audit: bool) -> Result<()> {
    if execution_is_active(&snapshot.record) {
        return reply(
            stream,
            503,
            &serde_json::json!({"error":"interrupted execution requires operator reconciliation; teardown is unproven; do not replay"}),
        );
    }
    if audit {
        reply(stream, 200, &snapshot.audit)
    } else {
        reply(stream, 200, &snapshot.record)
    }
}

fn reply_archived(stream: &mut TcpStream, state: &State, id: &str, audit: bool) -> Result<()> {
    match journal::read(&state.root, id) {
        Ok(Some(snapshot)) => reply_snapshot(stream, snapshot, audit),
        Ok(None) => reply(
            stream,
            404,
            &serde_json::json!({"error":"unknown execution"}),
        ),
        Err(_) => reply(
            stream,
            503,
            &serde_json::json!({"error":"execution journal unavailable; do not replay"}),
        ),
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
        if let Some(audit) = &mut entry.audit {
            audit.phase(&entry.value.phase);
            audit.receipt = entry.value.receipt.clone();
        }
        if let Err(error) = persist_terminal(entry) {
            eprintln!("dispatcher terminal journal unavailable: {error:#}");
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
        // Policy/provider admission refused before any program executes. Do
        // not label this a workload failure or invent a terminal guest receipt.
        update_execution(&executions, &request.id, |record| {
            record.phase = "Refused".into();
            record.reason = Some(error);
        });
        return;
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
            record.phase = "Preparing".into()
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

    if let Some(audit) = executions
        .lock()
        .expect("dispatcher registry not poisoned")
        .get_mut(&request.id)
        .and_then(|entry| entry.audit.as_mut())
    {
        audit.executed(&request, &outcome);
    }
    let output = outcome.output.as_deref().filter(|bytes| !bytes.is_empty());
    let (phase, stored_output, reason) = collect_result(&outcome, &root.join("outputs"));
    let receipt = ExecutionReceipt {
        api_version: request.api_version.clone(),
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

pub(crate) fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
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
            token_file: PathBuf::new(),
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

    #[test]
    fn credentials_rotate_and_fail_closed_without_restart() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = lifecycle_state(dir.path());
        state.token_file = dir.path().join("credential");
        let old = "old-public-test-token-at-least-24";
        let new = "new-public-test-token-at-least-24";
        std::fs::write(&state.token_file, old).unwrap();
        // An authenticated request reaches lookup (404); rejected requests do not.
        assert!(cancel_http(&state, "absent", old).starts_with("HTTP/1.1 404"));
        assert!(cancel_http(&state, "absent", "").starts_with("HTTP/1.1 401"));
        let replacement = dir.path().join("replacement");
        std::fs::write(&replacement, format!("{new}\n")).unwrap();
        std::fs::rename(&replacement, &state.token_file).unwrap();
        assert!(cancel_http(&state, "absent", old).starts_with("HTTP/1.1 401"));
        assert!(cancel_http(&state, "absent", new).starts_with("HTTP/1.1 404"));
        for invalid in [
            Vec::new(),
            b"short".to_vec(),
            format!("{new} injected").into_bytes(),
            format!("{new}\r\nInjected: header").into_bytes(),
            vec![b'x'; 4097],
            vec![0xff; 24],
        ] {
            std::fs::write(&state.token_file, invalid).unwrap();
            let response = cancel_http(&state, "absent", new);
            assert!(response.starts_with("HTTP/1.1 503"));
            assert!(!response.contains(new));
        }
        std::fs::remove_file(&state.token_file).unwrap();
        assert!(cancel_http(&state, "absent", old).starts_with("HTTP/1.1 503"));
        std::fs::write(&state.token_file, new).unwrap();
        assert!(cancel_http(&state, "absent", new).starts_with("HTTP/1.1 404"));
        assert!(state.executions.lock().unwrap().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn durable_records_survive_empty_registry_without_replaying_interrupted_claims() {
        fn http(state: &State, method: &str, path: &str, body: &[u8], token: &str) -> String {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let (server, _) = listener.accept().unwrap();
            write!(client, "{method} {path} HTTP/1.1\r\nAuthorization: Bearer {token}\r\nContent-Length: {}\r\n\r\n", body.len()).unwrap();
            client.write_all(body).unwrap();
            handle(server, state).unwrap();
            let mut response = String::new();
            client.read_to_string(&mut response).unwrap();
            response
        }
        let root = tempfile::tempdir().unwrap();
        let state = lifecycle_state(root.path());
        let request = request_with_egress(&[]);
        let body = serde_json::to_vec(&request).unwrap();
        let mut record = empty_record(&request.id);
        let mut audit = audit::Audit::new(&request, "test");
        journal::claim(root.path(), &body, &record, &audit).unwrap();
        // No live registry/worker exists, as after a restart. A durable claim
        // cannot be interpreted as a fresh request, success or teardown.
        for (method, suffix) in [("GET", ""), ("GET", "/audit"), ("POST", "/cancel")] {
            let path = format!("/v1/executions/{}{suffix}", request.id);
            assert!(http(&state, method, &path, b"", "wrong").starts_with("HTTP/1.1 401"));
            assert!(http(&state, method, &path, b"", &state.token).starts_with("HTTP/1.1 503"));
        }
        assert!(
            http(&state, "POST", "/v1/executions", &body, &state.token).starts_with("HTTP/1.1 503")
        );
        let mut changed = request.clone();
        changed.workload.id.push_str("-changed");
        assert!(http(
            &state,
            "POST",
            "/v1/executions",
            &serde_json::to_vec(&changed).unwrap(),
            &state.token
        )
        .starts_with("HTTP/1.1 409"));
        assert!(state.executions.lock().unwrap().is_empty());

        record.phase = "Refused".into();
        record.reason = Some("fixture refused before execution".into());
        audit.phase("Refused");
        journal::complete(root.path(), &record, &audit).unwrap();
        for (method, suffix) in [("GET", ""), ("GET", "/audit"), ("POST", "/cancel")] {
            let response = http(
                &state,
                method,
                &format!("/v1/executions/{}{suffix}", request.id),
                b"",
                &state.token,
            );
            assert!(response.starts_with("HTTP/1.1 200"), "{response}");
            let value: serde_json::Value =
                serde_json::from_str(response.split_once("\r\n\r\n").unwrap().1).unwrap();
            let expected = if suffix == "/audit" {
                serde_json::to_value(&audit).unwrap()
            } else {
                serde_json::to_value(&record).unwrap()
            };
            assert_eq!(value, expected);
        }
        assert!(
            http(&state, "POST", "/v1/executions", &body, &state.token).starts_with("HTTP/1.1 200")
        );
        assert!(state.executions.lock().unwrap().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn terminal_persistence_failure_is_not_reported_as_completion_or_evicted() {
        let root = tempfile::tempdir().unwrap();
        let request = request_with_egress(&[]);
        let mut entry = Entry::new(empty_record(&request.id));
        entry.journal_root = Some(root.path().into());
        entry.audit = Some(audit::Audit::new(&request, "test"));
        // Missing claim simulates unavailable/corrupt admission state.
        entry.value.phase = "Failed".into();
        entry.at = Instant::now() - RECORD_TTL - Duration::from_secs(1);
        assert!(persist_terminal(&entry).is_err());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        reply_entry(&mut server, &entry, false).unwrap();
        drop(server);
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 503"));
        let mut registry = HashMap::from([(request.id.clone(), entry)]);
        evict_expired(&mut registry);
        assert!(registry.contains_key(&request.id));
    }

    #[test]
    fn a_state_root_has_one_dispatcher_owner_and_releases_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        let owner = own_dispatch_root(dir.path()).unwrap();
        assert!(own_dispatch_root(dir.path()).is_err());
        drop(owner);
        assert!(own_dispatch_root(dir.path()).is_ok());
    }

    fn eligible_node(memory: u64, egress: u32) -> crate::node::NodeEligibility {
        crate::node::NodeEligibility {
            node_name: "test".into(),
            kvm: true,
            cpu_virtualization: true,
            guest_kernel: true,
            mote_store: true,
            tool_store: true,
            live_cells: 0,
            max_cells: 100,
            memory_bytes: memory,
            egress_slots: egress,
        }
    }

    #[test]
    fn concurrent_admission_cannot_overcommit_memory_or_brokers() {
        for (destinations, expected) in [(vec![], 2), (vec!["https://example.com"], 1)] {
            let registry: Executions = Arc::new(Mutex::new(HashMap::new()));
            let barrier = Arc::new(std::sync::Barrier::new(16));
            let mut workers = Vec::new();
            for index in 0..16 {
                let registry = registry.clone();
                let barrier = barrier.clone();
                let mut request = request_with_egress(&destinations);
                request.id = format!("request-{index}");
                workers.push(thread::spawn(move || {
                    barrier.wait();
                    let mut registry = registry.lock().unwrap();
                    let mut node = eligible_node(2 * 268435456, 1);
                    apply_reservations(&mut node, &registry, 0);
                    if matches!(
                        crate::node::admit(&request, &node),
                        crate::node::Admission::Accepted { .. }
                    ) {
                        let mut entry = Entry::new(empty_record(&request.id));
                        entry.reservation = Some(Reservation::for_request(&request));
                        registry.insert(request.id, entry);
                    }
                }));
            }
            for worker in workers {
                worker.join().unwrap();
            }
            assert_eq!(registry.lock().unwrap().len(), expected);
        }
    }

    #[test]
    fn reservations_survive_cancellation_and_release_on_every_terminal_state() {
        let req = request_with_egress(&["https://example.com", "https://another.example"]);
        let mut entry = Entry::new(empty_record("run"));
        entry.reservation = Some(Reservation::for_request(&req));
        let mut registry = HashMap::from([("run".into(), entry)]);
        for phase in ["Admitting", "Forging", "Running", "Cancelling"] {
            registry.get_mut("run").unwrap().value.phase = phase.into();
            let mut node = eligible_node(268435456, 1);
            apply_reservations(&mut node, &registry, 0);
            assert_eq!(
                (node.live_cells, node.memory_bytes, node.egress_slots),
                (1, 0, 0)
            );
        }
        for phase in ["Succeeded", "Failed", "Refused", "Cancelled"] {
            registry.get_mut("run").unwrap().value.phase = phase.into();
            let mut node = eligible_node(268435456, 1);
            apply_reservations(&mut node, &registry, 0);
            assert_eq!(
                (node.live_cells, node.memory_bytes, node.egress_slots),
                (0, 268435456, 1)
            );
        }
    }

    #[test]
    fn unknown_or_excess_usage_never_wraps_into_available_capacity() {
        let mut node = eligible_node(1, 1);
        apply_reservations(&mut node, &HashMap::new(), 1);
        assert_eq!((node.memory_bytes, node.egress_slots), (0, 0));
        let mut registry = HashMap::from([("unknown".into(), Entry::new(empty_record("unknown")))]);
        let mut node = eligible_node(u64::MAX, u32::MAX);
        apply_reservations(&mut node, &registry, 0);
        assert_eq!((node.memory_bytes, node.egress_slots), (0, 0));
        registry.get_mut("unknown").unwrap().reservation = Some(Reservation {
            memory_bytes: u64::MAX,
            egress_slots: u32::MAX,
        });
        let mut node = eligible_node(1, 1);
        apply_reservations(&mut node, &registry, 0);
        assert_eq!((node.memory_bytes, node.egress_slots), (0, 0));
    }

    #[test]
    fn health_uses_configured_paths_and_identity_hints_require_authentication() {
        let work = tempfile::tempdir().unwrap();
        let state = lifecycle_state(work.path());
        std::fs::create_dir(&state.probe.mote_store).unwrap();
        for (path, expected) in [
            ("/v1/health", "HTTP/1.1 200"),
            ("/v1/node", "HTTP/1.1 401"),
            ("/v1/capabilities", "HTTP/1.1 401"),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (server, _) = listener.accept().unwrap();
            write!(client, "GET {path} HTTP/1.1\r\n\r\n").unwrap();
            handle(server, &state).unwrap();
            let mut response = String::new();
            client.read_to_string(&mut response).unwrap();
            assert!(response.starts_with(expected), "{response}");
            if path == "/v1/health" {
                let body: serde_json::Value =
                    serde_json::from_str(response.split_once("\r\n\r\n").unwrap().1).unwrap();
                assert_eq!(body["mote_store"], true);
                assert_eq!(body["tool_store"], false);
                assert_eq!(body["ok"], false);
                assert_eq!(body["configured_memory_bytes"], 268435456u64);
                assert!(body.get("warm").is_none());
            }
        }
    }

    #[test]
    fn capability_report_is_versioned_preflight_and_does_not_advertise_artifact_readiness() {
        let work = tempfile::tempdir().unwrap();
        let state = lifecycle_state(work.path());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        write!(
            client,
            "GET /v1/capabilities HTTP/1.1\r\nAuthorization: Bearer {}\r\n\r\n",
            state.token
        )
        .unwrap();
        handle(server, &state).unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200"));
        let report: crate::capabilities::DispatcherCapabilities =
            serde_json::from_str(response.split_once("\r\n\r\n").unwrap().1).unwrap();
        assert!(report.compatible());
        assert!(!report.node.eligible()); // Configured stores are absent.
        assert!(!report.persistent_sessions);
        assert_eq!(report.harness_contracts, ["celln.reference-functions/v1"]);
        assert_eq!(report.artifact_readiness, "not_checked");
        assert!(state.executions.lock().unwrap().is_empty());
        assert!(!work.path().join("execution-journal").exists());
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
    fn audit_endpoint_is_authenticated_and_preserves_the_strict_receipt() {
        let dir = tempfile::tempdir().unwrap();
        let state = lifecycle_state(dir.path());
        let request = request_with_egress(&[]);
        let mut entry = Entry::new(empty_record(&request.id));
        entry.audit = Some(audit::Audit::new(&request, "test"));
        state
            .executions
            .lock()
            .unwrap()
            .insert(request.id.clone(), entry);
        let mut receipt: ExecutionReceipt = serde_json::from_str(include_str!(
            "../../../examples/execution/succeeded-receipt.json"
        ))
        .unwrap();
        receipt.request_id = request.id.clone();
        update_execution(&state.executions, &request.id, |record| {
            record.phase = "Succeeded".into();
            record.receipt = Some(receipt.clone());
        });
        for (suffix, token, status) in [
            ("/audit", "wrong", 401),
            ("/audit", state.token.as_str(), 200),
            ("", state.token.as_str(), 200),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (server, _) = listener.accept().unwrap();
            write!(
                client,
                "GET /v1/executions/{}{suffix} HTTP/1.1\r\nAuthorization: Bearer {token}\r\n\r\n",
                request.id
            )
            .unwrap();
            handle(server, &state).unwrap();
            let mut response = String::new();
            client.read_to_string(&mut response).unwrap();
            assert!(response.starts_with(&format!("HTTP/1.1 {status}")));
            if status == 200 {
                let body: serde_json::Value =
                    serde_json::from_str(response.split_once("\r\n\r\n").unwrap().1).unwrap();
                let decoded: ExecutionReceipt =
                    serde_json::from_value(body["receipt"].clone()).unwrap();
                assert_eq!(
                    serde_json::to_value(decoded).unwrap(),
                    serde_json::to_value(&receipt).unwrap()
                );
                if suffix == "/audit" {
                    assert_eq!(body["apiVersion"], "celln.dev/audit-v1alpha1");
                    assert_eq!(body["events"][1]["phase"], "Succeeded");
                } else {
                    assert!(body.get("events").is_none());
                }
            }
        }
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
        for (bytes, expected) in [(65537, "input budget"), (4, "input trust policy")] {
            let mut request = request_with_egress(&[]);
            request.capabilities.workspace = celln_spec::WorkspaceAccess::ReadWrite;
            request.inputs.push(celln_spec::ExecutionInput {
                name: "oversized".into(),
                hash: celln_manifest::Hash::of(b"data").0,
                media_type: "text/plain".into(),
                bytes,
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
            assert!(record.reason.as_deref().unwrap().contains(expected));
            assert!(record.receipt.is_none());
            assert!(!execution_is_active(record));
            assert!(!root.exists());
        }
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
            token_file: PathBuf::new(),
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
            execution: None,
            substrate: None,
            broker: Default::default(),
            lifecycle: Vec::new(),
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
                reservation: None,
                audit: None,
                journal_root: None,
            },
        );
        registry.insert("fresh".into(), Entry::new(empty_record("fresh")));
        registry.insert(
            "old-active".into(),
            Entry {
                at: Instant::now() - RECORD_TTL - Duration::from_secs(1),
                value: empty_record("old-active"),
                control: None,
                reservation: None,
                audit: None,
                journal_root: None,
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
