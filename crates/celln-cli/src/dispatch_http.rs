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
    !matches!(record.phase.as_str(), "Succeeded" | "Failed" | "Refused")
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
    let started_at = crate::dispatch::now_rfc3339();
    let runtime_root = match crate::agent::runtime_root() {
        Ok(path) => path,
        Err(error) => return fail_execution(&executions, &request.id, error.to_string()),
    };
    let assay_root = root.join("assay");

    // Resolved authority for the receipt: (mote, program hash, alias, args,
    // bytes to seal). The declared and forge paths converge here — from this
    // point on, `launch` doesn't know or care which one produced the bytes.
    let (mote, program_hash, alias, args, program_bytes) = if let Some(forge_request) =
        &request.forge
    {
        update_execution(&executions, &request.id, |record| {
            record.phase = "Forging".into()
        });
        let forged = match crate::dispatch::forge(
            forge_request,
            &assay_root,
            request.capabilities.timeout_ms / 1000,
        ) {
            Ok(forged) => forged,
            Err(error) => return fail_execution(&executions, &request.id, error),
        };
        (
            None,
            forged.hash,
            crate::agent::ALIAS.to_owned(),
            Vec::new(),
            forged.bytes,
        )
    } else {
        update_execution(&executions, &request.id, |record| {
            record.phase = "Resolving".into()
        });
        let resolved =
            match crate::dispatch::resolve_bundle(&request, &probe.mote_store, &probe.tool_store) {
                Ok(resolved) => resolved,
                Err(error) => return fail_execution(&executions, &request.id, error),
            };
        let tool_store = match Store::open(&probe.tool_store) {
            Ok(store) => store,
            Err(error) => return fail_execution(&executions, &request.id, error.to_string()),
        };
        let program_bytes =
            match tool_store.get(&celln_manifest::Hash(resolved.program_hash.clone())) {
                Ok(bytes) => bytes,
                Err(error) => return fail_execution(&executions, &request.id, error.to_string()),
            };
        // Presence already validated by celln_spec's own problems() — a
        // declared request always has an invocation.
        let invocation = request
            .invocation
            .as_ref()
            .expect("declared request has an invocation");
        (
            Some(resolved.bundle_hash),
            resolved.program_hash,
            invocation.alias.clone(),
            invocation.args.clone(),
            program_bytes,
        )
    };

    update_execution(&executions, &request.id, |record| {
        record.phase = "Running".into()
    });
    let outcome = match crate::dispatch::launch(
        &request,
        &alias,
        &args,
        &program_bytes,
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
            mote,
            tools: vec![program_hash],
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
    let output_text = output.map(|bytes| String::from_utf8_lossy(bytes).into_owned());
    update_execution(&executions, &request.id, |record| {
        record.phase = format!("{:?}", receipt.phase);
        record.reason = outcome.denial.clone();
        record.output = output_text;
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
                value: empty_record("stale"),
            },
        );
        registry.insert("fresh".into(), Entry::new(empty_record("fresh")));

        evict_expired(&mut registry);

        assert!(!registry.contains_key("stale"));
        assert!(registry.contains_key("fresh"));
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
