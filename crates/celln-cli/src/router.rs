//! Authenticated router that distributes actions across Celln dispatcher
//! backends. Each backend is a Celln process with a `/v1/health` endpoint that
//! reports KVM availability. The router picks a backend, checks its health,
//! and forwards if healthy; otherwise it tries the next BEFORE claiming an
//! owner. Claimed executions are never reselected or automatically replayed.
//!
//! The router is intentionally not a load tracker. It relies on per-node
//! admission ("can this node spawn another cell?") via the health check.
//! One accepted request = one warden = one cell — no multiplexing.

use crate::dispatch_http::{
    constant_time_eq, read_bounded_line, MAX_HEADER_COUNT, MAX_HEADER_LINE, MAX_REQUEST_LINE,
};
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::io::{BufReader, Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[path = "router_ownership.rs"]
mod ownership;
#[path = "router_parents.rs"]
mod parents;

// Credentials are bounded and never echoed in errors. Reload on each request
// to support atomic file/Secret rotation; an unreadable file fails closed.
fn read_token(path: &Path) -> Result<String> {
    crate::dispatch_http::read_bearer_token(path)
}

fn credentials(state: &RouterState) -> Result<(String, String, Option<String>)> {
    let client = read_token(&state.client_token_file)?;
    let backend = read_token(&state.token_file)?;
    if constant_time_eq(client.as_bytes(), backend.as_bytes()) {
        bail!("client and dispatcher credentials must be distinct");
    }
    let capability = capability_credential(state, &client, &backend)?;
    Ok((client, backend, capability))
}

fn capability_credential(
    state: &RouterState,
    client: &str,
    backend: &str,
) -> Result<Option<String>> {
    let token = state
        .capability_token_file
        .as_deref()
        .map(read_token)
        .transpose()?;
    if token.as_ref().is_some_and(|token| {
        constant_time_eq(token.as_bytes(), client.as_bytes())
            || constant_time_eq(token.as_bytes(), backend.as_bytes())
    }) {
        bail!("capability credential must be distinct");
    }
    Ok(token)
}

/// How the router selects a dispatcher backend for each action.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum RoutingMode {
    /// Deterministic per action id (an FNV-1a hash of the id, modulo the
    /// backend count), skipping unhealthy backends. This is what lets a
    /// caller retry a POST with the same id and land on the same backend
    /// it reached the first time, instead of wherever a shared rotating
    /// cursor happens to point on the retry.
    RoundRobin,
    /// Pick a backend at random; fall through to the next if unhealthy.
    Random,
}

/// FNV-1a. Only needs to be a stable, well-distributed hash — not
/// cryptographic — so retries of the same action id are deterministic.
fn fnv1a(bytes: &[u8]) -> u64 {
    const OFFSET: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x100000001b3;
    bytes.iter().fold(OFFSET, |hash, byte| {
        (hash ^ *byte as u64).wrapping_mul(PRIME)
    })
}

#[derive(Debug, Deserialize)]
struct Health {
    ok: bool,
    kvm: bool,
}

#[allow(clippy::too_many_arguments)]
pub fn serve(
    listen: &str,
    backends: Vec<String>,
    backends_srv: Option<&str>,
    mode: RoutingMode,
    token_file: &Path,
    client_token_file: &Path,
    capability_token_file: Option<&Path>,
    parent_token_file: Option<&Path>,
    ownership_dir: &Path,
) -> Result<u8> {
    let mut urls: Vec<String> = backends
        .into_iter()
        .map(|b| b.trim_end_matches('/').to_string())
        .collect();

    // DNS-based discovery: resolve the SRV name to all pod IPs.
    if let Some(srv) = backends_srv {
        let srv = srv.trim_end_matches('/');
        let addr = if srv.contains(':') {
            srv.to_string()
        } else {
            format!("{srv}:8787")
        };
        match addr.to_socket_addrs() {
            Ok(addrs) => {
                for a in addrs {
                    let url = format!("http://{}:{}", a.ip(), a.port());
                    if !urls.contains(&url) {
                        urls.push(url);
                    }
                }
            }
            Err(e) => eprintln!("celln route: warning: could not resolve {addr}: {e}"),
        }
    }

    if urls.is_empty() {
        bail!("at least one dispatcher backend URL is required (--backends or --backends-srv)");
    }
    for url in &urls {
        backend_to_addr(url)?;
    }
    let state = Arc::new(RouterState {
        backends: urls.clone(),
        mode,
        cursor: AtomicUsize::new(0),
        executions: ownership::Ledger::open(ownership_dir, 100_000)?,
        parents: ownership::Ledger::open(&ownership_dir.join("parents"), 100_000)?,
        parent_token_file: parent_token_file.map(Path::to_owned),
        token_file: token_file.to_owned(),
        client_token_file: client_token_file.to_owned(),
        capability_token_file: capability_token_file.map(Path::to_owned),
        capability_probe_active: AtomicBool::new(false),
    });
    credentials(&state).context("router credentials are missing, invalid or not distinct")?;
    let listener = TcpListener::bind(listen).with_context(|| format!("binding router {listen}"))?;
    eprintln!(
        "celln route listening on {listen} ({} backends, {mode:?})",
        urls.len()
    );
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let state = Arc::clone(&state);
                std::thread::spawn(move || {
                    if let Err(error) = handle(stream, &state) {
                        eprintln!("router request failed: {error:#}");
                    }
                });
            }
            Err(error) => eprintln!("router accept failed: {error}"),
        }
    }
    Ok(crate::exit::OK)
}

struct RouterState {
    backends: Vec<String>,
    mode: RoutingMode,
    cursor: AtomicUsize,
    /// Shared durable ownership and anti-replay tombstones.
    executions: ownership::Ledger,
    parents: ownership::Ledger,
    parent_token_file: Option<PathBuf>,
    token_file: PathBuf,
    client_token_file: PathBuf,
    capability_token_file: Option<PathBuf>,
    capability_probe_active: AtomicBool,
}

fn handle(mut stream: TcpStream, state: &RouterState) -> Result<()> {
    let result = handle_request(&mut stream, state);
    finish_response(&mut stream);
    result
}

// A close with unread request bytes may reset TCP and discard even an already
// written refusal at an HTTP proxy. Send FIN first, then discard a bounded tail.
// Never parse, authorize or forward this tail; peers exceeding the limits still
// lose the connection. A total deadline prevents slow byte-at-a-time uploads
// from extending the per-read timeout indefinitely.
fn finish_response(stream: &mut TcpStream) {
    use std::net::Shutdown;
    use std::time::Instant;
    if stream.shutdown(Shutdown::Write).is_err() {
        return;
    }
    let deadline = Instant::now() + Duration::from_millis(100);
    let mut remaining = 65536;
    let mut buffer = [0u8; 4096];
    while remaining > 0 {
        let Some(timeout) = deadline.checked_duration_since(Instant::now()) else {
            break;
        };
        if stream.set_read_timeout(Some(timeout)).is_err() {
            break;
        }
        let limit = remaining.min(buffer.len());
        match stream.read(&mut buffer[..limit]) {
            Ok(0) | Err(_) => break,
            Ok(n) => remaining -= n,
        }
    }
}

fn handle_request(stream: &mut TcpStream, state: &RouterState) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let request_line = read_bounded_line(&mut reader, MAX_REQUEST_LINE)?;
    let Some((method, raw_path)) = request_line.trim_end().split_once(' ') else {
        return reply(
            stream,
            400,
            &serde_json::json!({"error":"malformed request line"}),
        );
    };
    let path = raw_path
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_owned();
    let method = method.to_owned();

    let mut length = 0usize;
    let mut seen_length = false;
    let mut authorization = None;
    let mut pinned_backend = None;
    let mut parent_incarnation = None;
    let mut respond_async = false;
    let mut header_count = 0usize;
    loop {
        let header = read_bounded_line(&mut reader, MAX_HEADER_LINE)?;
        if header.is_empty() {
            bail!("unexpected EOF in headers");
        }
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        header_count += 1;
        if header_count > MAX_HEADER_COUNT {
            bail!("too many headers (max {MAX_HEADER_COUNT})");
        }
        let Some((name, value)) = header.split_once(':') else {
            return reply(stream, 400, &serde_json::json!({"error":"invalid header"}));
        };
        if name.eq_ignore_ascii_case("authorization") {
            if authorization.is_some() {
                return reply(
                    stream,
                    400,
                    &serde_json::json!({"error":"duplicate authorization"}),
                );
            }
            authorization = Some(value.trim().to_owned());
        } else if name.eq_ignore_ascii_case("x-celln-backend") {
            if pinned_backend.is_some() {
                return reply(
                    stream,
                    400,
                    &serde_json::json!({"error":"duplicate backend pin"}),
                );
            }
            pinned_backend = Some(value.trim().to_owned());
        } else if name.eq_ignore_ascii_case("x-celln-parent-incarnation") {
            if parent_incarnation
                .replace(value.trim().to_owned())
                .is_some()
            {
                return reply(
                    stream,
                    400,
                    &serde_json::json!({"error":"duplicate parent identity"}),
                );
            }
        } else if name.eq_ignore_ascii_case("prefer") {
            if value.trim() != "respond-async" || respond_async {
                return reply(
                    stream,
                    400,
                    &serde_json::json!({"error":"unsupported or duplicate preference"}),
                );
            }
            respond_async = true;
        } else if name.eq_ignore_ascii_case("content-length") {
            if seen_length || !value.trim().bytes().all(|b| b.is_ascii_digit()) {
                return reply(
                    stream,
                    400,
                    &serde_json::json!({"error":"invalid content length"}),
                );
            }
            seen_length = true;
            let Ok(parsed) = value.trim().parse() else {
                return reply(
                    stream,
                    400,
                    &serde_json::json!({"error":"invalid content length"}),
                );
            };
            length = parsed;
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            return reply(
                stream,
                400,
                &serde_json::json!({"error":"transfer encoding unsupported"}),
            );
        }
    }

    let Ok((client_token, backend_token, read_token)) = credentials(state) else {
        return reply(
            stream,
            503,
            &serde_json::json!({"error":"router credentials unavailable"}),
        );
    };
    let presented = authorization.as_deref().and_then(|value| {
        let (scheme, token) = value.split_once(' ')?;
        scheme.eq_ignore_ascii_case("bearer").then_some(token)
    });
    let is_capability_read = method == "GET" && path == "/v1/capabilities";
    let authorized = presented.is_some_and(|token| {
        constant_time_eq(token.as_bytes(), client_token.as_bytes())
            || (is_capability_read
                && read_token
                    .as_ref()
                    .is_some_and(|read| constant_time_eq(token.as_bytes(), read.as_bytes())))
    });
    if !authorized {
        return reply(stream, 401, &serde_json::json!({"error":"unauthorized"}));
    }
    let backend_token = Some(backend_token);
    // Pins are trusted-controller routing intent, not tenant URLs. Match only
    // an exact operator-configured endpoint and never probe/select a fallback.
    if let Some(backend) = &pinned_backend {
        if backend.len() > 1024 || !state.backends.contains(backend) {
            return reply(
                stream,
                400,
                &serde_json::json!({"error":"backend pin is not configured"}),
            );
        }
        if method != "POST" || (path != "/v1/executions" && path != "/v1/artifacts/prewarm") {
            return reply(
                stream,
                400,
                &serde_json::json!({"error":"backend pin only applies to submission or prewarm"}),
            );
        }
    }
    match (method.as_str(), path.as_str()) {
        (_, path) if path == "/v1/parents" || path.starts_with("/v1/parents/") => {
            parents::forward(
                state,
                stream,
                &mut reader,
                &method,
                path,
                length,
                parent_incarnation.as_deref(),
                respond_async,
                &backend_token,
            )?;
        }
        ("GET", "/v1/capabilities") => capability_report(state, stream, &backend_token)?,
        ("POST", "/v1/artifacts/prewarm") => forward_prewarm(
            stream,
            &mut reader,
            length,
            pinned_backend.as_deref(),
            &backend_token,
        )?,
        ("POST", "/v1/executions") => forward_submission(
            state,
            stream,
            &mut reader,
            length,
            "/v1/executions",
            &backend_token,
            pinned_backend.as_deref(),
        )?,
        ("POST", path) if execution_path_id(path, true).is_some() => {
            if length != 0 {
                return reply(
                    stream,
                    400,
                    &serde_json::json!({"error":"cancel body must be empty"}),
                );
            }
            forward_existing(state, stream, "POST", path, true, &backend_token)?;
        }
        ("GET", path) if execution_path_id(path, false).is_some() => {
            forward_existing(state, stream, "GET", path, false, &backend_token)?
        }
        _ => {
            reply(stream, 404, &serde_json::json!({"error":"not found"}))?;
        }
    }
    Ok(())
}

fn capability_report(
    state: &RouterState,
    stream: &mut TcpStream,
    token: &Option<String>,
) -> Result<()> {
    // Bound fanout and permit only one probe at a time per router. No request or
    // owner ledger is mutated by discovery; failures never trigger execution.
    if state.backends.len() > 32 || state.capability_probe_active.swap(true, Ordering::AcqRel) {
        return reply(
            stream,
            503,
            &serde_json::json!({"error":"capability probe unavailable"}),
        );
    }
    struct ProbeGuard<'a>(&'a AtomicBool);
    impl Drop for ProbeGuard<'_> {
        fn drop(&mut self) {
            self.0.store(false, Ordering::Release);
        }
    }
    let _guard = ProbeGuard(&state.capability_probe_active);
    let nodes = std::thread::scope(|scope| {
        let probes: Vec<_> = state.backends.iter().enumerate().map(|(index, backend)| {
            scope.spawn(move || {
                let report = (|| -> Result<crate::capabilities::DispatcherCapabilities> {
                    let addr = backend_to_addr(backend)?;
                    let mut conn = connect(&addr)?;
                    let credential = token.as_deref().context("backend credential missing")?;
                    write!(conn, "GET /v1/capabilities HTTP/1.1\r\nHost: dispatcher\r\nAuthorization: Bearer {credential}\r\nConnection: close\r\n\r\n")?;
                    let response = read_capability_response(&mut conn)?;
                    if parse_status(&response) != 200 { bail!("backend capability request failed"); }
                    let report: crate::capabilities::DispatcherCapabilities = serde_json::from_str(extract_body(&response))?;
                    if !report.compatible() { bail!("incompatible backend capabilities"); }
                    Ok(report)
                })();
                match report {
                    Ok(report) => serde_json::json!({"index":index,"preflightEligible":report.node.eligible(),"report":report}),
                    Err(_) => serde_json::json!({"index":index,"preflightEligible":false,"reason":"unreachable_unauthorized_or_incompatible"}),
                }
            })
        }).collect();
        probes
            .into_iter()
            .map(|probe| {
                probe.join().unwrap_or_else(
                    |_| serde_json::json!({"preflightEligible":false,"reason":"probe_failed"}),
                )
            })
            .collect::<Vec<_>>()
    });
    let eligible = nodes
        .iter()
        .filter(|node| node["preflightEligible"] == true)
        .count();
    reply(
        stream,
        200,
        &serde_json::json!({
            "apiVersion":crate::capabilities::VERSION,
            "preflightOnly":true,
            "eligibleNodes":eligible,
            "artifactReadiness":"not_checked",
            "parentRouting":state.parent_token_file.is_some(),
            "nodes":nodes,
        }),
    )
}

/// `POST <endpoint>`: pick a healthy backend deterministically by the
/// request's own `id` field, forward the body verbatim, and — on
/// before forwarding — durably bind the body and owner. Lost responses must
/// not let another router replica replay a possibly executed POST.
fn forward_submission(
    state: &RouterState,
    stream: &mut TcpStream,
    reader: &mut BufReader<TcpStream>,
    length: usize,
    endpoint: &str,
    token: &Option<String>,
    pinned_backend: Option<&str>,
) -> Result<()> {
    if length == 0 || length > 64 * 1024 {
        return reply(
            stream,
            413,
            &serde_json::json!({"error":"request body exceeds 64 KiB or is empty"}),
        );
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body)?;

    let id = match extract_id(&body) {
        Ok(id) if valid_path_id(&id) => id,
        _ => {
            return reply(
                stream,
                400,
                &serde_json::json!({"error":"id must be a nonempty ASCII alphanumeric, dash, underscore or dot path component"}),
            )
        }
    };

    let claim = match state.executions.claim(&id, &body, || match pinned_backend {
        Some(backend) => Ok(backend.to_owned()),
        None => pick_backend(state, &id, token),
    }) {
        Ok(claim) => claim,
        Err(_) => {
            return reply(
                stream,
                503,
                &serde_json::json!({"error":"ownership unavailable; retry same request without changing id"}),
            )
        }
    };
    match claim {
        ownership::Claim::Conflict => reply(
            stream,
            409,
            &serde_json::json!({"error":"execution id already binds different request bytes"}),
        ),
        ownership::Claim::Full => reply(
            stream,
            503,
            &serde_json::json!({"error":"ownership capacity exhausted; operator reconciliation required"}),
        ),
        ownership::Claim::Existing(owner)
            if pinned_backend.is_some_and(|pin| pin != owner.backend) =>
        {
            reply(
                stream,
                409,
                &serde_json::json!({"error":"execution already binds a different backend; no reroute"}),
            )
        }
        ownership::Claim::Existing(owner) => forward_owned(
            state,
            stream,
            &owner.backend,
            "GET",
            &format!("/v1/executions/{id}"),
            token,
        ),
        ownership::Claim::New(owner) => {
            match forward_post(&owner.backend, endpoint, &body, token) {
                Ok(resp) => raw_reply(stream, &resp),
                Err(_) => reply(
                    stream,
                    503,
                    &serde_json::json!({"error":"submission outcome unknown; owner retained; POST will not be replayed"}),
                ),
            }
        }
    }
}

// Prewarm is an observation in one serving process, not an execution or an
// ownership claim. Require an explicit configured target; preserve body/response
// bytes and leave artifact validation, sealing and admission to that dispatcher.
fn forward_prewarm(
    stream: &mut TcpStream,
    reader: &mut BufReader<TcpStream>,
    length: usize,
    backend: Option<&str>,
    token: &Option<String>,
) -> Result<()> {
    let Some(backend) = backend else {
        return reply(
            stream,
            400,
            &serde_json::json!({"error":"prewarm requires an explicit backend pin"}),
        );
    };
    if length == 0 || length > 64 * 1024 {
        return reply(
            stream,
            413,
            &serde_json::json!({"error":"prewarm body exceeds 64 KiB or is empty"}),
        );
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body)?;
    match forward_post(backend, "/v1/artifacts/prewarm", &body, token) {
        Ok(response) => raw_reply(stream, &response),
        Err(_) => reply(
            stream,
            503,
            &serde_json::json!({"error":"pinned prewarm unavailable; no fallback"}),
        ),
    }
}

/// `GET <endpoint>/:id`: forward to whichever backend `forward_submission`
/// recorded as owning that id.
fn forward_existing(
    state: &RouterState,
    stream: &mut TcpStream,
    method: &str,
    path: &str,
    cancel: bool,
    token: &Option<String>,
) -> Result<()> {
    let id = execution_path_id(path, cancel).context("invalid execution path")?;
    let backend = match state.executions.lookup(id) {
        Ok(owner) => owner,
        Err(_) => {
            return reply(
                stream,
                503,
                &serde_json::json!({"error":"execution ownership unavailable"}),
            )
        }
    };
    match backend {
        Some(owner) => forward_owned(state, stream, &owner.backend, method, path, token),
        None => reply(
            stream,
            404,
            &serde_json::json!({"error": "unknown execution"}),
        ),
    }
}

fn forward_owned(
    state: &RouterState,
    stream: &mut TcpStream,
    backend: &str,
    method: &str,
    path: &str,
    token: &Option<String>,
) -> Result<()> {
    if !state.backends.iter().any(|url| url == backend) {
        return reply(
            stream,
            503,
            &serde_json::json!({"error":"recorded owner removed from configured backends; no reroute"}),
        );
    }
    let response = if method == "POST" {
        forward_post(backend, path, &[], token)
    } else {
        forward_get(backend, path, token)
    };
    match response {
        Ok(resp) if parse_status(&resp) != 404 => raw_reply(stream, &resp),
        _ => reply(
            stream,
            503,
            &serde_json::json!({"error":"recorded owner unavailable or outcome lost; no reroute or replay"}),
        ),
    }
}

fn execution_path_id(path: &str, cancel: bool) -> Option<&str> {
    let suffix = path.strip_prefix("/v1/executions/")?;
    let id = if cancel {
        suffix.strip_suffix("/cancel")?
    } else {
        suffix.strip_suffix("/audit").unwrap_or(suffix)
    };
    valid_path_id(id).then_some(id)
}

fn valid_path_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 512
        && id != "."
        && id != ".."
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}

fn pick_backend(state: &RouterState, action_id: &str, token: &Option<String>) -> Result<String> {
    let n = state.backends.len();
    let start = match state.mode {
        RoutingMode::RoundRobin => (fnv1a(action_id.as_bytes()) as usize) % n,
        RoutingMode::Random => {
            // Fast non-crypto random from the cursor.
            let t = state.cursor.fetch_add(1, Ordering::Relaxed);
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .subsec_nanos() as usize;
            (t.wrapping_mul(6364136223846793005).wrapping_add(nanos)) % n
        }
    };

    for offset in 0..n {
        let backend = &state.backends[(start + offset) % n];
        if is_healthy(backend, token).unwrap_or(false) {
            return Ok(backend.clone());
        }
    }
    bail!("no healthy dispatcher backends among {} candidates", n)
}

fn is_healthy(backend: &str, token: &Option<String>) -> Result<bool> {
    let resp = forward_get(backend, "/v1/health", token)?;
    match parse_status(&resp) {
        200 => {
            let body = extract_body(&resp);
            match serde_json::from_str::<Health>(body) {
                Ok(h) => Ok(h.ok && h.kvm),
                Err(_) => Ok(false),
            }
        }
        _ => Ok(false),
    }
}

fn forward_get(backend: &str, path: &str, token: &Option<String>) -> Result<String> {
    let addr = backend_to_addr(backend)?;
    let mut stream = connect(&addr)?;
    if let Some(t) = token {
        write!(stream, "GET {path} HTTP/1.1\r\nHost: {backend}\r\nAuthorization: Bearer {t}\r\nConnection: close\r\n\r\n")?;
    } else {
        write!(
            stream,
            "GET {path} HTTP/1.1\r\nHost: {backend}\r\nConnection: close\r\n\r\n"
        )?;
    }
    stream.flush()?;
    read_response(&mut stream)
}

fn forward_post(backend: &str, path: &str, body: &[u8], token: &Option<String>) -> Result<String> {
    let addr = backend_to_addr(backend)?;
    let mut stream = connect(&addr)?;
    if let Some(t) = token {
        write!(
            stream,
            "POST {path} HTTP/1.1\r\nHost: {backend}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAuthorization: Bearer {t}\r\nConnection: close\r\n\r\n",
            body.len()
        )?;
    } else {
        write!(
            stream,
            "POST {path} HTTP/1.1\r\nHost: {backend}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )?;
    }
    stream.write_all(body)?;
    stream.flush()?;
    read_response(&mut stream)
}

fn backend_to_addr(backend: &str) -> Result<String> {
    // This transport is raw TCP, not TLS. Never silently send a credential in
    // plaintext when the operator supplied an HTTPS URL.
    let host = backend
        .strip_prefix("http://")
        .context("router backend requires http://; native TLS is unsupported")?;
    if host.is_empty()
        || host.contains(['/', '@', '?', '#'])
        || host.chars().any(char::is_whitespace)
    {
        bail!("invalid router backend authority");
    }
    let addr = if host.contains(':') {
        host.to_string()
    } else {
        format!("{host}:80")
    };
    Ok(addr)
}

fn connect(addr: &str) -> Result<TcpStream> {
    let stream = TcpStream::connect_timeout(
        &addr
            .to_socket_addrs()
            .context("resolving backend address")?
            .next()
            .context("no address resolved")?,
        Duration::from_secs(3),
    )
    .context("connecting to backend")?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    Ok(stream)
}

fn read_response(stream: &mut TcpStream) -> Result<String> {
    // Dispatchers close each response. Bound the entire wire message, including
    // headers; a truncated header must not cause an infinite EOF loop.
    read_response_limit(stream, 16 * 1024 * 1024)
}

fn read_capability_response(stream: &mut TcpStream) -> Result<String> {
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let mut bytes = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let remaining = deadline
            .checked_duration_since(std::time::Instant::now())
            .context("capability response deadline exceeded")?;
        stream.set_read_timeout(Some(remaining))?;
        let n = stream.read(&mut buf)?;
        if n == 0 {
            break;
        }
        bytes.extend_from_slice(&buf[..n]);
        if bytes.len() > 65536 {
            bail!("oversized capability response");
        }
    }
    if !bytes.windows(4).any(|w| w == b"\r\n\r\n") {
        bail!("invalid capability response");
    }
    String::from_utf8(bytes).context("invalid capability encoding")
}

fn read_response_limit(stream: &mut TcpStream, max_response: u64) -> Result<String> {
    let mut bytes = Vec::new();
    stream.take(max_response + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_response || !bytes.windows(4).any(|w| w == b"\r\n\r\n") {
        bail!("invalid or oversized dispatcher response");
    }
    String::from_utf8(bytes).context("dispatcher response is not UTF-8")
}

fn parse_status(response: &str) -> u16 {
    response
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or(502)
}

fn extract_body(response: &str) -> &str {
    match response.find("\r\n\r\n") {
        Some(pos) => &response[pos + 4..],
        None => match response.find("\n\n") {
            Some(pos) => &response[pos + 2..],
            None => "",
        },
    }
}

/// `ExecutionRequest` carries a top-level `id` field.
fn extract_id(body: &[u8]) -> Result<String> {
    let v: serde_json::Value = serde_json::from_slice(body).context("parsing request body")?;
    v.get("id")
        .and_then(|id| id.as_str())
        .map(str::to_string)
        .context("request body missing required 'id' field")
}

fn reply(stream: &mut TcpStream, status: u16, body: &serde_json::Value) -> Result<()> {
    let body = serde_json::to_vec(body)?;
    write!(
        stream,
        "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(&body)?;
    Ok(())
}

fn raw_reply(stream: &mut TcpStream, response: &str) -> Result<()> {
    stream.write_all(response.as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fnv1a_is_deterministic_and_spreads_similar_keys() {
        assert_eq!(fnv1a(b"action-1"), fnv1a(b"action-1"));
        assert_ne!(fnv1a(b"action-1"), fnv1a(b"action-2"));
    }

    #[test]
    fn round_robin_selection_is_stable_for_the_same_action_id_across_backend_counts() {
        // The bug this closes: retrying a POST for the same action id must
        // land on the same backend index every time, for a fixed backend
        // count — not wherever a shared rotating cursor happens to be.
        let n = 5usize;
        let first = (fnv1a(b"same-action-id") as usize) % n;
        let second = (fnv1a(b"same-action-id") as usize) % n;
        assert_eq!(first, second);
    }

    #[test]
    fn extract_id_reads_the_id_field() {
        let body = br#"{"id":"run-42","task":"do a thing"}"#;
        assert_eq!(extract_id(body).unwrap(), "run-42");
    }

    #[test]
    fn extract_id_fails_without_an_id() {
        let body = br#"{"task":"do a thing"}"#;
        assert!(extract_id(body).is_err());
    }

    #[test]
    fn parse_status_reads_the_numeric_status_code() {
        assert_eq!(
            parse_status("HTTP/1.1 202 OK\r\nContent-Length: 0\r\n\r\n"),
            202
        );
        assert_eq!(parse_status("not a status line"), 502);
    }

    #[test]
    fn extract_body_finds_the_content_after_the_blank_line() {
        let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        assert_eq!(extract_body(response), "ok");
    }

    #[test]
    fn backend_to_addr_defaults_to_port_80_without_an_explicit_port() {
        assert_eq!(backend_to_addr("http://node1").unwrap(), "node1:80");
        assert_eq!(backend_to_addr("http://node1:9000").unwrap(), "node1:9000");
        assert!(backend_to_addr("https://node1:9000").is_err());
        assert!(backend_to_addr("http://user:password@node1").is_err());
    }

    const CLIENT_TOKEN: &str = "client-test-credential-at-least-24";
    const BACKEND_TOKEN: &str = "backend-test-credential-at-least-24";

    #[test]
    fn capability_token_is_read_only_distinct_and_rotatable() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = state(dir.path());
        let path = dir.path().join("capability");
        let first = "readonly-test-credential-at-least-24";
        let second = "rotated-readonly-credential-at-least-24";
        std::fs::write(&path, first).unwrap();
        state.capability_token_file = Some(path.clone());
        let headers = |token| format!("Authorization: Bearer {token}\r\n");
        for token in [first, CLIENT_TOKEN] {
            let response = request(&state, "GET", "/v1/capabilities", &headers(token), "");
            assert_eq!(parse_status(&response), 200);
            let report: serde_json::Value = serde_json::from_str(extract_body(&response)).unwrap();
            assert_eq!(report["eligibleNodes"], 0);
            assert_eq!(report["preflightOnly"], true);
        }
        for (method, path) in [
            ("POST", "/v1/executions"),
            ("GET", "/v1/executions/x"),
            ("GET", "/v1/executions/x/audit"),
            ("POST", "/v1/executions/x/cancel"),
            ("POST", "/v1/capabilities"),
            ("GET", "/v1/node"),
        ] {
            assert_eq!(
                parse_status(&request(&state, method, path, &headers(first), "")),
                401
            );
        }
        for token in ["", BACKEND_TOKEN, "wrong"] {
            assert_eq!(
                parse_status(&request(
                    &state,
                    "GET",
                    "/v1/capabilities",
                    &headers(token),
                    ""
                )),
                401
            );
        }
        std::fs::write(&path, second).unwrap();
        assert_eq!(
            parse_status(&request(
                &state,
                "GET",
                "/v1/capabilities",
                &headers(first),
                ""
            )),
            401
        );
        assert_eq!(
            parse_status(&request(
                &state,
                "GET",
                "/v1/capabilities",
                &headers(second),
                ""
            )),
            200
        );
        for invalid in [CLIENT_TOKEN, BACKEND_TOKEN, "short"] {
            std::fs::write(&path, invalid).unwrap();
            assert!(credentials(&state).is_err());
            assert_eq!(
                parse_status(&request(
                    &state,
                    "GET",
                    "/v1/capabilities",
                    &headers(second),
                    ""
                )),
                503
            );
        }
        std::fs::remove_file(path).unwrap();
        assert_eq!(
            parse_status(&request(
                &state,
                "GET",
                "/v1/capabilities",
                &headers(second),
                ""
            )),
            503
        );
    }

    #[test]
    fn capability_fanout_requires_authenticated_compatible_eligible_reports() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = state(dir.path());
        let base = crate::capabilities::DispatcherCapabilities::new(crate::node::NodeEligibility {
            node_name: "fixture".into(),
            kvm: true,
            cpu_virtualization: true,
            guest_kernel: true,
            mote_store: true,
            tool_store: true,
            live_cells: 0,
            max_cells: 1,
            memory_bytes: 268435456,
            egress_slots: 1,
        });
        let good = serde_json::to_value(base).unwrap();
        let mut missing_kvm = good.clone();
        missing_kvm["node"]["kvm"] = false.into();
        let mut full = good.clone();
        full["node"]["live_cells"] = 1.into();
        let mut incompatible = good.clone();
        incompatible["apiVersion"] = "future/unknown".into();
        let fixtures = [
            (200, good),
            (200, missing_kvm),
            (200, full),
            (200, incompatible),
            (401, serde_json::json!({})),
            (200, serde_json::json!({"ok":true,"kvm":true})),
        ];
        std::thread::scope(|scope| {
            for (status, body) in fixtures {
                let listener = TcpListener::bind("127.0.0.1:0").unwrap();
                state
                    .backends
                    .push(format!("http://{}", listener.local_addr().unwrap()));
                scope.spawn(move || {
                    let (mut stream, _) = listener.accept().unwrap();
                    let mut reader = BufReader::new(stream.try_clone().unwrap());
                    let line = read_bounded_line(&mut reader, MAX_REQUEST_LINE).unwrap();
                    assert_eq!(line, "GET /v1/capabilities HTTP/1.1\r\n");
                    let mut seen_backend = false;
                    loop {
                        let line = read_bounded_line(&mut reader, MAX_HEADER_LINE).unwrap();
                        if line.trim().is_empty() {
                            break;
                        }
                        if line.starts_with("Authorization:") {
                            assert_eq!(line, format!("Authorization: Bearer {BACKEND_TOKEN}\r\n"));
                            seen_backend = true;
                        }
                    }
                    assert!(seen_backend);
                    reply(&mut stream, status, &body).unwrap();
                });
            }
            let response = request(
                &state,
                "GET",
                "/v1/capabilities",
                &format!("Authorization: Bearer {CLIENT_TOKEN}\r\n"),
                "",
            );
            assert_eq!(parse_status(&response), 200);
            let report: serde_json::Value = serde_json::from_str(extract_body(&response)).unwrap();
            assert_eq!(report["eligibleNodes"], 1);
            assert_eq!(report["nodes"].as_array().unwrap().len(), 6);
            assert_eq!(report["artifactReadiness"], "not_checked");
            assert_eq!(report["nodes"][0]["report"]["persistentSessions"], false);
            assert!(!response.contains(BACKEND_TOKEN));
        });
        assert!(!state.capability_probe_active.load(Ordering::Acquire));
        state.capability_probe_active.store(true, Ordering::Release);
        assert_eq!(
            parse_status(&request(
                &state,
                "GET",
                "/v1/capabilities",
                &format!("Authorization: Bearer {CLIENT_TOKEN}\r\n"),
                ""
            )),
            503
        );
    }

    #[test]
    fn lost_acceptance_is_not_replayed_and_fresh_replica_recovers_owner() {
        let dir = tempfile::tempdir().unwrap();
        let mut first = state(dir.path());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let backend = format!("http://{}", listener.local_addr().unwrap());
        first.backends.push(backend.clone());
        let server = std::thread::spawn(move || {
            // Any second POST /v1/executions would violate this transcript.
            for (method, path, status) in [
                ("GET", "/v1/health", 200),
                ("POST", "/v1/executions", 0),
                ("GET", "/v1/executions/lost", 200),
                ("GET", "/v1/executions/lost", 200),
                ("GET", "/v1/executions/lost/audit", 200),
                ("POST", "/v1/executions/lost/cancel", 202),
            ] {
                let (mut stream, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                assert_eq!(
                    read_bounded_line(&mut reader, MAX_REQUEST_LINE).unwrap(),
                    format!("{method} {path} HTTP/1.1\r\n")
                );
                let mut length = 0;
                loop {
                    let line = read_bounded_line(&mut reader, MAX_HEADER_LINE).unwrap();
                    if line == "\r\n" {
                        break;
                    }
                    if let Some(n) = line.strip_prefix("Content-Length: ") {
                        length = n.trim().parse().unwrap();
                    }
                }
                let mut body = vec![0; length];
                reader.read_exact(&mut body).unwrap();
                if status == 0 {
                    continue;
                } // accepted backend work, lost reply
                let payload = if path == "/v1/health" {
                    r#"{"ok":true,"kvm":true}"#
                } else {
                    r#"{"requestId":"lost","phase":"Running"}"#
                };
                write!(stream,"HTTP/1.1 {status} OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",payload.len()).unwrap();
            }
        });
        let auth = format!("Authorization: Bearer {CLIENT_TOKEN}\r\n");
        let body = r#"{"id":"lost"}"#;
        let headers = format!("{auth}Content-Length: {}\r\n", body.len());
        assert_eq!(
            parse_status(&request(&first, "POST", "/v1/executions", &headers, body)),
            503
        );
        drop(first);
        let mut replica = state(dir.path());
        replica.backends = vec!["http://127.0.0.1:1".into(), backend];
        assert_eq!(
            parse_status(&request(&replica, "POST", "/v1/executions", &headers, body)),
            200
        );
        for path in ["/v1/executions/lost", "/v1/executions/lost/audit"] {
            assert_eq!(
                parse_status(&request(&replica, "GET", path, &auth, "")),
                200
            );
        }
        assert_eq!(
            parse_status(&request(
                &replica,
                "POST",
                "/v1/executions/lost/cancel",
                &auth,
                ""
            )),
            202
        );
        server.join().unwrap();
        // A lost node does not send this request to the spare backend.
        assert_eq!(
            parse_status(&request(&replica, "POST", "/v1/executions", &headers, body)),
            503
        );
        let changed = r#"{"id":"lost","task":"changed"}"#;
        assert_eq!(
            parse_status(&request(
                &replica,
                "POST",
                "/v1/executions",
                &format!("{auth}Content-Length: {}\r\n", changed.len()),
                changed
            )),
            409
        );
    }

    #[test]
    fn parent_affinity_survives_lost_create_and_gateway_restart() {
        let dir = tempfile::tempdir().unwrap();
        let mut first = state(dir.path());
        let parent_file = dir.path().join("parent-token");
        const PARENT: &str = "parent-principal-credential-at-least-24";
        std::fs::write(&parent_file, PARENT).unwrap();
        first.parent_token_file = Some(parent_file.clone());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let backend = format!("http://{}", listener.local_addr().unwrap());
        first.backends = vec![backend.clone()];
        let id = format!("blake3:{}", "a".repeat(64));
        let body = format!(
            r#"{{"apiVersion":"celln.parent-create/v1","launchProfile":"blake3:{}"}}"#,
            "b".repeat(64)
        );
        let headers = format!("Authorization: Bearer {CLIENT_TOKEN}\r\nX-Celln-Parent-Incarnation: {id}\r\nContent-Length: {}\r\n", body.len());
        let owner_id = id.clone();
        let server = std::thread::spawn(move || {
            for expected in [
                "GET /v1/health".to_string(),
                "POST /v1/parents".to_string(),
                format!("GET /v1/parents/{owner_id}"),
                format!("POST /v1/parents/{owner_id}/turns"),
            ] {
                let (mut stream, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let line = read_bounded_line(&mut reader, MAX_REQUEST_LINE).unwrap();
                assert!(line.starts_with(&format!("{expected} HTTP/1.1")), "{line}");
                let mut credential = String::new();
                let mut length = 0;
                let mut async_header = false;
                loop {
                    let h = read_bounded_line(&mut reader, MAX_HEADER_LINE).unwrap();
                    if h.trim().is_empty() {
                        break;
                    }
                    if h.starts_with("Authorization:") {
                        credential = h.clone();
                    }
                    if h.starts_with("Content-Length:") {
                        length = h
                            .split_once(':')
                            .unwrap()
                            .1
                            .trim()
                            .parse::<usize>()
                            .unwrap();
                    }
                    if h == "Prefer: respond-async\r\n" {
                        async_header = true;
                    }
                }
                let mut bytes = vec![0; length];
                reader.read_exact(&mut bytes).unwrap();
                if expected == "GET /v1/health" {
                    assert_eq!(
                        credential,
                        format!("Authorization: Bearer {BACKEND_TOKEN}\r\n")
                    );
                    reply(&mut stream, 200, &serde_json::json!({"ok":true,"kvm":true})).unwrap();
                } else {
                    assert_eq!(credential, format!("Authorization: Bearer {PARENT}\r\n"));
                    if expected == "POST /v1/parents" {
                        // Owner accepted; its acknowledgement is lost.
                        continue;
                    }
                    if expected.ends_with("/turns") {
                        assert!(async_header);
                    }
                    reply(&mut stream, 200, &serde_json::json!({"incarnation":owner_id,"status":"Ready","retryAuthorized":false})).unwrap();
                }
            }
        });
        assert_eq!(
            parse_status(&request(&first, "POST", "/v1/parents", &headers, &body)),
            502
        );
        drop(first);
        let mut replica = state(dir.path());
        replica.parent_token_file = Some(parent_file);
        replica.backends = vec![backend];
        assert_eq!(
            parse_status(&request(&replica, "POST", "/v1/parents", &headers, &body)),
            409
        );
        let auth = format!("Authorization: Bearer {CLIENT_TOKEN}\r\n");
        assert_eq!(
            parse_status(&request(
                &replica,
                "GET",
                &format!("/v1/parents/{id}"),
                &auth,
                ""
            )),
            200
        );
        assert_eq!(
            parse_status(&request(
                &replica,
                "POST",
                &format!("/v1/parents/{id}/turns"),
                &format!("{auth}Prefer: respond-async\r\nContent-Length: 2\r\n"),
                "{}"
            )),
            200
        );
        server.join().unwrap();
        replica.backends = vec!["http://127.0.0.1:1".into()];
        assert_eq!(
            parse_status(&request(
                &replica,
                "GET",
                &format!("/v1/parents/{id}"),
                &auth,
                ""
            )),
            503
        );
        assert_eq!(
            parse_status(&request(&replica, "POST", "/v1/parents", &headers, &body)),
            409
        );
    }

    #[test]
    fn parent_routes_refuse_discovery_credentials_and_malformed_identity() {
        let dir = tempfile::tempdir().unwrap();
        let mut owner = state(dir.path());
        let parent = dir.path().join("parent");
        std::fs::write(&parent, "parent-owner-credential-at-least-24").unwrap();
        owner.parent_token_file = Some(parent.clone());
        let discovery = dir.path().join("discovery");
        const DISCOVERY: &str = "discovery-credential-at-least-24";
        std::fs::write(&discovery, DISCOVERY).unwrap();
        owner.capability_token_file = Some(discovery);
        let id = format!("blake3:{}", "a".repeat(64));
        for path in [
            "/v1/parents".into(),
            format!("/v1/parents/{id}"),
            format!("/v1/parents/{id}/turns"),
        ] {
            assert_eq!(
                parse_status(&request(
                    &owner,
                    "POST",
                    &path,
                    &format!("Authorization: Bearer {DISCOVERY}\r\n"),
                    ""
                )),
                401
            );
        }
        for headers in [
            String::new(),
            "X-Celln-Parent-Incarnation: ../../escape\r\n".into(),
            format!("X-Celln-Parent-Incarnation: {id}\r\nX-Celln-Parent-Incarnation: {id}\r\n"),
        ] {
            assert_eq!(
                parse_status(&request(
                    &owner,
                    "POST",
                    "/v1/parents",
                    &format!("Authorization: Bearer {CLIENT_TOKEN}\r\n{headers}"),
                    ""
                )),
                400
            );
        }
        assert!(owner.parents.lookup(&id).unwrap().is_none());
        std::fs::write(parent, DISCOVERY).unwrap();
        assert_eq!(
            parse_status(&request(
                &owner,
                "GET",
                &format!("/v1/parents/{id}"),
                &format!("Authorization: Bearer {CLIENT_TOKEN}\r\n"),
                ""
            )),
            503
        );
    }

    fn state(dir: &Path) -> RouterState {
        let client_token_file = dir.join("client");
        let token_file = dir.join("backend");
        std::fs::write(&client_token_file, CLIENT_TOKEN).unwrap();
        std::fs::write(&token_file, BACKEND_TOKEN).unwrap();
        RouterState {
            backends: vec![],
            mode: RoutingMode::RoundRobin,
            cursor: AtomicUsize::new(0),
            executions: ownership::Ledger::open(&dir.join("ownership"), 100).unwrap(),
            parents: ownership::Ledger::open(&dir.join("ownership/parents"), 100).unwrap(),
            parent_token_file: None,
            token_file,
            client_token_file,
            capability_token_file: None,
            capability_probe_active: AtomicBool::new(false),
        }
    }

    #[test]
    fn pinned_prewarm_and_submission_keep_exact_owner_without_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let mut first = state(dir.path());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let backend = format!("http://{}", listener.local_addr().unwrap());
        let spare = TcpListener::bind("127.0.0.1:0").unwrap();
        spare.set_nonblocking(true).unwrap();
        let spare_url = format!("http://{}", spare.local_addr().unwrap());
        first.backends = vec![spare_url.clone(), backend.clone()];
        let body = r#"{"id":"pinned","unchanged":"exact bytes"}"#;
        let server = std::thread::spawn(move || {
            for (method, path, status) in [
                ("POST", "/v1/artifacts/prewarm", 200),
                ("POST", "/v1/executions", 0),
                ("GET", "/v1/executions/pinned", 200),
            ] {
                let deadline = std::time::Instant::now() + Duration::from_secs(10);
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(
                                std::time::Instant::now() < deadline,
                                "expected {method} {path}"
                            );
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        Err(e) => panic!("accept: {e}"),
                    }
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                assert_eq!(
                    read_bounded_line(&mut reader, MAX_REQUEST_LINE).unwrap(),
                    format!("{method} {path} HTTP/1.1\r\n")
                );
                let mut length = 0;
                let mut auth = false;
                loop {
                    let line = read_bounded_line(&mut reader, MAX_HEADER_LINE).unwrap();
                    if line == "\r\n" {
                        break;
                    }
                    if line == format!("Authorization: Bearer {BACKEND_TOKEN}\r\n") {
                        auth = true;
                    }
                    assert!(!line.to_ascii_lowercase().starts_with("x-celln-backend:"));
                    if let Some(n) = line.strip_prefix("Content-Length: ") {
                        length = n.trim().parse().unwrap();
                    }
                }
                assert!(auth, "router must use backend credential, not caller token");
                let mut bytes = vec![0; length];
                reader.read_exact(&mut bytes).unwrap();
                if method == "POST" {
                    assert_eq!(bytes, body.as_bytes());
                }
                if status == 0 {
                    continue;
                }
                let payload = r#"{"observation":"unchanged"}"#;
                write!(stream, "HTTP/1.1 {status} OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}", payload.len()).unwrap();
            }
        });
        let headers = format!("Authorization: Bearer {CLIENT_TOKEN}\r\nX-Celln-Backend: {backend}\r\nContent-Length: {}\r\n", body.len());
        let observed = request(&first, "POST", "/v1/artifacts/prewarm", &headers, body);
        assert_eq!(parse_status(&observed), 200);
        assert!(observed.ends_with(r#"{"observation":"unchanged"}"#));
        assert!(
            first.executions.lookup("pinned").unwrap().is_none(),
            "prewarm must not claim an execution"
        );
        assert_eq!(
            parse_status(&request(&first, "POST", "/v1/executions", &headers, body)),
            503
        );
        assert_eq!(
            first.executions.lookup("pinned").unwrap().unwrap().backend,
            backend
        );
        drop(first);
        let mut replica = state(dir.path());
        replica.backends = vec![backend.clone(), spare_url.clone()];
        let changed_pin = headers.replace(&backend, &spare_url);
        assert_eq!(
            parse_status(&request(
                &replica,
                "POST",
                "/v1/executions",
                &changed_pin,
                body
            )),
            409
        );
        assert_eq!(
            parse_status(&request(&replica, "POST", "/v1/executions", &headers, body)),
            200
        );
        server.join().unwrap();
        let unavailable_body = r#"{"id":"unavailable"}"#;
        let unavailable_headers = format!("Authorization: Bearer {CLIENT_TOKEN}\r\nX-Celln-Backend: {backend}\r\nContent-Length: {}\r\n", unavailable_body.len());
        assert_eq!(
            parse_status(&request(
                &replica,
                "POST",
                "/v1/executions",
                &unavailable_headers,
                unavailable_body
            )),
            503
        );
        assert_eq!(
            replica
                .executions
                .lookup("unavailable")
                .unwrap()
                .unwrap()
                .backend,
            backend
        );
        assert_eq!(
            parse_status(&request(
                &replica,
                "POST",
                "/v1/artifacts/prewarm",
                &headers,
                body
            )),
            503
        );
        assert_eq!(
            parse_status(&request(&replica, "POST", "/v1/executions", &headers, body)),
            503
        );
        assert!(matches!(spare.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock));
    }

    #[test]
    fn backend_pin_refuses_untrusted_ambiguous_and_unbounded_requests() {
        const READ_TOKEN: &str = "read-only-pinned-test-credential-24";
        let dir = tempfile::tempdir().unwrap();
        let mut state = state(dir.path());
        state.backends = vec!["http://127.0.0.1:1".into()];
        let auth = format!("Authorization: Bearer {CLIENT_TOKEN}\r\n");
        let pin = "X-Celln-Backend: http://127.0.0.1:1\r\n";
        for (method, path, headers, status) in [
            (
                "POST",
                "/v1/artifacts/prewarm",
                format!("{pin}Content-Length: 2\r\n"),
                401,
            ),
            (
                "POST",
                "/v1/artifacts/prewarm",
                format!("{auth}Content-Length: 2\r\n"),
                400,
            ),
            (
                "POST",
                "/v1/artifacts/prewarm",
                format!("{auth}{pin}{pin}Content-Length: 2\r\n"),
                400,
            ),
            (
                "POST",
                "/v1/artifacts/prewarm",
                format!(
                    "{auth}X-Celln-Backend: http://unconfigured.invalid\r\nContent-Length: 2\r\n"
                ),
                400,
            ),
            (
                "POST",
                "/v1/artifacts/prewarm",
                format!("{auth}{pin}Content-Length: 65537\r\n"),
                413,
            ),
            (
                "POST",
                "/v1/artifacts/prewarm",
                format!("{auth}{pin}Content-Length: 0\r\n"),
                413,
            ),
            ("GET", "/v1/executions/pinned", format!("{auth}{pin}"), 400),
            (
                "POST",
                "/v1/executions/pinned/cancel",
                format!("{auth}{pin}"),
                400,
            ),
        ] {
            assert_eq!(
                parse_status(&request(&state, method, path, &headers, "{}")),
                status
            );
        }
        let read_file = dir.path().join("read-token");
        std::fs::write(&read_file, READ_TOKEN).unwrap();
        state.capability_token_file = Some(read_file);
        assert_eq!(
            parse_status(&request(
                &state,
                "POST",
                "/v1/artifacts/prewarm",
                &format!("Authorization: Bearer {READ_TOKEN}\r\n{pin}Content-Length: 2\r\n"),
                "{}"
            )),
            401
        );
        assert!(state.executions.lookup("pinned").unwrap().is_none());
    }

    // Actual TCP request parsing/forwarding; backend is a protocol fixture,
    // deliberately not a KVM/isolation proof.
    fn request(state: &RouterState, method: &str, path: &str, headers: &str, body: &str) -> String {
        std::thread::scope(|scope| {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let server = scope.spawn(move || handle(listener.accept().unwrap().0, state));
            write!(client, "{method} {path} HTTP/1.1\r\n{headers}\r\n{body}").unwrap();
            let mut response = String::new();
            client.read_to_string(&mut response).unwrap();
            drop(client);
            server.join().unwrap().unwrap();
            response
        })
    }

    #[test]
    fn unauthorized_buffered_body_receives_complete_response_without_reset() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(dir.path());
        std::thread::scope(|scope| {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let (ready, sent) = std::sync::mpsc::channel();
            let server = scope.spawn(move || {
                let stream = listener.accept().unwrap().0;
                sent.recv().unwrap();
                handle(stream, &state)
            });
            // Queue more than BufReader can prefetch before the server reads
            // headers. Early auth refusal must not reset unread body bytes.
            let body = vec![b'x'; 32768];
            write!(
                client,
                "POST /v1/executions HTTP/1.1\r\nHost: router\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .unwrap();
            client.write_all(&body).unwrap();
            client.shutdown(std::net::Shutdown::Write).unwrap();
            ready.send(()).unwrap();
            let mut response = String::new();
            let result = client.read_to_string(&mut response);
            server.join().unwrap().unwrap();
            assert!(result.is_ok(), "refusal response reset: {result:?}");
            assert_eq!(parse_status(&response), 401);
            assert_eq!(extract_body(&response), r#"{"error":"unauthorized"}"#);
        });
    }

    #[test]
    fn response_tail_drain_has_a_total_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        client
            .set_write_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let (mut server, _) = listener.accept().unwrap();
        let (done, completed) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            finish_response(&mut server);
            done.send(()).unwrap();
        });
        let writer = std::thread::spawn(move || {
            for _ in 0..100 {
                if client.write_all(b"x").is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        });
        completed
            .recv_timeout(Duration::from_millis(750))
            .expect("slow body extended the total drain deadline");
        worker.join().unwrap();
        writer.join().unwrap();
    }

    #[test]
    fn inbound_auth_is_required_on_submission_poll_audit_and_cancel() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(dir.path());
        // Empty backend list would panic on submission if authorization were
        // bypassed. No backend can be contacted by these requests.
        for (method, path) in [
            ("POST", "/v1/executions"),
            ("GET", "/v1/executions/x"),
            ("GET", "/v1/executions/x/audit"),
            ("POST", "/v1/executions/x/cancel"),
        ] {
            for header in [
                String::new(),
                "Authorization: Bearer wrong\r\n".into(),
                format!("Authorization: Bearer {BACKEND_TOKEN}\r\n"),
            ] {
                assert_eq!(
                    parse_status(&request(&state, method, path, &header, "")),
                    401
                );
            }
        }
        let header = format!("authorization: bEaReR {CLIENT_TOKEN}\r\n");
        assert_eq!(
            parse_status(&request(&state, "GET", "/v1/executions/x", &header, "")),
            404
        );
    }

    #[test]
    fn credential_rotation_and_bad_files_fail_closed_without_restart() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(dir.path());
        let old = format!("Authorization: Bearer {CLIENT_TOKEN}\r\n");
        let new_token = "rotated-client-credential-at-least-24";
        std::fs::write(&state.client_token_file, new_token).unwrap();
        assert_eq!(
            parse_status(&request(&state, "GET", "/v1/executions/x", &old, "")),
            401
        );
        let new = format!("Authorization: Bearer {new_token}\r\n");
        assert_eq!(
            parse_status(&request(&state, "GET", "/v1/executions/x", &new, "")),
            404
        );
        for invalid in [
            "short",
            "credential contains whitespace and is long",
            BACKEND_TOKEN,
        ] {
            std::fs::write(&state.client_token_file, invalid).unwrap();
            assert_eq!(
                parse_status(&request(&state, "GET", "/v1/executions/x", &new, "")),
                503
            );
        }
        std::fs::remove_file(&state.client_token_file).unwrap();
        assert!(credentials(&state).is_err());
        assert_eq!(
            parse_status(&request(&state, "GET", "/v1/executions/x", &old, "")),
            503
        );
    }

    #[test]
    fn ambiguous_headers_and_cancel_bodies_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(dir.path());
        let auth = format!("Authorization: Bearer {CLIENT_TOKEN}\r\n");
        for extra in [
            auth.clone(),
            "Content-Length: 0\r\ncontent-length: 0\r\n".into(),
            "Transfer-Encoding: chunked\r\n".into(),
            "Content-Length: -1\r\n".into(),
        ] {
            assert_eq!(
                parse_status(&request(
                    &state,
                    "POST",
                    "/v1/executions/x/cancel",
                    &(auth.clone() + &extra),
                    ""
                )),
                400
            );
        }
        assert_eq!(
            parse_status(&request(
                &state,
                "POST",
                "/v1/executions/x/cancel",
                &(auth + "Content-Length: 1\r\n"),
                "x"
            )),
            400
        );
    }

    #[test]
    fn unaddressable_ids_refuse_before_submission() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(dir.path());
        for id in ["", ".", "..", "a/b", "a?b", "a b", "a%2fb"] {
            let body = serde_json::json!({"id":id}).to_string();
            let headers = format!(
                "Authorization: Bearer {CLIENT_TOKEN}\r\nContent-Length: {}\r\n",
                body.len()
            );
            assert_eq!(
                parse_status(&request(&state, "POST", "/v1/executions", &headers, &body)),
                400
            );
        }
    }

    #[test]
    fn submission_poll_audit_and_cancel_use_only_rotatable_backend_credential() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = state(dir.path());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        state
            .backends
            .push(format!("http://{}", listener.local_addr().unwrap()));
        let server = std::thread::spawn(move || {
            for (method, path, status, payload, token) in [
                (
                    "GET",
                    "/v1/health",
                    200,
                    r#"{"ok":true,"kvm":true}"#,
                    BACKEND_TOKEN,
                ),
                (
                    "POST",
                    "/v1/executions",
                    202,
                    r#"{"requestId":"x","phase":"Running"}"#,
                    BACKEND_TOKEN,
                ),
                (
                    "GET",
                    "/v1/executions/x",
                    200,
                    r#"{"requestId":"x","phase":"Running"}"#,
                    BACKEND_TOKEN,
                ),
                (
                    "GET",
                    "/v1/executions/x/audit",
                    200,
                    r#"{"requestId":"x"}"#,
                    BACKEND_TOKEN,
                ),
                (
                    "POST",
                    "/v1/executions/x/cancel",
                    202,
                    r#"{"requestId":"x","phase":"Cancelling"}"#,
                    "rotated-backend-credential-at-least-24",
                ),
                (
                    "POST",
                    "/v1/executions/x/cancel",
                    200,
                    r#"{"requestId":"x","phase":"Cancelled"}"#,
                    "rotated-backend-credential-at-least-24",
                ),
            ] {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                assert_eq!(
                    read_bounded_line(&mut reader, MAX_REQUEST_LINE).unwrap(),
                    format!("{method} {path} HTTP/1.1\r\n")
                );
                let mut headers = String::new();
                let mut length = 0;
                loop {
                    let header = read_bounded_line(&mut reader, MAX_HEADER_LINE).unwrap();
                    if header == "\r\n" {
                        break;
                    }
                    if let Some(value) = header.strip_prefix("Content-Length: ") {
                        length = value.trim().parse().unwrap();
                    }
                    headers.push_str(&header);
                }
                assert!(headers.contains(&format!("Authorization: Bearer {token}\r\n")));
                assert!(!headers.contains(CLIENT_TOKEN));
                let mut body = vec![0; length];
                reader.read_exact(&mut body).unwrap();
                if path.ends_with("/cancel") {
                    assert!(body.is_empty());
                }
                write!(stream, "HTTP/1.1 {status} OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}", payload.len()).unwrap();
            }
        });
        let auth = format!("Authorization: Bearer {CLIENT_TOKEN}\r\n");
        let body = r#"{"id":"x"}"#;
        assert_eq!(
            parse_status(&request(
                &state,
                "POST",
                "/v1/executions",
                &format!("{auth}Content-Length: {}\r\n", body.len()),
                body
            )),
            202
        );
        for path in ["/v1/executions/x", "/v1/executions/x/audit"] {
            assert_eq!(parse_status(&request(&state, "GET", path, &auth, "")), 200);
        }
        std::fs::write(&state.token_file, "rotated-backend-credential-at-least-24").unwrap();
        for (status, phase) in [(202, "Cancelling"), (200, "Cancelled")] {
            let response = request(&state, "POST", "/v1/executions/x/cancel", &auth, "");
            assert_eq!(parse_status(&response), status);
            assert!(response.contains(phase));
        }
        assert_eq!(
            parse_status(&request(
                &state,
                "POST",
                "/v1/executions/absent/cancel",
                &auth,
                ""
            )),
            404
        );
        server.join().unwrap();
    }
}
