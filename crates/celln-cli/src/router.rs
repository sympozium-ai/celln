//! Authenticated router that distributes actions across Celln dispatcher
//! backends. Each backend is a Celln process with a `/v1/health` endpoint that
//! reports KVM availability. The router picks a backend, checks its health,
//! and forwards if healthy; otherwise it tries the next.
//!
//! The router is intentionally not a load tracker. It relies on per-node
//! admission ("can this node spawn another cell?") via the health check.
//! One accepted request = one warden = one cell — no multiplexing.

use crate::dispatch_http::{
    constant_time_eq, read_bounded_line, MAX_HEADER_COUNT, MAX_HEADER_LINE, MAX_REQUEST_LINE,
};
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::io::{BufReader, Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const ROUTER_TOKEN_BYTES: usize = 24;

// Credentials are bounded and never echoed in errors. Reload on each request
// to support atomic file/Secret rotation; an unreadable file fails closed.
fn read_token(path: &Path) -> Result<String> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(4097)
        .read_to_end(&mut bytes)?;
    let token = std::str::from_utf8(&bytes)?.trim();
    if bytes.len() > 4096
        || token.len() < ROUTER_TOKEN_BYTES
        || !token.bytes().all(|b| b.is_ascii_graphic())
    {
        bail!("invalid router credential");
    }
    Ok(token.to_owned())
}

fn credentials(state: &RouterState) -> Result<(String, String)> {
    let client = read_token(&state.client_token_file)?;
    let backend = read_token(&state.token_file)?;
    if constant_time_eq(client.as_bytes(), backend.as_bytes()) {
        bail!("client and dispatcher credentials must be distinct");
    }
    Ok((client, backend))
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

pub fn serve(
    listen: &str,
    backends: Vec<String>,
    backends_srv: Option<&str>,
    mode: RoutingMode,
    token_file: &Path,
    client_token_file: &Path,
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
        executions: Mutex::new(HashMap::new()),
        token_file: token_file.to_owned(),
        client_token_file: client_token_file.to_owned(),
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
    /// Which backend owns each in-flight `/v1/executions` id, so a later
    /// GET can find it.
    executions: Mutex<HashMap<String, String>>,
    token_file: PathBuf,
    client_token_file: PathBuf,
}

fn handle(mut stream: TcpStream, state: &RouterState) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let request_line = read_bounded_line(&mut reader, MAX_REQUEST_LINE)?;
    let Some((method, raw_path)) = request_line.trim_end().split_once(' ') else {
        return reply(
            &mut stream,
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
            return reply(
                &mut stream,
                400,
                &serde_json::json!({"error":"invalid header"}),
            );
        };
        if name.eq_ignore_ascii_case("authorization") {
            if authorization.is_some() {
                return reply(
                    &mut stream,
                    400,
                    &serde_json::json!({"error":"duplicate authorization"}),
                );
            }
            authorization = Some(value.trim().to_owned());
        } else if name.eq_ignore_ascii_case("content-length") {
            if seen_length || !value.trim().bytes().all(|b| b.is_ascii_digit()) {
                return reply(
                    &mut stream,
                    400,
                    &serde_json::json!({"error":"invalid content length"}),
                );
            }
            seen_length = true;
            let Ok(parsed) = value.trim().parse() else {
                return reply(
                    &mut stream,
                    400,
                    &serde_json::json!({"error":"invalid content length"}),
                );
            };
            length = parsed;
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            return reply(
                &mut stream,
                400,
                &serde_json::json!({"error":"transfer encoding unsupported"}),
            );
        }
    }

    let Ok((client_token, backend_token)) = credentials(state) else {
        return reply(
            &mut stream,
            503,
            &serde_json::json!({"error":"router credentials unavailable"}),
        );
    };
    let authorized = authorization
        .as_deref()
        .and_then(|value| {
            let (scheme, token) = value.split_once(' ')?;
            scheme.eq_ignore_ascii_case("bearer").then_some(token)
        })
        .is_some_and(|token| constant_time_eq(token.as_bytes(), client_token.as_bytes()));
    if !authorized {
        return reply(
            &mut stream,
            401,
            &serde_json::json!({"error":"unauthorized"}),
        );
    }
    let backend_token = Some(backend_token);
    match (method.as_str(), path.as_str()) {
        ("POST", "/v1/executions") => forward_submission(
            state,
            &mut stream,
            &mut reader,
            length,
            "/v1/executions",
            &state.executions,
            &backend_token,
        )?,
        ("POST", path) if execution_path_id(path, true).is_some() => {
            if length != 0 {
                return reply(
                    &mut stream,
                    400,
                    &serde_json::json!({"error":"cancel body must be empty"}),
                );
            }
            forward_existing(state, &mut stream, "POST", path, true, &backend_token)?;
        }
        ("GET", path) if execution_path_id(path, false).is_some() => {
            forward_existing(state, &mut stream, "GET", path, false, &backend_token)?
        }
        _ => {
            reply(&mut stream, 404, &serde_json::json!({"error":"not found"}))?;
        }
    }
    Ok(())
}

/// `POST <endpoint>`: pick a healthy backend deterministically by the
/// request's own `id` field, forward the body verbatim, and — on
/// acceptance — remember which backend owns that id so a later poll can
/// find it.
fn forward_submission(
    state: &RouterState,
    stream: &mut TcpStream,
    reader: &mut BufReader<TcpStream>,
    length: usize,
    endpoint: &str,
    tracker: &Mutex<HashMap<String, String>>,
    token: &Option<String>,
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

    let backend = pick_backend(state, &id, token)?;
    let resp = forward_post(&backend, endpoint, &body, token)?;
    let status = parse_status(&resp);

    if status == 202 || status == 200 {
        tracker
            .lock()
            .expect("router tracking map not poisoned")
            .insert(id, backend);
    }

    raw_reply(stream, &resp)
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
    let backend = state
        .executions
        .lock()
        .expect("router tracking map not poisoned")
        .get(id)
        .cloned();
    match backend {
        Some(backend_url) => {
            let resp = if method == "POST" {
                forward_post(&backend_url, path, &[], token)?
            } else {
                forward_get(&backend_url, path, token)?
            };
            raw_reply(stream, &resp)
        }
        None => reply(
            stream,
            404,
            &serde_json::json!({"error": "unknown execution"}),
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
        if is_healthy(backend, token)? {
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
    const MAX_RESPONSE: u64 = 16 * 1024 * 1024;
    let mut bytes = Vec::new();
    stream.take(MAX_RESPONSE + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_RESPONSE || !bytes.windows(4).any(|w| w == b"\r\n\r\n") {
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

    fn state(dir: &Path) -> RouterState {
        let client_token_file = dir.join("client");
        let token_file = dir.join("backend");
        std::fs::write(&client_token_file, CLIENT_TOKEN).unwrap();
        std::fs::write(&token_file, BACKEND_TOKEN).unwrap();
        RouterState {
            backends: vec![],
            mode: RoutingMode::RoundRobin,
            cursor: AtomicUsize::new(0),
            executions: Mutex::new(HashMap::new()),
            token_file,
            client_token_file,
        }
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
            if let Err(error) = client.read_to_string(&mut response) {
                // Early refusal may close with unread request bytes. Linux
                // then resets the connection after delivering the response.
                assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
                assert!(!response.is_empty());
            }
            server.join().unwrap().unwrap();
            response
        })
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
