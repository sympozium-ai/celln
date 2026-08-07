//! Thin stateless router that distributes actions across Celln dispatcher
//! backends. Each backend is a Celln process with a `/v1/health` endpoint that
//! reports KVM availability. The router picks a backend, checks its health,
//! and forwards if healthy; otherwise it tries the next.
//!
//! The router is intentionally not a load tracker. It relies on per-node
//! admission ("can this node spawn another cell?") via the health check.
//! One accepted request = one warden = one cell — no multiplexing.

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const ROUTER_TOKEN_BYTES: usize = 24;

/// How the router selects a dispatcher backend for each action.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum RoutingMode {
    /// Cycle through backends deterministically, skipping unhealthy ones.
    RoundRobin,
    /// Pick a backend at random; fall through to the next if unhealthy.
    Random,
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
    token_file: Option<&Path>,
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
            Err(e) => eprintln!(
                "celln route: warning: could not resolve {addr}: {e}"
            ),
        }
    }

    if urls.is_empty() {
        bail!("at least one dispatcher backend URL is required (--backends or --backends-srv)");
    }
    let token = match token_file {
        Some(path) => {
            let t = std::fs::read_to_string(path)
                .with_context(|| format!("reading router token {}", path.display()))?
                .trim()
                .to_owned();
            if t.len() < ROUTER_TOKEN_BYTES {
                bail!("router token must contain at least {ROUTER_TOKEN_BYTES} non-whitespace bytes");
            }
            Some(t)
        }
        None => None,
    };
    let listener =
        TcpListener::bind(listen).with_context(|| format!("binding router {listen}"))?;
    let state = Arc::new(RouterState {
        backends: urls.clone(),
        mode,
        cursor: AtomicUsize::new(0),
        actions: Mutex::new(HashMap::new()),
        token,
    });
    eprintln!("celln route listening on {listen} ({} backends, {mode:?})", urls.len());
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
    actions: Mutex<HashMap<String, String>>,
    token: Option<String>,
}

fn handle(mut stream: TcpStream, state: &RouterState) -> Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    let Some((method, raw_path)) = request_line.trim_end().split_once(' ') else {
        return reply(&mut stream, 400, &serde_json::json!({"error":"malformed request line"}));
    };
    let path = raw_path.split_whitespace().next().unwrap_or_default();

    let mut length = 0usize;
    loop {
        let mut header = String::new();
        reader.read_line(&mut header)?;
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        if let Some(value) = header.strip_prefix("Content-Length: ") {
            length = value.parse().context("invalid Content-Length")?;
        }
    }

    match (method, path) {
        ("POST", "/v1/actions") => {
            if length == 0 || length > 64 * 1024 {
                return reply(
                    &mut stream,
                    413,
                    &serde_json::json!({"error":"request body exceeds 64 KiB or is empty"}),
                );
            }
            let mut body = vec![0; length];
            reader.read_exact(&mut body)?;

            let action_id = extract_action_id(&body)?;

            let backend = pick_backend(state)?;
            let resp = forward_post(&backend, "/v1/actions", &body, &state.token)?;
            let status = parse_status(&resp);

            // Track which backend owns this action so GET can find it.
            if status == 202 || status == 200 {
                state
                    .actions
                    .lock()
                    .expect("router action map not poisoned")
                    .insert(action_id, backend);
            }

            raw_reply(&mut stream, &resp)?;
        }
        ("GET", path) if path.starts_with("/v1/actions/") => {
            let id = path.trim_start_matches("/v1/actions/");
            let backend = state
                .actions
                .lock()
                .expect("router action map not poisoned")
                .get(id)
                .cloned();
            match backend {
                Some(backend_url) => {
                    let resp = forward_get(&backend_url, path, &state.token)?;
                    raw_reply(&mut stream, &resp)?;
                }
                None => {
                    reply(
                        &mut stream,
                        404,
                        &serde_json::json!({"error":"unknown action"}),
                    )?;
                }
            }
        }
        _ => {
            reply(&mut stream, 404, &serde_json::json!({"error":"not found"}))?;
        }
    }
    Ok(())
}

fn pick_backend(state: &RouterState) -> Result<String> {
    let n = state.backends.len();
    let start = match state.mode {
        RoutingMode::RoundRobin => state.cursor.fetch_add(1, Ordering::Relaxed) % n,
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
            if is_healthy(backend, &state.token)? {
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
        write!(stream, "GET {path} HTTP/1.1\r\nHost: {backend}\r\nConnection: close\r\n\r\n")?;
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
    let host = backend
        .trim_start_matches("http://")
        .trim_start_matches("https://");
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
    let mut reader = BufReader::new(stream);
    let mut response = String::new();

    // Status line.
    let mut line = String::new();
    reader.read_line(&mut line)?;
    response.push_str(&line);

    // Headers.
    loop {
        let mut header = String::new();
        reader.read_line(&mut header)?;
        response.push_str(&header);
        if header == "\r\n" || header == "\n" {
            break;
        }
    }

    // Body: read until connection closes.
    let mut body = Vec::new();
    reader.read_to_end(&mut body)?;
    response.push_str(&String::from_utf8_lossy(&body));

    Ok(response)
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

fn extract_action_id(body: &[u8]) -> Result<String> {
    let v: serde_json::Value = serde_json::from_slice(body).context("parsing action body")?;
    v.get("id")
        .and_then(|id| id.as_str())
        .map(str::to_string)
        .context("action body missing required 'id' field")
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
