//! Authenticated local dispatcher for real Celln agent actions.
//!
//! This service is intentionally a Celln process, not a Kubernetes Job
//! wrapper. Every submitted action is executed by the existing KVM/Pilot path.
//! It is the first transport seam; immutable bundle/receipt publication remains
//! a separate required stage before upstream controllers may claim completion.

use crate::agent::Backend;
use anyhow::{bail, Context, Result};
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

type Actions = Arc<Mutex<HashMap<String, ActionStatus>>>;

pub fn serve(listen: &str, token_file: &Path, root: PathBuf) -> Result<u8> {
    let token = std::fs::read_to_string(token_file)
        .with_context(|| format!("reading dispatcher token {}", token_file.display()))?
        .trim()
        .to_owned();
    if token.len() < 24 {
        bail!("dispatcher token must contain at least 24 non-whitespace bytes");
    }
    let listener =
        TcpListener::bind(listen).with_context(|| format!("binding dispatcher {listen}"))?;
    let actions: Actions = Arc::new(Mutex::new(HashMap::new()));
    eprintln!("celln dispatcher listening on {listen}");
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let actions = Arc::clone(&actions);
                let token = token.clone();
                let root = root.clone();
                thread::spawn(move || {
                    if let Err(error) = handle(stream, &token, actions, root) {
                        eprintln!("dispatcher request failed: {error:#}");
                    }
                });
            }
            Err(error) => eprintln!("dispatcher accept failed: {error}"),
        }
    }
    Ok(crate::exit::OK)
}

fn handle(mut stream: TcpStream, token: &str, actions: Actions, root: PathBuf) -> Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    let Some((method, path)) = request_line.trim_end().split_once(' ') else {
        return reply(
            &mut stream,
            400,
            &serde_json::json!({"error":"malformed request line"}),
        );
    };
    let path = path.split_whitespace().next().unwrap_or_default();
    let mut authorized = false;
    let mut length = 0usize;
    loop {
        let mut header = String::new();
        reader.read_line(&mut header)?;
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        if let Some(value) = header.strip_prefix("Authorization: Bearer ") {
            authorized = constant_time_eq(value.as_bytes(), token.as_bytes());
        }
        if let Some(value) = header.strip_prefix("Content-Length: ") {
            length = value.parse().context("invalid Content-Length")?;
        }
    }
    if !authorized && !(method == "GET" && path == "/v1/health") {
        return reply(
            &mut stream,
            401,
            &serde_json::json!({"error":"unauthorized"}),
        );
    }
    match (method, path) {
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
            let mut registry = actions.lock().expect("dispatcher registry not poisoned");
            if let Some(existing) = registry.get(&action.id) {
                return reply(&mut stream, 202, existing);
            }
            registry.insert(action.id.clone(), status.clone());
            drop(registry);
            let worker_actions = Arc::clone(&actions);
            thread::spawn(move || run_action(action, worker_actions, root));
            reply(&mut stream, 202, &status)
        }
        ("GET", path) if path.starts_with("/v1/actions/") => {
            let id = path.trim_start_matches("/v1/actions/");
            let registry = actions.lock().expect("dispatcher registry not poisoned");
            match registry.get(id) {
                Some(status) => reply(&mut stream, 200, status),
                None => reply(
                    &mut stream,
                    404,
                    &serde_json::json!({"error":"unknown action"}),
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

fn persist_output(actions: &Actions, id: &str, root: &Path) -> Result<()> {
    let output = actions
        .lock()
        .expect("dispatcher registry not poisoned")
        .get(id)
        .and_then(|status| status.output.clone())
        .ok_or_else(|| anyhow::anyhow!("successful action emitted no bounded output"))?;
    let store = Store::open(&root.join("outputs"))?;
    let hash = store.put(output.as_bytes())?;
    update(actions, id, |status| {
        status.output_hash = Some(hash.0);
        status.output_bytes = Some(output.len() as u64);
    });
    Ok(())
}

fn update(actions: &Actions, id: &str, f: impl FnOnce(&mut ActionStatus)) {
    if let Some(status) = actions
        .lock()
        .expect("dispatcher registry not poisoned")
        .get_mut(id)
    {
        f(status);
    }
}

fn fail(actions: &Actions, id: &str, error: String) {
    update(actions, id, |status| {
        status.phase = "Failed".into();
        status.error = Some(error);
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
