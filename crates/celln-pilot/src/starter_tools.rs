//! Signed guest tool entrypoints. No host paths, shell, credentials or direct
//! sockets: all effects go through independently granted host broker requests.
use anyhow::{ensure, Result};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{io::Read, time::Duration};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadInput {
    name: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WriteInput {
    name: String,
    revision: u64,
    content: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FetchInput {
    url: String,
}

fn request(kind: &str, input: &[u8]) -> Result<(Vec<String>, Vec<u8>)> {
    let body = match kind {
        "read" => {
            let input: ReadInput = serde_json::from_slice(input)?;
            json!({"operation":"read", "name":input.name})
        }
        "write" => {
            let input: WriteInput = serde_json::from_slice(input)?;
            json!({"operation":"write", "name":input.name,"revision":input.revision,"content":input.content})
        }
        "fetch" => {
            let input: FetchInput = serde_json::from_slice(input)?;
            ensure!(
                input.url.starts_with("https://")
                    && input.url.len() <= 8192
                    && !input.url.contains('\0'),
                "invalid HTTPS URL"
            );
            return Ok((vec![input.url], vec![]));
        }
        _ => anyhow::bail!("unknown starter tool"),
    };
    let wire = serde_json::to_vec(&json!({"apiVersion":"celln.workspace/v1","body":body}))?;
    ensure!(wire.len() <= 8192, "workspace request exceeds wire limit");
    Ok((vec!["--json-stdin".into()], wire))
}

fn run(kind: &str) -> Result<Value> {
    let mut input = Vec::new();
    std::io::stdin().take(8193).read_to_end(&mut input)?;
    ensure!(input.len() <= 8192, "tool input exceeds limit");
    let (args, wire) = request(kind, &input)?;
    let result =
        crate::harness_io::child("/pilot-fetch", &args, &wire, 65536, Duration::from_secs(30))?;
    if kind == "fetch" {
        Ok(json!({"content":std::str::from_utf8(&result)?}))
    } else {
        Ok(serde_json::from_slice(&result)?)
    }
}

pub fn main(kind: &str) {
    // Tool errors are data for the model, not fabricated success or a retry.
    let output = run(kind).unwrap_or_else(|error| json!({"error":error.to_string()}));
    println!("{output}");
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn strict_inputs_cannot_choose_a_host_path_command_or_identity() {
        assert!(request("read", br#"{"name":"note.txt","parent":"other"}"#).is_err());
        assert!(request("fetch", br#"{"url":"--config=/secret"}"#).is_err());
        assert!(request("write", br#"{"name":"note.txt","content":"x"}"#).is_err());
        let (args, wire) = request(
            "write",
            br#"{"name":"note.txt","revision":0,"content":"violet"}"#,
        )
        .unwrap();
        assert_eq!(args, ["--json-stdin"]);
        let value: Value = serde_json::from_slice(&wire).unwrap();
        assert_eq!(value["apiVersion"], "celln.workspace/v1");
        assert_eq!(value["body"]["content"], "violet");
    }
}
