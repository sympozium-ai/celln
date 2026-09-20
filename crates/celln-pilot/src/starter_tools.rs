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
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListInput {}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SearchInput {
    pattern: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeleteInput {
    name: String,
    revision: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PostInput {
    url: String,
    /// A JSON object as text: tool schemas are closed, so the body cannot be
    /// declared as a free-form object. The host validates the URL and host.
    body: String,
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
        "list" => {
            let ListInput {} = serde_json::from_slice(input)?;
            json!({"operation":"list"})
        }
        "append" => {
            let input: WriteInput = serde_json::from_slice(input)?;
            json!({"operation":"append", "name":input.name,"revision":input.revision,"content":input.content})
        }
        "search" => {
            let input: SearchInput = serde_json::from_slice(input)?;
            json!({"operation":"search", "pattern":input.pattern})
        }
        "delete" => {
            let input: DeleteInput = serde_json::from_slice(input)?;
            json!({"operation":"delete", "name":input.name,"revision":input.revision})
        }
        "post" => {
            let input: PostInput = serde_json::from_slice(input)?;
            // Plain HTTP is only ever honoured by a host that opted in for a
            // private endpoint; the broker decides, the guest just carries it.
            ensure!(
                (input.url.starts_with("https://") || input.url.starts_with("http://"))
                    && input.url.len() <= 2048
                    && !input.url.contains('\0'),
                "invalid URL"
            );
            let body: Value = serde_json::from_str(&input.body)?;
            ensure!(body.is_object(), "body must be a JSON object");
            let wire = serde_json::to_vec(
                &json!({"apiVersion":"celln.fetch/v1","method":"POST","url":input.url,"body":body}),
            )?;
            ensure!(wire.len() <= 8192, "POST request exceeds wire limit");
            return Ok((vec!["--json-stdin".into()], wire));
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

    #[test]
    fn workspace_operations_and_json_posts_carry_only_declared_fields() {
        let (_, wire) = request("list", b"{}").unwrap();
        let value: Value = serde_json::from_slice(&wire).unwrap();
        assert_eq!(value["body"], serde_json::json!({"operation":"list"}));
        assert!(request("list", br#"{"name":"x"}"#).is_err());
        let (_, wire) = request(
            "append",
            br#"{"name":"log.txt","revision":2,"content":"violet\n"}"#,
        )
        .unwrap();
        let value: Value = serde_json::from_slice(&wire).unwrap();
        assert_eq!(value["body"]["operation"], "append");
        assert_eq!(value["body"]["revision"], 2);
        let (_, wire) = request("search", br#"{"pattern":"vio"}"#).unwrap();
        let value: Value = serde_json::from_slice(&wire).unwrap();
        assert_eq!(value["body"]["pattern"], "vio");
        let (_, wire) = request("delete", br#"{"name":"log.txt","revision":3}"#).unwrap();
        let value: Value = serde_json::from_slice(&wire).unwrap();
        assert_eq!(
            value["body"],
            serde_json::json!({"operation":"delete","name":"log.txt","revision":3})
        );
        assert!(request("delete", br#"{"name":"log.txt"}"#).is_err());
        let (args, wire) = request(
            "post",
            br#"{"url":"https://hooks.example/in","body":"{\"event\":\"done\",\"n\":2}"}"#,
        )
        .unwrap();
        assert_eq!(args, ["--json-stdin"]);
        let value: Value = serde_json::from_slice(&wire).unwrap();
        assert_eq!(value["apiVersion"], "celln.fetch/v1");
        assert_eq!(value["method"], "POST");
        assert_eq!(value["body"], serde_json::json!({"event":"done","n":2}));
        // Not an object, not a URL, or a URL that is really an option: refused.
        assert!(request(
            "post",
            br#"{"url":"https://hooks.example/in","body":"[1]"}"#
        )
        .is_err());
        assert!(request("post", br#"{"url":"--config=/x","body":"{}"}"#).is_err());
        assert!(request("post", br#"{"url":"ftp://hooks.example/in","body":"{}"}"#).is_err());
    }
}
