//! Experimental in-cell reference loop, not a Pi/Hermes compatibility claim.
use anyhow::{bail, ensure, Context, Result};
use celln_manifest::Hash;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::process::{Command, Stdio};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Tool {
    name: String,
    path: String,
    hash: String,
    description: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    task: String,
    url: String,
    model: String,
    tools: Vec<Tool>,
}

fn bounded_child(path: &str, args: &[String], input: Option<&[u8]>) -> Result<Vec<u8>> {
    let mut command = Command::new(path);
    command
        .args(args)
        .env_clear()
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    // Avoid opening /dev/null inside the sealed root, where it is not lent.
    command.stdin(if input.is_some() {
        Stdio::piped()
    } else {
        Stdio::inherit()
    });
    let mut child = command.spawn().context("starting lent executable")?;
    let result = (|| -> Result<Vec<u8>> {
        if let Some(input) = input {
            child.stdin.take().context("stdin")?.write_all(input)?;
        }
        let mut output = Vec::new();
        child
            .stdout
            .take()
            .context("stdout")?
            .take(1_048_577)
            .read_to_end(&mut output)?;
        ensure!(output.len() <= 1_048_576, "child output exceeded limit");
        ensure!(child.wait()?.success(), "lent executable failed");
        Ok(output)
    })();
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    result
}

fn run() -> Result<()> {
    let config: Config =
        serde_json::from_str(&std::env::args().nth(1).context("missing host config")?)?;
    ensure!(
        config.tools.len() == 2,
        "reference proof requires exactly two lent tools"
    );
    let mut names = BTreeSet::new();
    for tool in &config.tools {
        ensure!(names.insert(&tool.name), "duplicate tool");
        ensure!(
            tool.path.starts_with('/') && Hash::of(&std::fs::read(&tool.path)?).0 == tool.hash,
            "lent tool identity mismatch"
        );
        ensure!(
            std::fs::OpenOptions::new()
                .write(true)
                .open(&tool.path)
                .is_err(),
            "lent code is writable"
        );
    }
    // These files exist in the signed filesystem but have no member grant.
    ensure!(
        std::fs::read("/unselected").is_err(),
        "unselected tool readable"
    );
    let refused = Command::new("/unselected")
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .status();
    ensure!(
        matches!(refused, Err(ref e) if e.raw_os_error() == Some(libc::EACCES)),
        "unselected executable not denied by confinement"
    );
    ensure!(
        std::fs::read("/provider-token").is_err(),
        "provider credential visible"
    );
    println!(
        "CELLN_HARNESS_EVENT {}",
        json!({"type":"negative-checks","unselected":"EACCES","toolWrites":"denied"})
    );
    for (field, value, reason) in [
        ("model", json!("unapproved-model"), "model not granted"),
        (
            "max_tokens",
            json!(513),
            "model output token limit exceeded",
        ),
        ("n", json!(2), "unsupported model request parameters"),
        (
            "stream",
            json!(true),
            "unsupported model request parameters",
        ),
    ] {
        let mut body = json!({"model":config.model,"stream":false,"max_tokens":512,"messages":[{"role":"user","content":"budget probe"}]});
        body[field] = value;
        prove_model_denial(&config.url, body, reason)?;
    }
    let definitions: Vec<Value> = config.tools.iter().map(|t| json!({"type":"function","function":{
        "name":t.name,"description":t.description,"parameters":{"type":"object","properties":{"args":{"type":"array","items":{"type":"string"},"minItems":2,"maxItems":2}},"required":["args"],"additionalProperties":false}
    }})).collect();
    let mut messages = vec![json!({"role":"user","content":config.task})];
    let mut used = BTreeSet::new();
    let mut ids = BTreeSet::new();
    let mut calls = 0;
    for turn in 0..6 {
        let wire = serde_json::to_vec(
            &json!({"apiVersion":"celln.fetch/v1","method":"POST","url":config.url,"body":{
                "model":config.model,"stream":false,"max_tokens":512,"messages":messages,"tools":definitions,
                "tool_choice":if used.len() < config.tools.len() { "required" } else { "auto" }
            }}),
        )?;
        ensure!(wire.len() <= 8192, "conversation exceeded broker budget");
        let response: Value = serde_json::from_slice(&bounded_child(
            "/pilot-fetch",
            &["--json-stdin".into()],
            Some(&wire),
        )?)?;
        let message = response
            .pointer("/choices/0/message")
            .context("no model message")?
            .clone();
        println!(
            "CELLN_HARNESS_EVENT {}",
            json!({"type":"model","turn":turn,"id":response["id"],"model":response["model"],"usage":response["usage"]})
        );
        let tool_calls = message["tool_calls"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        // Provider responses can contain response-only extensions (e.g.
        // reasoning metadata). Do not reflect arbitrary provider fields back
        // into the host's deliberately narrow request contract.
        let mut next_message = json!({"role":"assistant","content":message["content"]});
        if !tool_calls.is_empty() {
            next_message["tool_calls"] = json!(tool_calls.iter().map(|call| json!({
                "id":call["id"],"type":call["type"],
                "function":{"name":call["function"]["name"],"arguments":call["function"]["arguments"]}
            })).collect::<Vec<_>>());
        }
        messages.push(next_message);
        if tool_calls.is_empty() {
            ensure!(
                used.len() == config.tools.len(),
                "model stopped before using lent tools"
            );
            let answer = message["content"].as_str().context("no final answer")?;
            prove_model_denial(
                &config.url,
                json!({"model":config.model,"stream":false,"max_tokens":512,"messages":[{"role":"user","content":"budget probe"}]}),
                "model cumulative output budget exhausted",
            )?;
            println!(
                "CELLN_HARNESS_EVENT {}",
                json!({"type":"completed","answer":answer,"toolsUsed":used,"calls":calls})
            );
            return Ok(());
        }
        for call in tool_calls {
            calls += 1;
            ensure!(calls <= 6, "tool call budget exhausted");
            let id = call["id"].as_str().context("missing call ID")?.to_owned();
            ensure!(ids.insert(id.clone()), "duplicate call ID");
            let name = call["function"]["name"]
                .as_str()
                .context("missing tool name")?;
            let tool = config
                .tools
                .iter()
                .find(|t| t.name == name)
                .context("unselected tool requested")?;
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Arguments {
                args: Vec<String>,
            }
            let args: Arguments = serde_json::from_str(
                call["function"]["arguments"]
                    .as_str()
                    .context("missing arguments")?,
            )?;
            ensure!(
                args.args.len() == 2
                    && args
                        .args
                        .iter()
                        .all(|a| a.len() <= 16 && a.parse::<i32>().is_ok()),
                "invalid tool arguments"
            );
            let output = bounded_child(&tool.path, &args.args, None)?;
            ensure!(output.len() <= 1024, "tool result budget exceeded");
            let result = String::from_utf8(output)?;
            used.insert(tool.name.clone());
            println!(
                "CELLN_HARNESS_EVENT {}",
                json!({"type":"tool","id":id,"name":name,"hash":tool.hash,"args":args.args,"result":result})
            );
            messages.push(json!({"role":"tool","tool_call_id":id,"content":result}));
        }
    }
    bail!("model turn budget exhausted")
}

fn prove_model_denial(url: &str, body: Value, reason: &str) -> Result<()> {
    let wire = serde_json::to_vec(
        &json!({"apiVersion":"celln.fetch/v1","method":"POST","url":url,"body":body}),
    )?;
    let mut child = Command::new("/pilot-fetch")
        .arg("--json-stdin")
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .context("probe stdin")?
        .write_all(&wire)?;
    let mut error = String::new();
    child
        .stderr
        .take()
        .context("probe stderr")?
        .take(4096)
        .read_to_string(&mut error)?;
    ensure!(
        !child.wait()?.success()
            && error.contains(&format!("CELLN_FETCH_ERROR:host fetch failed: {reason}")),
        "model policy probe did not receive expected refusal: {reason}"
    );
    println!(
        "CELLN_HARNESS_EVENT {}",
        json!({"type":"model-denied","reason":reason})
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("CELLN_HARNESS_ERROR {error:#}");
        std::process::exit(1);
    }
}
