//! Native bounded JSON-tool Harness contract. Model output selects only an
//! already lent name; schemas and limits are immutable host-provided ceilings.
use anyhow::{bail, ensure, Context, Result};
use celln_manifest::{tool_schema::ToolSchema, Hash};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeSet;

pub const CONTRACT: &str = "celln.json-tools/v1";

/// Committed text context from the native parent, never system instructions,
/// tool definitions, credentials, or unfinished tool calls.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Exchange {
    pub user: String,
    pub assistant: String,
}

#[cfg(test)]
#[path = "json_harness_tests.rs"]
mod tests;

pub fn validate(config: &Config) -> Result<()> {
    validate_with_history(config, &[])
}

pub fn validate_with_history(config: &Config, history: &[Exchange]) -> Result<()> {
    let tools = compile(config)?;
    let history = fit_history(config, &tools, history)?;
    model_request(config, &tools, &contextual_messages(config, history)?, 0).map(|_| ())
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Schema {
    pub bytes: String,
    pub hash: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Tool {
    pub name: String,
    pub path: String,
    pub hash: String,
    pub description: String,
    pub input_schema: Schema,
    pub output_schema: Schema,
    pub input_bytes: usize,
    pub output_bytes: usize,
    pub timeout_ms: u64,
    /// `celln.argv/v1`: the tool is an ordinary command-line program borrowed
    /// from a pinned image. Validated arguments become argv and stdin through
    /// this fixed binding; stdout and the exit status come back as JSON. No
    /// shell, no free-form flags, no host paths. Absent means JSON on stdin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub argv: Option<Argv>,
}

/// How a validated JSON argument object becomes a command line. An `args`
/// entry is a literal, `{field}` (the field's string form; an absent optional
/// field drops the entry), `{field?FLAG}` (FLAG when the boolean field is
/// true, else dropped) or `{field:FLAG}` (FLAG followed by the field's value
/// when present, else nothing). `stdin` names a string field fed to the tool.
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct Argv {
    pub args: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdin: Option<String>,
}

/// Longest stdout an argv tool hands back, in bytes; the tool schema subset
/// bounds strings at this length.
pub const ARGV_OUTPUT_CHARS: usize = 4096;

/// Most bytes one model request may occupy on the broker wire: the persona,
/// every selected tool's schema and the conversation so far. A worker with
/// two dozen tools and a long conversation needs more than the 8 KiB the
/// workspace and fetch tools are held to.
pub const MODEL_WIRE_BYTES: usize = 32768;

/// Wire room a turn's first model request leaves for what follows it: each
/// tool round adds the model's call and the tool's result to the same
/// conversation. History is what gives way, oldest exchange first, so a long
/// conversation with tools keeps working instead of failing every turn.
pub const TOOL_ROUND_WIRE_RESERVE: usize = MODEL_WIRE_BYTES / 2;

/// Largest final answer a worker commits, and the most the parent accepts.
pub const MAX_ANSWER_BYTES: usize = warden::parent_protocol::MAX_ANSWER_BYTES;

/// Result shape every argv tool returns to the model; the packager declares
/// it as such a tool's output schema.
pub fn argv_output_schema() -> Value {
    json!({"type":"object","properties":{"output":{"type":"string","minLength":0,"maxLength":ARGV_OUTPUT_CHARS},"exit":{"type":"integer","minimum":-1,"maximum":255}},"required":["output","exit"],"additionalProperties":false})
}

/// Builds argv and stdin for one call from already schema-validated arguments.
pub fn argv_invocation(tool: &Tool, arguments: &[u8]) -> Result<(Vec<String>, Vec<u8>)> {
    let binding = tool.argv.as_ref().context("tool has no argv binding")?;
    let input: serde_json::Map<String, Value> = serde_json::from_slice(arguments)?;
    let text = |field: &str| -> Result<Option<String>> {
        Ok(match input.get(field) {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) => Some(s.clone()),
            Some(Value::Number(n)) => Some(n.to_string()),
            Some(Value::Bool(b)) => Some(b.to_string()),
            Some(_) => bail!("argument {field} is not a scalar"),
        })
    };
    let mut args = Vec::with_capacity(binding.args.len());
    for entry in &binding.args {
        match placeholder(entry) {
            Some((field, Placeholder::Switch(flag))) => {
                if input.get(field) == Some(&Value::Bool(true)) {
                    args.push(flag.to_string());
                }
            }
            Some((field, Placeholder::Option(flag))) => {
                if let Some(value) = text(field)? {
                    ensure!(!value.contains('\0'), "argument {field} contains NUL");
                    args.push(flag.to_string());
                    args.push(value);
                }
            }
            Some((field, Placeholder::Value)) => {
                if let Some(value) = text(field)? {
                    ensure!(!value.contains('\0'), "argument {field} contains NUL");
                    args.push(value);
                }
            }
            None => args.push(entry.clone()),
        }
    }
    let stdin = match &binding.stdin {
        Some(field) => text(field)?.unwrap_or_default().into_bytes(),
        None => Vec::new(),
    };
    Ok((args, stdin))
}

enum Placeholder<'a> {
    Value,
    Switch(&'a str),
    Option(&'a str),
}

/// `{field}`, `{field?FLAG}` or `{field:FLAG}`; anything else is a literal.
fn placeholder(entry: &str) -> Option<(&str, Placeholder<'_>)> {
    let inner = entry.strip_prefix('{')?.strip_suffix('}')?;
    if inner.is_empty() || inner.contains(['{', '}']) {
        return None;
    }
    if let Some((field, flag)) = inner.split_once('?') {
        return Some((field, Placeholder::Switch(flag)));
    }
    if let Some((field, flag)) = inner.split_once(':') {
        return Some((field, Placeholder::Option(flag)));
    }
    Some((inner, Placeholder::Value))
}

/// What the model sees from an argv tool: bounded UTF-8 stdout and the exit
/// status. Invalid UTF-8 is replaced rather than failing the turn.
pub fn argv_output(exit: i32, stdout: &[u8]) -> Vec<u8> {
    let mut text = String::from_utf8_lossy(stdout).into_owned();
    let room = ARGV_OUTPUT_CHARS;
    if text.len() > room {
        let mut end = room;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
    }
    serde_json::to_vec(&json!({"output": text, "exit": exit})).unwrap_or_default()
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub contract: String,
    pub task: String,
    pub system: String,
    pub url: String,
    pub model: String,
    pub tools: Vec<Tool>,
    pub max_turns: usize,
    pub max_calls: usize,
    /// Explicit host-template requirement, not a grant to any additional tool.
    /// Omission preserves the original serialized template and optional calls.
    #[serde(default, skip_serializing_if = "is_false")]
    pub require_tool_call: bool,
    /// Operator opt-in for an HTTP or self-signed private model endpoint.
    /// Omission preserves the original serialized template hash.
    #[serde(default, skip_serializing_if = "is_false")]
    pub allow_insecure: bool,
}

fn is_false(value: &bool) -> bool {
    !*value
}

struct CheckedTool<'a> {
    tool: &'a Tool,
    input: ToolSchema,
    output: ToolSchema,
    definition: Value,
}

fn compile(config: &Config) -> Result<Vec<CheckedTool<'_>>> {
    ensure!(config.contract == CONTRACT, "unsupported Harness contract");
    ensure!(
        !config.task.trim().is_empty() && config.task.len() <= 2048 && config.system.len() <= 2048,
        "task/persona exceeds contract"
    );
    ensure!(
        !config.model.is_empty()
            && config.model.len() <= 128
            && (config.url.starts_with("https://")
                || (config.allow_insecure && config.url.starts_with("http://")))
            && config.url.len() <= 512,
        "invalid model selection"
    );
    ensure!(
        (1..=6).contains(&config.max_turns) && config.max_calls <= 16 && config.tools.len() <= 24,
        "turn/call/tool limit exceeds contract"
    );
    let mut names = BTreeSet::new();
    ensure!(
        !config.require_tool_call
            || (!config.tools.is_empty() && config.max_calls > 0 && config.max_turns >= 2),
        "required tool call needs a selected tool and call/result budgets"
    );
    let mut paths = BTreeSet::new();
    config.tools.iter().map(|tool| {
        ensure!(!tool.name.is_empty() && tool.name.len() <= 64 && tool.name.bytes().all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
            && names.insert(&tool.name) && paths.insert(&tool.path), "invalid or duplicate tool identity");
        ensure!(celln_manifest::closure::canonical_path(&tool.path) && tool.path.len() <= 256
            && tool.path != "/pilot-fetch" && tool.hash.len() == 71 && tool.hash.starts_with("blake3:")
            && tool.hash.as_bytes()[7..].iter().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b)), "invalid tool path/hash");
        ensure!(!tool.description.is_empty() && tool.description.len() <= 512
            && (1..=65536).contains(&tool.input_bytes) && (1..=65536).contains(&tool.output_bytes)
            && (1..=30000).contains(&tool.timeout_ms), "invalid tool ceilings");
        let input = ToolSchema::parse(tool.input_schema.bytes.as_bytes(), &Hash(tool.input_schema.hash.clone())).map_err(anyhow::Error::msg)?;
        let output = ToolSchema::parse(tool.output_schema.bytes.as_bytes(), &Hash(tool.output_schema.hash.clone())).map_err(anyhow::Error::msg)?;
        let parameters: Value = serde_json::from_str(&tool.input_schema.bytes)?;
        ensure!(parameters["type"] == "object", "JSON-tool inputs must use an object schema");
        if let Some(argv) = &tool.argv {
            let properties = parameters["properties"].as_object().cloned().unwrap_or_default();
            ensure!(argv.args.len() <= 32 && argv.args.iter().all(|a| a.len() <= 1024 && !a.contains('\0')), "argv binding exceeds contract");
            for entry in &argv.args {
                if let Some((field, shape)) = placeholder(entry) {
                    let kind = properties.get(field).map(|p| p["type"].clone()).unwrap_or(Value::Null);
                    ensure!(!kind.is_null(), "argv placeholder {field} is not an input field");
                    match shape {
                        Placeholder::Switch(_) => ensure!(kind == "boolean", "argv flag placeholder {field} must be a boolean field"),
                        _ => ensure!(kind == "string" || kind == "integer" || kind == "number" || kind == "boolean", "argv placeholder {field} must be a scalar field"),
                    }
                }
            }
            if let Some(field) = &argv.stdin {
                ensure!(properties.get(field).is_some_and(|p| p["type"] == "string"), "argv stdin field must be a string input field");
            }
            let output: Value = serde_json::from_str(&tool.output_schema.bytes)?;
            ensure!(output == argv_output_schema(), "argv tool output schema must be the argv result shape");
        }
        let definition = json!({"type":"function","function":{"name":tool.name,"description":tool.description,"parameters":parameters}});
        Ok(CheckedTool { tool, input, output, definition })
    }).collect()
}

/// Executes the bounded model loop through injected broker/tool transports.
/// No ambient tool discovery, implicit all-tools call requirement or shell.
/// Tool transport receives exact model argument bytes AFTER schema validation.
pub fn run(
    config: &Config,
    broker: impl FnMut(&[u8]) -> Result<Vec<u8>>,
    execute: impl FnMut(&Tool, &[u8]) -> Result<Vec<u8>>,
    event: impl FnMut(Value),
) -> Result<String> {
    run_with_history(config, &[], broker, execute, event)
}

/// Explicit native turn-worker entry point. The one-shot adapter calls `run`
/// with no history; existing config and grant formats remain unchanged.
pub fn run_with_history(
    config: &Config,
    history: &[Exchange],
    mut broker: impl FnMut(&[u8]) -> Result<Vec<u8>>,
    mut execute: impl FnMut(&Tool, &[u8]) -> Result<Vec<u8>>,
    mut event: impl FnMut(Value),
) -> Result<String> {
    let tools = compile(config)?;
    let offered = history.len();
    let history = fit_history(config, &tools, history)?;
    if history.len() < offered {
        event(
            json!({"type":"context","historyKept":history.len(),"historyDropped":offered - history.len()}),
        );
    }
    let mut messages = contextual_messages(config, history)?;
    let mut ids = BTreeSet::new();
    let mut calls = 0usize;
    for turn in 0..config.max_turns {
        let wire = model_request(config, &tools, &messages, calls)?;
        let response = broker(&wire)?;
        ensure!(response.len() <= 1_048_576, "model response exceeds limit");
        let response: Value = serde_json::from_slice(&response)?;
        let choices = response["choices"]
            .as_array()
            .context("missing model choices")?;
        ensure!(choices.len() == 1, "exactly one model choice required");
        let message = &choices[0]["message"];
        ensure!(message["role"] == "assistant", "invalid response role");
        let tool_calls = match message.get("tool_calls") {
            None | Some(Value::Null) => vec![],
            Some(Value::Array(calls)) => calls.clone(),
            _ => bail!("invalid tool call list"),
        };
        ensure!(
            tool_calls.len() <= config.max_calls.saturating_sub(calls),
            "tool call budget exhausted"
        );
        event(json!({"type":"model","turn":turn,"model":config.model}));
        if tool_calls.is_empty() {
            ensure!(
                !config.require_tool_call || calls > 0,
                "model completed without required tool execution"
            );
            let answer = message["content"]
                .as_str()
                .context("missing final answer")?;
            ensure!(!answer.trim().is_empty(), "final answer is empty");
            ensure!(
                answer.len() <= MAX_ANSWER_BYTES,
                "final answer exceeds {MAX_ANSWER_BYTES} bytes"
            );
            // `answerLimit` tells the host which answer contract this guest
            // package was built with; a package without it predates 8 KiB.
            event(
                json!({"type":"completed","answer":answer,"calls":calls,"answerLimit":MAX_ANSWER_BYTES}),
            );
            return Ok(answer.into());
        }
        // Do not start side effects when the configured turn budget already
        // makes returning their results to the model impossible.
        ensure!(
            turn + 1 < config.max_turns,
            "model budget leaves no tool result turn"
        );
        // Validate the complete batch before any side effects. Preserve only
        // the supported assistant fields, never arbitrary provider extensions.
        let mut pending = Vec::new();
        let mut sanitized = Vec::new();
        for call in &tool_calls {
            let id = call["id"].as_str().context("missing tool-call ID")?;
            ensure!(
                !id.is_empty()
                    && id.len() <= 128
                    && ids.insert(id.to_owned())
                    && call["type"] == "function",
                "duplicate or invalid tool call"
            );
            let name = call["function"]["name"]
                .as_str()
                .context("missing tool name")?;
            let tool = tools
                .iter()
                .find(|t| t.tool.name == name)
                .context("unselected tool requested")?;
            let arguments = call["function"]["arguments"]
                .as_str()
                .context("missing JSON arguments")?;
            tool.input
                .validate(arguments.as_bytes(), tool.tool.input_bytes)
                .map_err(anyhow::Error::msg)?;
            pending.push((id, tool, arguments));
            sanitized.push(
                json!({"id":id,"type":"function","function":{"name":name,"arguments":arguments}}),
            );
        }
        ensure!(
            message["content"].is_null() || message["content"].is_string(),
            "invalid assistant content"
        );
        messages
            .push(json!({"role":"assistant","content":message["content"],"tool_calls":sanitized}));
        for (id, tool, arguments) in pending {
            let output = execute(tool.tool, arguments.as_bytes())?;
            tool.output
                .validate(&output, tool.tool.output_bytes)
                .map_err(anyhow::Error::msg)?;
            let text = String::from_utf8(output)?;
            calls += 1;
            event(
                json!({"type":"tool","id":id,"name":tool.tool.name,"hash":tool.tool.hash,
                "inputSchema":tool.tool.input_schema.hash,"outputSchema":tool.tool.output_schema.hash,
                "arguments":serde_json::from_str::<Value>(arguments)?,"result":serde_json::from_str::<Value>(&text)?}),
            );
            messages.push(json!({"role":"tool","tool_call_id":id,"content":text}));
        }
    }
    bail!("model turn budget exhausted")
}

fn initial_messages(config: &Config) -> Vec<Value> {
    let mut messages = Vec::new();
    if !config.system.is_empty() {
        messages.push(json!({"role":"system","content":config.system}));
    }
    messages.push(json!({"role":"user","content":config.task}));
    messages
}

fn contextual_messages(config: &Config, history: &[Exchange]) -> Result<Vec<Value>> {
    ensure!(history.len() <= 16, "parent history count exceeds limit");
    let mut bytes = 0usize;
    for exchange in history {
        for text in [&exchange.user, &exchange.assistant] {
            ensure!(
                !text.trim().is_empty() && !text.contains('\0'),
                "invalid parent history text"
            );
            bytes = bytes
                .checked_add(text.len())
                .context("parent history overflow")?;
            ensure!(
                bytes <= warden::parent_protocol::MAX_TASK_BYTES,
                "parent history exceeds byte limit"
            );
        }
    }
    let mut messages = initial_messages(config);
    let current = messages.pop().expect("initial user message always present");
    for exchange in history {
        messages.push(json!({"role":"user", "content":exchange.user}));
        messages.push(json!({"role":"assistant", "content":exchange.assistant}));
    }
    messages.push(current);
    Ok(messages)
}

/// The newest exchanges whose first model request leaves
/// `TOOL_ROUND_WIRE_RESERVE` free. Host validation and the guest loop both
/// use this, so they agree on the request. With no history left the ordinary
/// wire bound alone decides.
fn fit_history<'a>(
    config: &Config,
    tools: &[CheckedTool<'_>],
    history: &'a [Exchange],
) -> Result<&'a [Exchange]> {
    // A worker that can make no tool call has no later rounds to reserve for.
    let reserve = if tools.is_empty() || config.max_calls == 0 {
        0
    } else {
        TOOL_ROUND_WIRE_RESERVE
    };
    for start in 0..history.len() {
        let kept = &history[start..];
        let wire = model_wire(config, tools, &contextual_messages(config, kept)?, 0)?;
        if wire.len() <= MODEL_WIRE_BYTES - reserve {
            return Ok(kept);
        }
    }
    Ok(&[])
}

fn model_request(
    config: &Config,
    tools: &[CheckedTool<'_>],
    messages: &[Value],
    calls: usize,
) -> Result<Vec<u8>> {
    let wire = model_wire(config, tools, messages, calls)?;
    ensure!(
        wire.len() <= MODEL_WIRE_BYTES,
        "conversation/schema envelope exceeds broker byte limit"
    );
    Ok(wire)
}

fn model_wire(
    config: &Config,
    tools: &[CheckedTool<'_>],
    messages: &[Value],
    calls: usize,
) -> Result<Vec<u8>> {
    let mut body =
        json!({"model":config.model,"stream":false,"max_tokens":512,"messages":messages});
    if !tools.is_empty() {
        body["tools"] = json!(tools.iter().map(|t| &t.definition).collect::<Vec<_>>());
        // Provider request is advisory; completion is independently checked
        // above. Once a tool has run, allow the final answer without forcing
        // another side effect or replenishing the existing call budget.
        body["tool_choice"] = json!(if config.require_tool_call && calls == 0 {
            "required"
        } else {
            "auto"
        });
    }
    Ok(serde_json::to_vec(
        &json!({"apiVersion":"celln.fetch/v1","method":"POST","url":config.url,"body":body}),
    )?)
}
