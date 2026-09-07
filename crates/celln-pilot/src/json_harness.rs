//! Native bounded JSON-tool Harness contract. Model output selects only an
//! already lent name; schemas and limits are immutable host-provided ceilings.
use anyhow::{bail, ensure, Context, Result};
use celln_manifest::{tool_schema::ToolSchema, Hash};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeSet;

pub const CONTRACT: &str = "celln.json-tools/v1";

#[cfg(test)]
#[path = "json_harness_tests.rs"]
mod tests;

pub fn validate(config: &Config) -> Result<()> {
    compile(config).map(|_| ())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Schema {
    pub bytes: String,
    pub hash: String,
}

#[derive(Deserialize)]
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
}

#[derive(Deserialize)]
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
            && config.url.starts_with("https://")
            && config.url.len() <= 512,
        "invalid model selection"
    );
    ensure!(
        (1..=6).contains(&config.max_turns) && config.max_calls <= 16 && config.tools.len() <= 16,
        "turn/call/tool limit exceeds contract"
    );
    let mut names = BTreeSet::new();
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
        let definition = json!({"type":"function","function":{"name":tool.name,"description":tool.description,"parameters":parameters}});
        Ok(CheckedTool { tool, input, output, definition })
    }).collect()
}

/// Executes the bounded model loop through injected broker/tool transports.
/// No ambient tool discovery, implicit all-tools call requirement or shell.
/// Tool transport receives exact model argument bytes AFTER schema validation.
pub fn run(
    config: &Config,
    mut broker: impl FnMut(&[u8]) -> Result<Vec<u8>>,
    mut execute: impl FnMut(&Tool, &[u8]) -> Result<Vec<u8>>,
    mut event: impl FnMut(Value),
) -> Result<String> {
    let tools = compile(config)?;
    let mut messages = Vec::new();
    if !config.system.is_empty() {
        messages.push(json!({"role":"system","content":config.system}));
    }
    messages.push(json!({"role":"user","content":config.task}));
    let mut ids = BTreeSet::new();
    let mut calls = 0usize;
    for turn in 0..config.max_turns {
        let mut body =
            json!({"model":config.model,"stream":false,"max_tokens":512,"messages":messages});
        if !tools.is_empty() {
            body["tools"] = json!(tools.iter().map(|t| &t.definition).collect::<Vec<_>>());
            body["tool_choice"] = json!("auto");
        }
        let wire = serde_json::to_vec(
            &json!({"apiVersion":"celln.fetch/v1","method":"POST","url":config.url,"body":body}),
        )?;
        ensure!(
            wire.len() <= 8192,
            "conversation/schema envelope exceeds broker byte limit"
        );
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
            let answer = message["content"]
                .as_str()
                .context("missing final answer")?;
            ensure!(
                !answer.trim().is_empty() && answer.len() <= 4096,
                "final answer is empty or exceeds limit"
            );
            event(json!({"type":"completed","answer":answer,"calls":calls}));
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
