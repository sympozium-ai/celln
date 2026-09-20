//! Explicit, endpoint-scoped JSON POST authority for an in-cell model client.
//! The wire contains no headers, credential reference, redirects or proxy
//! options. Only the host chooses a credential and the permitted endpoint.

use super::{response_status_and_location, FetchDenied, HttpBroker};
use serde::Deserialize;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::Command;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ModelProtocol {
    #[default]
    OpenaiChat,
    AnthropicMessages,
}

/// A validated model endpoint. The default contract is a public HTTPS host on
/// port 443; the operator opt-in also permits HTTP and an explicit port so a
/// private or self-signed model can be reached.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelEndpoint {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub origin: String,
}

/// Validate the endpoint before reading any credentials. Transport additionally
/// checks DNS/IP policy and refuses redirects and non-public addresses.
pub fn model_endpoint_target(url: &str, allow_insecure: bool) -> Result<ModelEndpoint, String> {
    let (scheme, rest) = if let Some(rest) = url.strip_prefix("https://") {
        ("https", rest)
    } else if allow_insecure {
        (
            "http",
            url.strip_prefix("http://")
                .ok_or("model endpoint requires HTTP or HTTPS")?,
        )
    } else {
        return Err("model endpoint requires HTTPS".into());
    };
    if url.len() > 2048 || url.contains(['?', '#', '\r', '\n', '\0']) {
        return Err("invalid model endpoint".into());
    }
    let (authority, path) = rest
        .split_once('/')
        .ok_or("complete model endpoint required")?;
    if path.is_empty() || authority.is_empty() || authority.contains('@') {
        return Err("invalid model endpoint".into());
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => {
            let port: u16 = port.parse().map_err(|_| "invalid model endpoint port")?;
            if port == 0 {
                return Err("invalid model endpoint port".into());
            }
            (host, port)
        }
        None => (authority, if scheme == "https" { 443 } else { 80 }),
    };
    if !allow_insecure && port != 443 {
        return Err("model endpoint requires port 443".into());
    }
    if host.is_empty() || host.len() > 253 {
        return Err("invalid model endpoint".into());
    }
    let host_valid = if allow_insecure {
        host.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'[' | b']'))
    } else {
        host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
    };
    if !host_valid {
        return Err("invalid model endpoint".into());
    }
    let default_port = (scheme == "https" && port == 443) || (scheme == "http" && port == 80);
    let origin = if default_port {
        format!("{scheme}://{host}")
    } else {
        format!("{scheme}://{host}:{port}")
    };
    Ok(ModelEndpoint {
        scheme: scheme.into(),
        host: host.into(),
        port,
        origin,
    })
}

pub fn model_endpoint_host(url: &str) -> Result<String, String> {
    model_endpoint_target(url, false).map(|target| target.host)
}

/// Output tokens one model request may ask for when the operator states no
/// cap: what every starter worker requested before the cap was configurable.
pub const DEFAULT_REQUEST_OUTPUT_TOKENS: u64 = 512;
/// The per-request caps an operator may configure for a model backend
/// (`modelConnection.maxOutputTokens`). The pinned profile carries the chosen
/// value, the grant enforces it and the worker template tells the guest.
pub const REQUEST_OUTPUT_TOKENS: std::ops::RangeInclusive<u64> = 256..=4096;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JsonPostGrant {
    pub protocol: ModelProtocol,
    pub url: String,
    /// Operator-controlled file, read per request. Never delivered to guest.
    pub bearer_token_file: PathBuf,
    /// Exact provider model alias; mandatory, never supplied as authority by guest.
    pub model: String,
    pub max_output_tokens: u64,
    /// Sum of requested output ceilings, reserved before network I/O. Failed
    /// or interrupted requests are not refunded because they may be billed.
    pub max_total_output_tokens: u64,
    /// Operator-pinned provider fields (see `model_parameters`). The host adds
    /// them to the outgoing body after the guest request passed validation;
    /// they are never part of the guest contract nor delivered to the guest.
    pub parameters: serde_json::Map<String, serde_json::Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChatRequest {
    model: String,
    max_tokens: u64,
    stream: bool,
    messages: Vec<ChatMessage>,
    #[serde(default)]
    tools: Option<Vec<ChatTool>>,
    #[serde(default)]
    tool_choice: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChatMessage {
    role: String,
    // Text-only: no provider-fetched URLs or multimodal input objects.
    content: Option<String>,
    #[serde(default)]
    tool_calls: Option<Vec<ChatToolCall>>,
    #[serde(default)]
    tool_call_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChatTool {
    #[serde(rename = "type")]
    kind: String,
    function: ChatFunction,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChatFunction {
    name: String,
    description: String,
    parameters: serde_json::Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChatToolCall {
    id: String,
    #[serde(rename = "type")]
    kind: String,
    function: ChatFunctionCall,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChatFunctionCall {
    name: String,
    arguments: String,
}

fn validate_chat(body: &serde_json::Value, grant: &JsonPostGrant) -> Result<u64, FetchDenied> {
    let chat: ChatRequest = serde_json::from_value(body.clone())
        .map_err(|_| refused("unsupported model request parameters"))?;
    if grant.model.is_empty() || chat.model != grant.model {
        return Err(refused("model not granted"));
    }
    if chat.max_tokens == 0
        || chat.max_tokens > grant.max_output_tokens
        || chat.max_tokens > grant.max_total_output_tokens
    {
        return Err(refused("model output token limit exceeded"));
    }
    if chat.stream
        || chat.messages.is_empty()
        || chat.messages.len() > 128
        || chat.messages.iter().any(|m| {
            !matches!(m.role.as_str(), "system" | "user" | "assistant" | "tool")
                || (m.content.is_none() && m.tool_calls.is_none())
                || (m.tool_calls.is_some() && m.role != "assistant")
                || (m.tool_call_id.is_some() != (m.role == "tool"))
                || m.tool_calls.as_ref().is_some_and(|calls| {
                    calls.is_empty()
                        || calls.len() > 16
                        || calls.iter().any(|c| {
                            c.kind != "function"
                                || c.id.is_empty()
                                || c.function.name.is_empty()
                                || c.function.arguments.len() > 4096
                        })
                })
        })
        || chat.tools.as_ref().is_some_and(|tools| {
            tools.is_empty()
                || tools.len() > 24
                || tools.iter().any(|t| {
                    t.kind != "function"
                        || t.function.name.is_empty()
                        || t.function.description.len() > 4096
                        || !t.function.parameters.is_object()
                })
        })
        || chat
            .tool_choice
            .as_ref()
            .is_some_and(|choice| !matches!(choice.as_str(), "auto" | "required" | "none"))
    {
        return Err(refused("unsupported model request parameters"));
    }
    Ok(chat.max_tokens)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Request {
    api_version: String,
    method: String,
    url: String,
    body: serde_json::Value,
}

fn refused(reason: &str) -> FetchDenied {
    FetchDenied::Fetch(reason.into())
}

fn parse(raw: &str) -> Result<Request, FetchDenied> {
    if raw.len() > 32768 {
        return Err(refused("request exceeds broker wire budget"));
    }
    let request: Request =
        serde_json::from_str(raw).map_err(|_| refused("invalid JSON request"))?;
    if request.api_version != "celln.fetch/v1" || request.method != "POST" {
        return Err(refused("unsupported broker request version or method"));
    }
    if !request.body.is_object() {
        return Err(refused("POST body must be a JSON object"));
    }
    Ok(request)
}

fn credential_header(
    path: &std::path::Path,
    protocol: ModelProtocol,
) -> Result<tempfile::NamedTempFile, FetchDenied> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .and_then(|file| file.take(4097).read_to_end(&mut bytes))
        .map_err(|_| refused("provider credential unavailable"))?;
    let token = std::str::from_utf8(&bytes)
        .map_err(|_| refused("invalid provider credential"))?
        .trim();
    if bytes.len() > 4096 || token.len() < 24 || !token.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(refused("invalid provider credential"));
    }
    // tempfile creates mode 0600. curl reads this file, never a token in argv.
    let mut header =
        tempfile::NamedTempFile::new().map_err(|_| refused("credential staging failed"))?;
    let value = match protocol {
        ModelProtocol::OpenaiChat => format!("Authorization: Bearer {token}"),
        ModelProtocol::AnthropicMessages => {
            format!("x-api-key: {token}\nanthropic-version: 2023-06-01")
        }
    };
    writeln!(header, "{value}").map_err(|_| refused("credential staging failed"))?;
    Ok(header)
}

// The guest contract remains bounded Chat Completions. Protocol translation is
// host-owned and runs only after that request has passed grant validation.
fn provider_request(
    body: &serde_json::Value,
    protocol: ModelProtocol,
) -> Result<serde_json::Value, FetchDenied> {
    use serde_json::{json, Value};
    if protocol == ModelProtocol::OpenaiChat {
        return Ok(body.clone());
    }
    let chat: ChatRequest =
        serde_json::from_value(body.clone()).map_err(|_| refused("invalid chat request"))?;
    let mut system = Vec::new();
    let mut messages: Vec<Value> = Vec::new();
    for message in chat.messages {
        if message.role == "system" {
            system.push(message.content.unwrap_or_default());
            continue;
        }
        let role = if message.role == "tool" {
            "user"
        } else {
            &message.role
        };
        let mut content = Vec::new();
        if message.role == "tool" {
            content.push(json!({"type":"tool_result", "tool_use_id":message.tool_call_id, "content":message.content.unwrap_or_default()}));
        } else {
            if let Some(text) = message.content.filter(|text| !text.is_empty()) {
                content.push(json!({"type":"text", "text":text}));
            }
            for call in message.tool_calls.unwrap_or_default() {
                let input: Value = serde_json::from_str(&call.function.arguments)
                    .map_err(|_| refused("invalid tool arguments"))?;
                if !input.is_object() {
                    return Err(refused("tool arguments must be an object"));
                }
                content.push(json!({"type":"tool_use", "id":call.id, "name":call.function.name, "input":input}));
            }
        }
        if messages.last().is_some_and(|last| last["role"] == role) {
            messages.last_mut().unwrap()["content"]
                .as_array_mut()
                .unwrap()
                .extend(content);
        } else {
            messages.push(json!({"role":role,"content":content}));
        }
    }
    let mut out =
        json!({"model":chat.model,"max_tokens":chat.max_tokens,"stream":false,"messages":messages});
    if !system.is_empty() {
        out["system"] = json!(system.join("\n\n"));
    }
    if let Some(tools) = chat.tools {
        if chat.tool_choice.as_deref() != Some("none") {
            out["tools"] = json!(tools.into_iter().map(|tool| json!({"name":tool.function.name,"description":tool.function.description,"input_schema":tool.function.parameters})).collect::<Vec<_>>());
            out["tool_choice"] = json!({"type": if chat.tool_choice.as_deref() == Some("required") { "any" } else { "auto" }});
        }
    }
    Ok(out)
}

/// The exact JSON sent to the provider: the validated guest request in the
/// provider's protocol, plus the operator's pinned parameters. A parameter
/// never replaces a field the contract set; such a request is refused.
fn outgoing_body(
    body: &serde_json::Value,
    grant: &JsonPostGrant,
) -> Result<serde_json::Value, FetchDenied> {
    let mut out = provider_request(body, grant.protocol)?;
    // The refusal reaches the guest, so it names no parameter.
    crate::model_parameters::merge(&mut out, &grant.parameters).map_err(|_| {
        refused("operator model parameters collide with the provider request; nothing sent")
    })?;
    Ok(out)
}

fn provider_response(raw: Vec<u8>, protocol: ModelProtocol) -> Result<Vec<u8>, FetchDenied> {
    use serde_json::{json, Value};
    if protocol == ModelProtocol::OpenaiChat {
        return Ok(raw);
    }
    let response: Value =
        serde_json::from_slice(&raw).map_err(|_| refused("invalid provider response"))?;
    let blocks = response["content"]
        .as_array()
        .ok_or_else(|| refused("provider response has no content"))?;
    let mut text = String::new();
    let mut calls = Vec::new();
    for block in blocks {
        match block["type"].as_str() {
            Some("text") => text.push_str(
                block["text"]
                    .as_str()
                    .ok_or_else(|| refused("invalid provider text"))?,
            ),
            Some("tool_use") => {
                let id = block["id"]
                    .as_str()
                    .ok_or_else(|| refused("missing tool id"))?;
                let name = block["name"]
                    .as_str()
                    .ok_or_else(|| refused("missing tool name"))?;
                if !block["input"].is_object() {
                    return Err(refused("invalid tool input"));
                }
                calls.push(json!({"id":id,"type":"function","function":{"name":name,"arguments":block["input"].to_string()}}));
            }
            // Reasoning is not part of the answer or the transcript the
            // guest sees; providers (and Anthropic-compatible servers such as
            // llama-server) may send it unrequested.
            Some("thinking" | "redacted_thinking") => {}
            _ => return Err(refused("unsupported provider content block")),
        }
    }
    let mut message = json!({"role":"assistant","content":text});
    if !calls.is_empty() {
        message["tool_calls"] = json!(calls);
    }
    let finish = match response["stop_reason"].as_str() {
        Some("tool_use") => "tool_calls",
        Some("max_tokens") => "length",
        Some("end_turn" | "stop_sequence") => "stop",
        _ => return Err(refused("unsupported provider stop reason")),
    };
    let input = response["usage"]["input_tokens"].as_u64().unwrap_or(0);
    let output = response["usage"]["output_tokens"].as_u64().unwrap_or(0);
    serde_json::to_vec(&json!({"choices":[{"index":0,"message":message,"finish_reason":finish}],"usage":{"prompt_tokens":input,"completion_tokens":output,"total_tokens":input.saturating_add(output)}})).map_err(|_| refused("invalid normalized response"))
}

impl HttpBroker {
    fn grant_for(&self, request: &Request) -> Result<&JsonPostGrant, FetchDenied> {
        self.policy
            .json_posts
            .iter()
            .find(|grant| grant.url == request.url)
            .ok_or_else(|| refused("JSON POST endpoint not granted"))
    }

    pub(super) fn post_json(&mut self, raw: &str) -> Result<Vec<u8>, FetchDenied> {
        let request = parse(raw)?;
        let Ok(grant) = self.grant_for(&request).cloned() else {
            return self.post_plain(request);
        };
        let output_tokens = validate_chat(&request.body, &grant)?;
        // Defence in depth: configure and the profile reader already hold
        // these rules; a grant built any other way is refused before I/O.
        // The refusal reaches the guest, so it names no parameter.
        crate::model_parameters::validate(&grant.parameters)
            .map_err(|_| refused("operator model parameters violate host policy"))?;
        let used = if self.policy.get.is_some() {
            self.used - self.get_used
        } else {
            self.used
        };
        if used >= self.policy.max_requests {
            return Err(FetchDenied::Budget);
        }
        let reserved = self
            .post_output_reserved
            .get(&request.url)
            .copied()
            .unwrap_or(0);
        let next = reserved
            .checked_add(output_tokens)
            .filter(|total| *total <= grant.max_total_output_tokens)
            .ok_or_else(|| refused("model cumulative output budget exhausted"))?;
        if let Some(relay) = self.model_relay.as_mut() {
            celln_control::check().map_err(|_| refused("mediated model invocation cancelled"))?;
            let provider_body = outgoing_body(&request.body, &grant)?;
            let body = serde_json::to_vec(&provider_body)
                .map_err(|_| refused("invalid mediated model request"))?;
            if body.len() > 262144 {
                return Err(refused("mediated model request too large"));
            }
            // Reserve before calling the relay and never refund, including on
            // cancellation, malformed output, response loss or transport error.
            // This is a local ceiling; the gateway owns durable accounting.
            self.used += 1;
            self.post_output_reserved.insert(request.url.clone(), next);
            let raw = relay.invoke(&body).map_err(|error| match error {
                FetchDenied::Budget => FetchDenied::Budget,
                _ => refused("mediated model invocation failed"),
            })?;
            celln_control::check().map_err(|_| refused("mediated model invocation cancelled"))?;
            if raw.len() > self.policy.max_response_bytes {
                return Err(refused("mediated model response too large"));
            }
            let response = provider_response(raw, grant.protocol)
                .map_err(|_| refused("invalid mediated model response"))?;
            if response.len() > self.policy.max_response_bytes {
                return Err(refused("mediated model response too large"));
            }
            return Ok(response);
        }
        let authorized = self.authorize(&request.url)?;
        self.used += 1;
        self.post_output_reserved.insert(request.url.clone(), next);
        let credential = credential_header(&grant.bearer_token_file, grant.protocol)?;
        let mut body =
            tempfile::NamedTempFile::new().map_err(|_| refused("request staging failed"))?;
        let provider_body = outgoing_body(&request.body, &grant)?;
        serde_json::to_writer(&mut body, &provider_body)
            .map_err(|_| refused("request staging failed"))?;
        let response_headers =
            tempfile::NamedTempFile::new().map_err(|_| refused("response staging failed"))?;
        let mut command = Command::new("curl");
        command
            .args([
                "--disable",
                "--silent",
                "--show-error",
                "--globoff",
                "--noproxy",
                "*",
                "--proto",
                if self.policy.allow_insecure {
                    "=http,https"
                } else {
                    "=https"
                },
                "--max-redirs",
                "0",
                "--request",
                "POST",
                "--header",
                "Content-Type: application/json",
            ])
            .arg("--header")
            .arg(format!("@{}", credential.path().display()))
            .arg("--data-binary")
            .arg(format!("@{}", body.path().display()))
            .arg("--max-time")
            .arg(self.policy.timeout.as_secs().max(1).to_string())
            .arg("--max-filesize")
            .arg(self.policy.max_response_bytes.to_string());
        if self.policy.allow_insecure && authorized.scheme == "https" {
            // Opt-in only: accept a self-signed certificate for a private host.
            command.arg("--insecure");
        }
        command
            .arg("--resolve")
            .arg(format!(
                "{}:{}:{}",
                authorized.host, authorized.port, authorized.ip
            ))
            .arg("--dump-header")
            .arg(response_headers.path())
            .arg("--url")
            .arg(&request.url);
        let out =
            celln_control::process::output_with_timeout(&mut command, Some(self.policy.timeout))
                .map_err(|_| refused("HTTPS POST interrupted or unavailable"))?;
        if !out.status.success() {
            return Err(refused("HTTPS POST failed"));
        }
        if out.stdout.len() > self.policy.max_response_bytes {
            return Err(refused("response exceeded byte budget"));
        }
        let headers = std::fs::read_to_string(response_headers.path())
            .map_err(|_| refused("invalid response headers"))?;
        let (status, _) = response_status_and_location(&headers)
            .ok_or_else(|| refused("missing HTTP response headers"))?;
        // No redirect/retry for credential-bearing, potentially billed requests.
        if !(200..300).contains(&status) {
            return Err(refused(&format!("HTTP {status}; POST not replayed")));
        }
        let normalized = provider_response(out.stdout, grant.protocol)?;
        if normalized.len() > self.policy.max_response_bytes {
            return Err(refused("normalized response exceeded byte budget"));
        }
        Ok(normalized)
    }

    /// A credential-free JSON POST under the starter post grant: exact host,
    /// bounded body and response, no headers beyond the content type, no
    /// redirect. The HTTP status is data for the tool, not a refusal, so a
    /// receiver's 4xx reaches the model verbatim.
    fn post_plain(&mut self, request: Request) -> Result<Vec<u8>, FetchDenied> {
        let grant = self
            .policy
            .post
            .clone()
            .ok_or_else(|| refused("JSON POST endpoint not granted"))?;
        let host = super::url_host(&request.url).ok_or(FetchDenied::Authority)?;
        if !grant
            .allow_hosts
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(&host))
        {
            return Err(FetchDenied::Host(host));
        }
        if self.post_used >= grant.max_requests {
            return Err(FetchDenied::Budget);
        }
        let body_bytes =
            serde_json::to_vec(&request.body).map_err(|_| refused("request staging failed"))?;
        if body_bytes.len() > grant.max_body_bytes {
            return Err(refused("POST body exceeds byte budget"));
        }
        let authorized = self.authorize(&request.url)?;
        self.post_used += 1;
        let mut body =
            tempfile::NamedTempFile::new().map_err(|_| refused("request staging failed"))?;
        body.write_all(&body_bytes)
            .map_err(|_| refused("request staging failed"))?;
        let response_headers =
            tempfile::NamedTempFile::new().map_err(|_| refused("response staging failed"))?;
        let mut command = Command::new("curl");
        command
            .args([
                "--disable",
                "--silent",
                "--show-error",
                "--globoff",
                "--noproxy",
                "*",
                "--proto",
                if self.policy.allow_insecure {
                    "=http,https"
                } else {
                    "=https"
                },
                "--max-redirs",
                "0",
                "--request",
                "POST",
                "--header",
                "Content-Type: application/json",
            ])
            .arg("--data-binary")
            .arg(format!("@{}", body.path().display()))
            .arg("--max-time")
            .arg(grant.timeout.as_secs().max(1).to_string())
            .arg("--max-filesize")
            .arg(grant.max_response_bytes.to_string());
        if self.policy.allow_insecure && authorized.scheme == "https" {
            command.arg("--insecure");
        }
        command
            .arg("--resolve")
            .arg(format!(
                "{}:{}:{}",
                authorized.host, authorized.port, authorized.ip
            ))
            .arg("--dump-header")
            .arg(response_headers.path())
            .arg("--url")
            .arg(&request.url);
        let out = celln_control::process::output_with_timeout(&mut command, Some(grant.timeout))
            .map_err(|_| refused("JSON POST interrupted or unavailable"))?;
        if !out.status.success() {
            return Err(refused("JSON POST failed"));
        }
        if out.stdout.len() > grant.max_response_bytes {
            return Err(refused("response exceeded byte budget"));
        }
        let headers = std::fs::read_to_string(response_headers.path())
            .map_err(|_| refused("invalid response headers"))?;
        let (status, _) = response_status_and_location(&headers)
            .ok_or_else(|| refused("missing HTTP response headers"))?;
        let content = String::from_utf8_lossy(&out.stdout).into_owned();
        serde_json::to_vec(&serde_json::json!({"status":status,"content":content}))
            .map_err(|_| refused("response encoding failed"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::egress::{HttpPolicy, PostGrant};

    #[test]
    fn plain_posts_need_their_own_grant_host_and_budget_and_never_a_credential() {
        use serde_json::json;
        let wire = |url: &str| {
            json!({"apiVersion":"celln.fetch/v1","method":"POST","url":url,"body":{"event":"done"}})
                .to_string()
        };
        // No post grant: the model grant list does not cover arbitrary URLs.
        let mut none = HttpBroker::new(HttpPolicy::new(vec!["hooks.example".into()]));
        assert_eq!(
            none.fetch(&wire("https://hooks.example/in")).unwrap_err(),
            refused("JSON POST endpoint not granted")
        );
        let mut policy = HttpPolicy::new(vec!["hooks.example".into()]);
        policy.post = Some(PostGrant {
            allow_hosts: vec!["hooks.example".into()],
            max_requests: 1,
            max_body_bytes: 8,
            max_response_bytes: 4096,
            timeout: std::time::Duration::from_secs(1),
        });
        let mut broker = HttpBroker::new(policy);
        // The grant names hosts exactly; the model host is not a POST host.
        assert!(matches!(
            broker.fetch(&wire("https://other.example/in")).unwrap_err(),
            FetchDenied::Host(_)
        ));
        // A body beyond the grant is refused before any network use.
        assert_eq!(
            broker.fetch(&wire("https://hooks.example/in")).unwrap_err(),
            refused("POST body exceeds byte budget")
        );
        assert_eq!(broker.post_used, 0);
        // Not an object, not a POST, wrong version: parse refuses.
        for raw in [
            json!({"apiVersion":"celln.fetch/v1","method":"POST","url":"https://hooks.example/in","body":[1]}).to_string(),
            json!({"apiVersion":"celln.fetch/v1","method":"PUT","url":"https://hooks.example/in","body":{}}).to_string(),
            json!({"apiVersion":"celln.fetch/v2","method":"POST","url":"https://hooks.example/in","body":{}}).to_string(),
        ] {
            assert!(broker.fetch(&raw).is_err());
        }
    }

    #[test]
    fn anthropic_round_trip_preserves_tool_ids_results_and_usage() {
        use serde_json::json;
        let body = json!({"model":"chosen","max_tokens":512,"stream":false,"messages":[
            {"role":"system","content":"Use approved tools."},
            {"role":"user","content":"Read the file"},
            {"role":"assistant","content":null,"tool_calls":[{"id":"call-1","type":"function","function":{"name":"read","arguments":"{\"name\":\"notes\"}"}}]},
            {"role":"tool","tool_call_id":"call-1","content":"violet"},
            {"role":"user","content":"What did it say?"}
        ],"tools":[{"type":"function","function":{"name":"read","description":"Read file","parameters":{"type":"object"}}}],"tool_choice":"required"});
        let request = provider_request(&body, ModelProtocol::AnthropicMessages).unwrap();
        assert_eq!(request["system"], "Use approved tools.");
        assert_eq!(request["messages"][1]["content"][0]["id"], "call-1");
        assert_eq!(
            request["messages"][2]["content"][0]["tool_use_id"],
            "call-1"
        );
        assert_eq!(request["messages"][2]["content"][0]["content"], "violet");
        assert_eq!(
            request["messages"][2]["content"].as_array().unwrap().len(),
            2
        );
        assert_eq!(request["tool_choice"]["type"], "any");
        assert_eq!(request["tools"][0]["input_schema"]["type"], "object");
        let reply = json!({"content":[{"type":"text","text":"Checking"},{"type":"tool_use","id":"next","name":"read","input":{"name":"other"}}],"stop_reason":"tool_use","usage":{"input_tokens":12,"output_tokens":7}});
        let normalized: serde_json::Value = serde_json::from_slice(
            &provider_response(
                serde_json::to_vec(&reply).unwrap(),
                ModelProtocol::AnthropicMessages,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            normalized["choices"][0]["message"]["tool_calls"][0]["id"],
            "next"
        );
        assert_eq!(normalized["choices"][0]["finish_reason"], "tool_calls");
        assert_eq!(normalized["usage"]["total_tokens"], 19);
        // Reasoning blocks are dropped, never forwarded as text.
        let thinking = json!({"content":[{"type":"thinking","thinking":"private chain","signature":""},{"type":"redacted_thinking","data":"x"},{"type":"tool_use","id":"t1","name":"read","input":{}}],"stop_reason":"tool_use","usage":{"input_tokens":1,"output_tokens":1}});
        let normalized: serde_json::Value = serde_json::from_slice(
            &provider_response(
                serde_json::to_vec(&thinking).unwrap(),
                ModelProtocol::AnthropicMessages,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(normalized["choices"][0]["message"]["content"], "");
        assert_eq!(
            normalized["choices"][0]["message"]["tool_calls"][0]["id"],
            "t1"
        );
        let unknown = json!({"content":[{"type":"image","source":{}}],"stop_reason":"end_turn"});
        assert!(provider_response(
            serde_json::to_vec(&unknown).unwrap(),
            ModelProtocol::AnthropicMessages
        )
        .is_err());
        assert_eq!(
            provider_request(&body, ModelProtocol::OpenaiChat).unwrap(),
            body
        );
    }

    #[test]
    fn model_endpoints_reject_credential_and_transport_overrides() {
        for url in [
            "http://example.com/v1",
            "https://key@example.com/v1",
            "https://example.com:8080/v1",
            "https://example.com/v1?key=secret",
            "https://example.com/v1#fragment",
        ] {
            assert!(model_endpoint_host(url).is_err(), "accepted {url}");
        }
        assert_eq!(
            model_endpoint_host("https://api.anthropic.com/v1/messages").unwrap(),
            "api.anthropic.com"
        );
        assert_eq!(
            model_endpoint_host("https://custom.example/v1/chat/completions").unwrap(),
            "custom.example"
        );
    }

    #[test]
    fn insecure_endpoint_target_allows_http_private_and_ports() {
        let target =
            model_endpoint_target("http://192.168.1.237:8080/v1/chat/completions", true).unwrap();
        assert_eq!(target.origin, "http://192.168.1.237:8080");
        assert_eq!(target.port, 8080);
        assert_eq!(target.host, "192.168.1.237");
        assert!(model_endpoint_target("http://192.168.1.237:8080/v1", false).is_err());
        assert_eq!(
            model_endpoint_target("https://api.deepseek.com/chat/completions", true)
                .unwrap()
                .origin,
            "https://api.deepseek.com"
        );
    }

    #[test]
    fn insecure_broker_posts_to_private_http_endpoint() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            let body = br#"{"id":"x","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"LOCAL-OK"},"finish_reason":"stop"}]}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.write_all(body);
            let _ = stream.flush();
        });
        let mut token = tempfile::NamedTempFile::new().unwrap();
        writeln!(token, "{}", "a".repeat(32)).unwrap();
        let mut policy = HttpPolicy::new(vec!["127.0.0.1".into()]);
        policy.allow_insecure = true;
        policy.json_posts.push(JsonPostGrant {
            protocol: ModelProtocol::OpenaiChat,
            url: format!("http://127.0.0.1:{port}/v1/chat/completions"),
            bearer_token_file: token.path().to_path_buf(),
            model: "local".into(),
            max_output_tokens: 512,
            max_total_output_tokens: 1024,
            parameters: Default::default(),
        });
        let mut broker = HttpBroker::new(policy);
        let request = serde_json::json!({"apiVersion":"celln.fetch/v1","method":"POST",
            "url":format!("http://127.0.0.1:{port}/v1/chat/completions"),
            "body":{"model":"local","stream":false,"max_tokens":64,
                "messages":[{"role":"user","content":"hi"}]}})
        .to_string();
        let out = broker.post_json(&request).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(value["choices"][0]["message"]["content"], "LOCAL-OK");
        server.join().unwrap();
    }

    struct RecordingRelay {
        calls: std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
        fail: bool,
    }

    impl crate::egress::ModelRelay for RecordingRelay {
        fn invoke(&mut self, body: &[u8]) -> Result<Vec<u8>, FetchDenied> {
            self.calls.lock().unwrap().push(body.to_vec());
            if self.fail {
                return Err(FetchDenied::Fetch("private transport diagnostic".into()));
            }
            Ok(br#"{"choices":[{"message":{"role":"assistant","content":"relay-ok"}}]}"#.to_vec())
        }
    }

    #[test]
    fn mediated_transport_has_no_provider_file_or_dns_fallback() {
        let calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut policy = model_policy();
        let relay = || {
            Box::new(RecordingRelay {
                calls: calls.clone(),
                fail: false,
            })
        };
        // Standing credentials are forbidden even if the file does not exist.
        assert!(HttpBroker::new_mediated(policy.clone(), relay()).is_err());
        policy.json_posts[0].bearer_token_file.clear();
        let mut broker = HttpBroker::new_mediated(policy, relay()).unwrap();
        let wire = serde_json::json!({"apiVersion":"celln.fetch/v1","method":"POST",
            "url":"https://provider.invalid/chat","body":chat_body()})
        .to_string();
        let out = broker.fetch(&wire).unwrap();
        assert!(String::from_utf8(out).unwrap().contains("relay-ok"));
        assert_eq!(calls.lock().unwrap().len(), 1);
        let body: serde_json::Value = serde_json::from_slice(&calls.lock().unwrap()[0]).unwrap();
        assert_eq!(body, chat_body());
        assert!(body.get("url").is_none());
        assert!(body.get("headers").is_none());
        let other = wire.replace("provider.invalid", "other.invalid");
        assert!(broker.fetch(&other).is_err());
        assert_eq!(calls.lock().unwrap().len(), 1);
    }

    #[test]
    fn mediated_errors_are_redacted_and_never_refunded() {
        let calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut policy = model_policy();
        policy.json_posts[0].bearer_token_file.clear();
        policy.max_requests = 1;
        let mut broker = HttpBroker::new_mediated(
            policy,
            Box::new(RecordingRelay {
                calls: calls.clone(),
                fail: true,
            }),
        )
        .unwrap();
        let wire = serde_json::json!({"apiVersion":"celln.fetch/v1","method":"POST",
            "url":"https://provider.invalid/chat","body":chat_body()})
        .to_string();
        let error = broker.fetch(&wire).unwrap_err();
        assert_eq!(error, refused("mediated model invocation failed"));
        assert_eq!(broker.fetch(&wire), Err(FetchDenied::Budget));
        assert_eq!(calls.lock().unwrap().len(), 1);
        assert_eq!(
            broker.post_output_reserved["https://provider.invalid/chat"],
            512
        );
    }

    /// One-request local provider: answers `reply` and hands back the exact
    /// request (headers and body) the broker sent.
    fn capture(reply: String) -> (u16, std::thread::JoinHandle<(String, serde_json::Value)>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut seen = Vec::new();
            let mut buf = [0u8; 4096];
            let (head, body) = loop {
                let n = stream.read(&mut buf).unwrap();
                assert!(n > 0, "request ended early");
                seen.extend_from_slice(&buf[..n]);
                let Some(split) = seen.windows(4).position(|w| w == b"\r\n\r\n") else {
                    continue;
                };
                let head = String::from_utf8(seen[..split].to_vec()).unwrap();
                let length: usize = head
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse().unwrap())
                    })
                    .unwrap();
                if seen.len() >= split + 4 + length {
                    break (head, seen[split + 4..split + 4 + length].to_vec());
                }
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
                reply.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
            stream.flush().unwrap();
            (head, serde_json::from_slice(&body).unwrap())
        });
        (port, server)
    }

    fn local_broker(
        port: u16,
        protocol: ModelProtocol,
        token: &std::path::Path,
        parameters: serde_json::Value,
    ) -> (HttpBroker, String) {
        let url = format!("http://127.0.0.1:{port}/v1/model");
        let mut policy = HttpPolicy::new(vec!["127.0.0.1".into()]);
        policy.allow_insecure = true;
        policy.json_posts.push(JsonPostGrant {
            protocol,
            url: url.clone(),
            bearer_token_file: token.to_path_buf(),
            model: "local".into(),
            max_output_tokens: 512,
            max_total_output_tokens: 1024,
            parameters: parameters.as_object().unwrap().clone(),
        });
        (HttpBroker::new(policy), url)
    }

    #[test]
    fn operator_parameters_join_the_openai_body_and_never_reach_the_guest() {
        use serde_json::json;
        // llama-server shape: reasoning_content and timings ride along.
        let reply = json!({"id":"chatcmpl-1","object":"chat.completion","created":1,"model":"qwen",
            "choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant",
                "content":"LOCAL-OK","reasoning_content":""}}],
            "usage":{"prompt_tokens":9,"completion_tokens":3,"total_tokens":12},
            "timings":{"prompt_n":9,"predicted_n":3,"predicted_per_second":41.5}});
        let (port, server) = capture(reply.to_string());
        let mut token = tempfile::NamedTempFile::new().unwrap();
        writeln!(token, "{}", "a".repeat(32)).unwrap();
        let (mut broker, url) = local_broker(
            port,
            ModelProtocol::OpenaiChat,
            token.path(),
            json!({"chat_template_kwargs":{"enable_thinking":false},"top_k":20}),
        );
        let guest_body = json!({"model":"local","stream":false,"max_tokens":512,
            "messages":[{"role":"user","content":"hi"}],
            "tools":[{"type":"function","function":{"name":"read","description":"Read","parameters":{"type":"object"}}}],
            "tool_choice":"auto"});
        let request =
            json!({"apiVersion":"celln.fetch/v1","method":"POST","url":url,"body":guest_body})
                .to_string();
        let delivered = broker.post_json(&request).unwrap();
        let (head, sent) = server.join().unwrap();
        // Exactly the guest's validated body plus the two pinned fields.
        let mut expected = guest_body.clone();
        expected["chat_template_kwargs"] = json!({"enable_thinking":false});
        expected["top_k"] = json!(20);
        assert_eq!(sent, expected);
        assert!(head.contains("Authorization: Bearer "));
        // The response is delivered as the provider sent it; nothing of the
        // operator's parameters is echoed into the cell.
        let value: serde_json::Value = serde_json::from_slice(&delivered).unwrap();
        assert_eq!(value, reply);
        let text = String::from_utf8(delivered).unwrap();
        assert!(!text.contains("chat_template_kwargs") && !text.contains("enable_thinking"));
        assert!(!text.contains("top_k"));
    }

    #[test]
    fn operator_parameters_join_the_anthropic_body_after_translation() {
        use serde_json::json;
        let reply = json!({"id":"msg_1","type":"message","role":"assistant","model":"local",
            "content":[{"type":"text","text":"REMOTE-OK"}],"stop_reason":"end_turn",
            "usage":{"input_tokens":4,"output_tokens":2}});
        let (port, server) = capture(reply.to_string());
        let mut token = tempfile::NamedTempFile::new().unwrap();
        writeln!(token, "{}", "a".repeat(32)).unwrap();
        let (mut broker, url) = local_broker(
            port,
            ModelProtocol::AnthropicMessages,
            token.path(),
            json!({"temperature":0.2,"metadata":{"user_id":"fleet-7"},"stop_sequences":["END"]}),
        );
        let request = json!({"apiVersion":"celln.fetch/v1","method":"POST","url":url,
            "body":{"model":"local","stream":false,"max_tokens":256,"messages":[
                {"role":"system","content":"Be brief."},{"role":"user","content":"hi"}]}})
        .to_string();
        let delivered = broker.post_json(&request).unwrap();
        let (head, sent) = server.join().unwrap();
        assert_eq!(
            sent,
            json!({"model":"local","max_tokens":256,"stream":false,"system":"Be brief.",
                "messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}],
                "temperature":0.2,"metadata":{"user_id":"fleet-7"},"stop_sequences":["END"]})
        );
        assert!(head.contains("x-api-key: ") && head.contains("anthropic-version: 2023-06-01"));
        let value: serde_json::Value = serde_json::from_slice(&delivered).unwrap();
        assert_eq!(
            value,
            json!({"choices":[{"index":0,"message":{"role":"assistant","content":"REMOTE-OK"},"finish_reason":"stop"}],
                "usage":{"prompt_tokens":4,"completion_tokens":2,"total_tokens":6}})
        );
    }

    #[test]
    fn parameters_never_widen_the_guest_contract_or_replace_contract_fields() {
        use serde_json::json;
        let pinned = json!({"chat_template_kwargs":{"enable_thinking":false}});
        let mut policy = model_policy();
        policy.json_posts[0].parameters = pinned.as_object().unwrap().clone();
        let wire = |body: &serde_json::Value| {
            json!({"apiVersion":"celln.fetch/v1","method":"POST","url":"https://provider.invalid/chat","body":body}).to_string()
        };
        // The guest still may not send the field the operator pinned, nor any
        // other unknown field: deny_unknown_fields is untouched.
        for (key, value) in [
            ("chat_template_kwargs", json!({"enable_thinking":true})),
            ("temperature", json!(2)),
            ("parameters", pinned.clone()),
        ] {
            let mut body = chat_body();
            body[key] = value;
            let mut broker = HttpBroker::new(policy.clone());
            assert_eq!(
                broker.post_json(&wire(&body)).unwrap_err(),
                refused("unsupported model request parameters")
            );
            assert_eq!(broker.used, 0);
        }
        // A grant that did not come through configure is refused before the
        // credential, DNS or any budget is touched, without naming the key.
        for bad in [
            json!({"max_tokens":4096}),
            json!({"model":"other"}),
            json!({"Bad-Key":1}),
            json!({"a":{"b":{"c":{"d":1}}}}),
        ] {
            let mut policy = model_policy();
            policy.json_posts[0].parameters = bad.as_object().unwrap().clone();
            let mut broker = HttpBroker::new(policy);
            assert_eq!(
                broker.post_json(&wire(&chat_body())).unwrap_err(),
                refused("operator model parameters violate host policy")
            );
            assert_eq!(broker.used, 0);
            assert!(broker.post_output_reserved.is_empty());
        }
        // At merge time a parameter never overwrites what the contract set,
        // in either protocol.
        for protocol in [ModelProtocol::OpenaiChat, ModelProtocol::AnthropicMessages] {
            let mut grant = model_policy().json_posts.remove(0);
            grant.protocol = protocol;
            grant.parameters = pinned.as_object().unwrap().clone();
            let out = outgoing_body(&chat_body(), &grant).unwrap();
            assert_eq!(out["max_tokens"], 512);
            assert_eq!(out["chat_template_kwargs"]["enable_thinking"], false);
            grant.parameters = json!({"max_tokens":4096}).as_object().unwrap().clone();
            assert_eq!(
                outgoing_body(&chat_body(), &grant).unwrap_err(),
                refused(
                    "operator model parameters collide with the provider request; nothing sent"
                )
            );
        }
        // Without parameters the outgoing body is the guest body, unchanged.
        let grant = model_policy().json_posts.remove(0);
        assert_eq!(outgoing_body(&chat_body(), &grant).unwrap(), chat_body());
    }

    fn wire() -> String {
        serde_json::json!({"apiVersion":"celln.fetch/v1","method":"POST","url":"https://example.com/model","body":{"messages":[]}}).to_string()
    }

    fn model_policy() -> HttpPolicy {
        // .invalid plus an absent credential make accidental I/O visible:
        // every refusal below must occur before DNS or credential access.
        let mut policy = HttpPolicy::new(vec!["provider.invalid".into()]);
        policy.json_posts.push(JsonPostGrant {
            protocol: Default::default(),
            url: "https://provider.invalid/chat".into(),
            bearer_token_file: "/must-not-be-read".into(),
            model: "approved".into(),
            max_output_tokens: 512,
            max_total_output_tokens: 1024,
            parameters: Default::default(),
        });
        policy
    }

    fn chat_body() -> serde_json::Value {
        serde_json::json!({"model":"approved","stream":false,"max_tokens":512,
            "messages":[{"role":"user","content":"hello"}]})
    }

    #[test]
    fn independent_get_budget_cannot_buy_more_model_requests() {
        let mut policy = model_policy();
        policy.max_requests = 1;
        policy.get = Some(crate::egress::GetGrant {
            allow_hosts: vec!["fetch.invalid".into()],
            max_requests: 3,
            max_response_bytes: 1024,
            timeout: std::time::Duration::from_secs(1),
        });
        let mut broker = HttpBroker::new(policy);
        // Model allowance spent, GET allowance partially spent. Refusal must
        // occur before DNS or credential access, regardless of GET headroom.
        broker.used = 2;
        broker.get_used = 1;
        let request = serde_json::json!({"apiVersion":"celln.fetch/v1","method":"POST",
            "url":"https://provider.invalid/chat","body":chat_body()})
        .to_string();
        assert_eq!(broker.fetch(&request), Err(FetchDenied::Budget));
        assert_eq!(
            broker.fetch("https://provider.invalid/chat"),
            Err(FetchDenied::Host("provider.invalid".into()))
        );
        broker.get_used = 3;
        broker.used = 4;
        assert_eq!(
            broker.fetch("https://fetch.invalid/file"),
            Err(FetchDenied::Budget)
        );
    }

    #[test]
    fn a_request_may_ask_for_the_granted_cap_and_not_one_token_more() {
        for cap in [256u64, 512, 4096] {
            let mut grant = model_policy().json_posts.remove(0);
            grant.max_output_tokens = cap;
            grant.max_total_output_tokens = 6 * cap;
            let mut body = chat_body();
            body["max_tokens"] = serde_json::json!(cap);
            assert_eq!(validate_chat(&body, &grant), Ok(cap));
            body["max_tokens"] = serde_json::json!(cap + 1);
            assert_eq!(
                validate_chat(&body, &grant),
                Err(refused("model output token limit exceeded"))
            );
            // A worker built before the cap was configurable asks for 512:
            // accepted by any grant of at least that, refused below it.
            body["max_tokens"] = serde_json::json!(512);
            assert_eq!(validate_chat(&body, &grant).is_ok(), cap >= 512);
            // The turn total still bounds a single request.
            grant.max_total_output_tokens = cap - 1;
            body["max_tokens"] = serde_json::json!(cap);
            assert!(validate_chat(&body, &grant).is_err());
        }
    }

    #[test]
    fn model_policy_rejects_escalations_before_io() {
        let cases = [
            ("model", serde_json::json!("other"), "model not granted"),
            (
                "max_tokens",
                serde_json::json!(513),
                "model output token limit exceeded",
            ),
            (
                "max_tokens",
                serde_json::json!(0),
                "model output token limit exceeded",
            ),
            (
                "max_tokens",
                serde_json::json!(-1),
                "unsupported model request parameters",
            ),
            (
                "max_tokens",
                serde_json::json!(1.5),
                "unsupported model request parameters",
            ),
            (
                "stream",
                serde_json::json!(true),
                "unsupported model request parameters",
            ),
            (
                "n",
                serde_json::json!(8),
                "unsupported model request parameters",
            ),
            (
                "max_completion_tokens",
                serde_json::json!(9999),
                "unsupported model request parameters",
            ),
            (
                "temperature",
                serde_json::json!(2),
                "unsupported model request parameters",
            ),
            (
                "messages",
                serde_json::json!([{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://example.com"}}]}]),
                "unsupported model request parameters",
            ),
            (
                "tools",
                serde_json::json!([{"type":"web_search"}]),
                "unsupported model request parameters",
            ),
        ];
        for (field, value, reason) in cases {
            let mut body = chat_body();
            body[field] = value;
            let mut broker = HttpBroker::new(model_policy());
            let raw = serde_json::json!({"apiVersion":"celln.fetch/v1","method":"POST","url":"https://provider.invalid/chat","body":body}).to_string();
            assert_eq!(broker.fetch(&raw).unwrap_err(), refused(reason), "{field}");
            assert_eq!(broker.used(), 0);
            assert!(broker.post_output_reserved.is_empty());
        }
    }

    #[test]
    fn output_reservations_are_cumulative_and_overflow_safe() {
        for reserved in [513, 1024, u64::MAX] {
            let mut broker = HttpBroker::new(model_policy());
            broker
                .post_output_reserved
                .insert("https://provider.invalid/chat".into(), reserved);
            let raw = serde_json::json!({"apiVersion":"celln.fetch/v1","method":"POST","url":"https://provider.invalid/chat","body":chat_body()}).to_string();
            assert_eq!(
                broker.fetch(&raw).unwrap_err(),
                refused("model cumulative output budget exhausted")
            );
            assert_eq!(broker.used(), 0);
        }
    }

    #[test]
    fn failed_requests_do_not_refund_reserved_output() {
        let mut policy = model_policy();
        policy.allow_hosts = vec!["8.8.8.8".into()];
        policy.json_posts[0].url = "https://8.8.8.8/chat".into();
        policy.json_posts[0].max_total_output_tokens = 512;
        let mut broker = HttpBroker::new(policy);
        let raw = serde_json::json!({"apiVersion":"celln.fetch/v1","method":"POST","url":"https://8.8.8.8/chat","body":chat_body()}).to_string();
        // Literal IP authorization needs no DNS, then missing credentials fail
        // before curl starts. No network request is made by this test.
        assert_eq!(
            broker.fetch(&raw).unwrap_err(),
            refused("provider credential unavailable")
        );
        assert_eq!(broker.used(), 1);
        assert_eq!(
            broker.fetch(&raw).unwrap_err(),
            refused("model cumulative output budget exhausted")
        );
        assert_eq!(broker.post_output_reserved["https://8.8.8.8/chat"], 512);
    }

    #[test]
    fn text_and_function_results_fit_the_narrow_contract() {
        let mut body = chat_body();
        body["tools"] = serde_json::json!([{"type":"function","function":{"name":"add","description":"add integers","parameters":{"type":"object"}}}]);
        body["tool_choice"] = "required".into();
        body["messages"] = serde_json::json!([
            {"role":"user","content":"add"},
            {"role":"assistant","content":null,"tool_calls":[{"id":"call1","type":"function","function":{"name":"add","arguments":"{}"}}]},
            {"role":"tool","tool_call_id":"call1","content":"42"}
        ]);
        assert_eq!(
            validate_chat(&body, &model_policy().json_posts[0]).unwrap(),
            512
        );
        for field in ["model", "max_tokens", "stream", "messages"] {
            let mut missing = body.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(validate_chat(&missing, &model_policy().json_posts[0]).is_err());
        }
    }

    #[test]
    fn get_authority_does_not_imply_post_or_credentials() {
        let mut broker = HttpBroker::new(HttpPolicy::new(vec!["example.com".into()]));
        assert_eq!(
            broker.fetch(&wire()).unwrap_err(),
            refused("JSON POST endpoint not granted")
        );
        assert_eq!(broker.used(), 0);
    }

    #[test]
    fn endpoints_are_exact_and_untrusted_headers_are_rejected() {
        let mut policy = HttpPolicy::new(vec!["example.com".into()]);
        policy.json_posts.push(JsonPostGrant {
            protocol: Default::default(),
            url: "https://example.com/model".into(),
            bearer_token_file: "/not-read".into(),
            model: "approved-model".into(),
            max_output_tokens: 512,
            max_total_output_tokens: 1536,
            parameters: Default::default(),
        });
        let broker = HttpBroker::new(policy);
        assert!(broker.grant_for(&parse(&wire()).unwrap()).is_ok());
        for url in [
            "https://example.com/other",
            "https://example.com/model?extra=1",
            "https://evil.example/model",
        ] {
            let mut req = parse(&wire()).unwrap();
            req.url = url.into();
            assert!(broker.grant_for(&req).is_err());
        }
        for field in ["headers", "credential", "proxy"] {
            let mut req: serde_json::Value = serde_json::from_str(&wire()).unwrap();
            req[field] = "untrusted".into();
            assert!(parse(&req.to_string()).is_err());
        }
    }

    #[test]
    fn protocol_is_versioned_bounded_and_object_only() {
        for (field, value) in [
            ("apiVersion", "other"),
            ("method", "PUT"),
            ("body", "not an object"),
        ] {
            let mut req: serde_json::Value = serde_json::from_str(&wire()).unwrap();
            req[field] = value.into();
            assert!(parse(&req.to_string()).is_err());
        }
        assert!(parse(&"x".repeat(8193)).is_err());
    }

    #[test]
    fn credentials_reload_refuse_injection_and_never_appear_in_errors() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("token");
        for token in [
            "first-test-token-at-least-24",
            "rotated-test-token-at-least-24",
        ] {
            std::fs::write(&file, token).unwrap();
            let header = credential_header(&file, ModelProtocol::OpenaiChat).unwrap();
            assert_eq!(
                std::fs::read_to_string(header.path()).unwrap(),
                format!("Authorization: Bearer {token}\n")
            );
        }
        for token in ["short", "secret-with-injected\r\nX-Header: bad"] {
            std::fs::write(&file, token).unwrap();
            assert_eq!(
                credential_header(&file, ModelProtocol::OpenaiChat).unwrap_err(),
                refused("invalid provider credential")
            );
        }
    }
}
