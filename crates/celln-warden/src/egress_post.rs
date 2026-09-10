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
                || tools.len() > 16
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
    if raw.len() > 8192 {
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
        let grant = self.grant_for(&request)?.clone();
        let output_tokens = validate_chat(&request.body, &grant)?;
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
        let authorized = self.authorize(&request.url)?;
        self.used += 1;
        self.post_output_reserved.insert(request.url.clone(), next);
        let credential = credential_header(&grant.bearer_token_file, grant.protocol)?;
        let mut body =
            tempfile::NamedTempFile::new().map_err(|_| refused("request staging failed"))?;
        let provider_body = provider_request(&request.body, grant.protocol)?;
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::egress::HttpPolicy;

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
