//! Explicit, endpoint-scoped JSON POST authority for an in-cell model client.
//! The wire contains no headers, credential reference, redirects or proxy
//! options. Only the host chooses a credential and the permitted endpoint.

use super::{response_status_and_location, FetchDenied, HttpBroker};
use serde::Deserialize;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::Command;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JsonPostGrant {
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

fn credential_header(path: &std::path::Path) -> Result<tempfile::NamedTempFile, FetchDenied> {
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
    writeln!(header, "Authorization: Bearer {token}")
        .map_err(|_| refused("credential staging failed"))?;
    Ok(header)
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
        if self.used >= self.policy.max_requests {
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
        let (host, ip) = self.authorize(&request.url)?;
        self.used += 1;
        self.post_output_reserved.insert(request.url.clone(), next);
        let credential = credential_header(&grant.bearer_token_file)?;
        let mut body =
            tempfile::NamedTempFile::new().map_err(|_| refused("request staging failed"))?;
        serde_json::to_writer(&mut body, &request.body)
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
                "=https",
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
            .arg(self.policy.max_response_bytes.to_string())
            .arg("--resolve")
            .arg(format!("{host}:443:{ip}"))
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
        Ok(out.stdout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::egress::HttpPolicy;

    fn wire() -> String {
        serde_json::json!({"apiVersion":"celln.fetch/v1","method":"POST","url":"https://example.com/model","body":{"messages":[]}}).to_string()
    }

    fn model_policy() -> HttpPolicy {
        // .invalid plus an absent credential make accidental I/O visible:
        // every refusal below must occur before DNS or credential access.
        let mut policy = HttpPolicy::new(vec!["provider.invalid".into()]);
        policy.json_posts.push(JsonPostGrant {
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
            let header = credential_header(&file).unwrap();
            assert_eq!(
                std::fs::read_to_string(header.path()).unwrap(),
                format!("Authorization: Bearer {token}\n")
            );
        }
        for token in ["short", "secret-with-injected\r\nX-Header: bad"] {
            std::fs::write(&file, token).unwrap();
            assert_eq!(
                credential_header(&file).unwrap_err(),
                refused("invalid provider credential")
            );
        }
    }
}
