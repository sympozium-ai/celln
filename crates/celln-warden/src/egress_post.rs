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
        if self.used >= self.policy.max_requests {
            return Err(FetchDenied::Budget);
        }
        let (host, ip) = self.authorize(&request.url)?;
        self.used += 1;
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
