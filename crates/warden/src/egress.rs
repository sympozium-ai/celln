//! Host-owned HTTP fetch capability for a cell.
//!
//! This is deliberately a *request broker*, not a network device. The guest
//! never receives AF_INET, DNS, a route, proxy configuration, or credentials.

use std::net::{IpAddr, ToSocketAddrs};
use std::process::Command;
use std::time::Duration;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpPolicy {
    /// Exact DNS names this cell may contact. Empty means no egress.
    pub allow_hosts: Vec<String>,
    pub max_requests: usize,
    pub max_response_bytes: usize,
    pub timeout: Duration,
}

impl HttpPolicy {
    pub fn new(allow_hosts: Vec<String>) -> Self {
        Self {
            allow_hosts,
            max_requests: 32,
            max_response_bytes: 1 << 20,
            timeout: Duration::from_secs(10),
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FetchDenied {
    #[error("only https URLs are permitted")]
    Scheme,
    #[error("URL must have a host and may not contain credentials or a non-443 port")]
    Authority,
    #[error("host {0:?} is not declared in this cell's allowlist")]
    Host(String),
    #[error("request budget exhausted")]
    Budget,
    #[error("host did not resolve to a public IPv4 address")]
    Address,
    #[error("host fetch failed: {0}")]
    Fetch(String),
}

/// Per-cell host capability state. It lives with `warden`, never in the
/// guest, so a compromised guest can at most spend its own bounded allowance.
pub struct HttpBroker {
    policy: HttpPolicy,
    used: usize,
}

impl HttpBroker {
    pub fn new(policy: HttpPolicy) -> Self {
        Self { policy, used: 0 }
    }

    pub fn used(&self) -> usize {
        self.used
    }

    /// Validate a request and pin its DNS result before curl is allowed to
    /// connect. Pinning closes a DNS-rebinding SSRF hole.
    fn authorize(&self, raw: &str) -> Result<(String, IpAddr), FetchDenied> {
        let rest = raw.strip_prefix("https://").ok_or(FetchDenied::Scheme)?;
        let authority = rest.split('/').next().unwrap_or_default();
        if authority.is_empty() || authority.contains('@') {
            return Err(FetchDenied::Authority);
        }
        let host = authority.split(':').next().unwrap_or_default().to_ascii_lowercase();
        if host.is_empty() || (authority.contains(':') && !authority.ends_with(":443")) {
            return Err(FetchDenied::Authority);
        }
        if !self.policy.allow_hosts.iter().any(|h| h.eq_ignore_ascii_case(&host)) {
            return Err(FetchDenied::Host(host));
        }
        let ip = (host.as_str(), 443)
            .to_socket_addrs()
            .map_err(|_| FetchDenied::Address)?
            .find_map(|a| match a.ip() {
                IpAddr::V4(v) if is_public_v4(v.octets()) => Some(IpAddr::V4(v)),
                _ => None,
            })
            .ok_or(FetchDenied::Address)?;
        Ok((host, ip))
    }

    /// HTTPS GET only, bounded body and time, DNS result pinned. Redirects are
    /// followed one hop at a time so every destination is independently
    /// authorised; `curl --location` would bypass the allowlist on hop two.
    pub fn fetch(&mut self, raw: &str) -> Result<Vec<u8>, FetchDenied> {
        let mut url = raw.to_owned();
        for _ in 0..=5 {
            if self.used >= self.policy.max_requests {
                return Err(FetchDenied::Budget);
            }
            let (host, ip) = self.authorize(&url)?;
            self.used += 1;
            let header = std::env::temp_dir().join(format!(
                "nous-fetch-{}-{}",
                std::process::id(),
                self.used
            ));
            let out = Command::new("curl")
                .args(["--silent", "--show-error", "--proto", "=https", "--max-redirs", "0"])
                .arg("--max-time")
                .arg(self.policy.timeout.as_secs().to_string())
                .arg("--max-filesize")
                .arg(self.policy.max_response_bytes.to_string())
                .arg("--resolve")
                .arg(format!("{host}:443:{ip}"))
                .arg("--dump-header")
                .arg(&header)
                .arg(&url)
                .output()
                .map_err(|e| FetchDenied::Fetch(e.to_string()))?;
            let headers = std::fs::read_to_string(&header).unwrap_or_default();
            let _ = std::fs::remove_file(&header);
            if !out.status.success() {
                return Err(FetchDenied::Fetch(String::from_utf8_lossy(&out.stderr).trim().into()));
            }
            if out.stdout.len() > self.policy.max_response_bytes {
                return Err(FetchDenied::Fetch("response exceeded byte budget".into()));
            }
            let (status, location) = response_status_and_location(&headers)
                .ok_or_else(|| FetchDenied::Fetch("missing HTTP response headers".into()))?;
            if !(300..400).contains(&status) {
                if status >= 400 {
                    return Err(FetchDenied::Fetch(format!("HTTP {status}")));
                }
                return Ok(out.stdout);
            }
            let location = location.ok_or_else(|| FetchDenied::Fetch("redirect without Location".into()))?;
            url = redirect_url(&url, &location)?;
        }
        Err(FetchDenied::Fetch("too many redirects (limit 5)".into()))
    }
}

fn response_status_and_location(headers: &str) -> Option<(u16, Option<String>)> {
    let block = headers
        .split("\r\n\r\n")
        .filter(|b| b.starts_with("HTTP/"))
        .last()?;
    let status = block.split_whitespace().nth(1)?.parse().ok()?;
    let location = block.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("location").then(|| value.trim().to_owned())
    });
    Some((status, location))
}

fn redirect_url(current: &str, location: &str) -> Result<String, FetchDenied> {
    if location.starts_with("https://") {
        return Ok(location.to_owned());
    }
    if let Some(host_relative) = location.strip_prefix("//") {
        return Ok(format!("https://{host_relative}"));
    }
    let rest = current.strip_prefix("https://").ok_or(FetchDenied::Scheme)?;
    let authority = rest.split('/').next().ok_or(FetchDenied::Authority)?;
    if location.starts_with('/') {
        return Ok(format!("https://{authority}{location}"));
    }
    let base = current.rsplit_once('/').map(|(p, _)| p).unwrap_or(current);
    Ok(format!("{base}/{location}"))
}

fn is_public_v4(o: [u8; 4]) -> bool {
    let [a, b, _, _] = o;
    !matches!(a, 0 | 10 | 127 | 224..=255)
        && !(a == 100 && (64..=127).contains(&b))
        && !(a == 169 && b == 254)
        && !(a == 172 && (16..=31).contains(&b))
        && !(a == 192 && (b == 0 || b == 168))
        && !(a == 198 && (b == 18 || b == 19))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_ambient_and_undeclared_reach() {
        let b = HttpBroker::new(HttpPolicy::new(vec!["example.com".into()]));
        assert_eq!(b.authorize("http://example.com/").unwrap_err(), FetchDenied::Scheme);
        assert!(matches!(b.authorize("https://evil.example/"), Err(FetchDenied::Host(_))));
        assert_eq!(b.authorize("https://example.com:444/"), Err(FetchDenied::Authority));
    }

    #[test]
    fn private_addresses_are_never_public() {
        assert!(!is_public_v4([10, 0, 0, 1]));
        assert!(!is_public_v4([127, 0, 0, 1]));
        assert!(!is_public_v4([192, 168, 1, 1]));
        assert!(is_public_v4([1, 1, 1, 1]));
    }

    #[test]
    fn redirects_are_resolved_then_reauthorised() {
        assert_eq!(
            redirect_url("https://example.com/a/b", "/next").unwrap(),
            "https://example.com/next"
        );
        assert_eq!(
            redirect_url("https://example.com/a/b", "other").unwrap(),
            "https://example.com/a/other"
        );
        assert_eq!(
            redirect_url("https://example.com/a", "//other.example/x").unwrap(),
            "https://other.example/x"
        );
    }
}
