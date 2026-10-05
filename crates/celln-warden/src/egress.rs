//! Host-owned HTTP fetch capability for a cell.
//!
//! This is deliberately a *request broker*, not a network device. The guest
//! never receives AF_INET, DNS, a route, proxy configuration, or credentials.

use std::net::{IpAddr, ToSocketAddrs};
use std::process::Command;
use std::time::Duration;

#[path = "egress_post.rs"]
mod post;
pub use post::{
    model_endpoint_host, model_endpoint_target, JsonPostGrant, ModelEndpoint, ModelProtocol,
    DEFAULT_REQUEST_OUTPUT_TOKENS, REQUEST_OUTPUT_TOKENS,
};

/// The tool allowlist sentinel: `["*"]`, and only that, lets a web tool
/// reach any **public** HTTPS host. It never widens the model path, never
/// admits HTTP, a non-443 port, an unverified certificate or a private,
/// reserved or IPv6 address. An empty list still means no egress.
pub const ANY_PUBLIC_HOST: &str = "*";

/// Whether `host` is admitted by a tool allowlist: exactly `["*"]` admits any
/// host (the address check still applies); otherwise an exact,
/// case-insensitive name match. A `"*"` mixed with other entries is not a
/// wildcard (configuration refuses it) and so matches nothing extra.
pub fn host_allowed(list: &[String], host: &str) -> bool {
    if host.is_empty() {
        return false;
    }
    if list.len() == 1 && list[0] == ANY_PUBLIC_HOST {
        return true;
    }
    list.iter()
        .any(|allowed| allowed != ANY_PUBLIC_HOST && allowed.eq_ignore_ascii_case(host))
}

/// Who a destination is for. Only the operator-pinned model endpoint may use
/// `allow_insecure`; every agent-selected web tool URL is `Tool`, which is
/// always HTTPS on 443 to a public IPv4 address with a verified certificate.
#[derive(Clone, Copy)]
enum Reach<'a> {
    Model,
    Tool(&'a [String]),
}

/// Independent credential-free GET authority for native starter tools.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetGrant {
    /// Exact hosts, or exactly `["*"]` for any public host. Empty denies.
    pub allow_hosts: Vec<String>,
    pub max_requests: usize,
    pub max_response_bytes: usize,
    pub timeout: Duration,
}

/// Independent credential-free JSON POST authority for native starter tools:
/// exact hosts, a request budget and body/response ceilings. It never carries
/// a credential and never implies GET or model access.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PostGrant {
    /// Exact hosts, or exactly `["*"]` for any public host. Empty denies.
    pub allow_hosts: Vec<String>,
    pub max_requests: usize,
    pub max_body_bytes: usize,
    pub max_response_bytes: usize,
    pub timeout: Duration,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpPolicy {
    /// Exact DNS names this cell may contact. Empty means no egress. The
    /// model path never treats `"*"` as a wildcard; the legacy GET path (no
    /// `get` grant) honours exactly `["*"]` as any public host.
    pub allow_hosts: Vec<String>,
    pub max_requests: usize,
    pub max_response_bytes: usize,
    pub timeout: Duration,
    /// Additional operator-owned authority. A GET host grant never implies
    /// POST or access to provider credentials.
    pub json_posts: Vec<JsonPostGrant>,
    /// Independent run-data authority; HTTPS/model grants never imply this.
    pub workspace: Option<crate::workspace_broker::Grant>,
    /// None preserves the legacy shared GET/model budget. Some uses an
    /// independent GET budget; an empty allowlist explicitly denies all GETs.
    pub get: Option<GetGrant>,
    /// Credential-free JSON POSTs to named hosts; None denies them all.
    pub post: Option<PostGrant>,
    /// Operator opt-in that also permits HTTP and self-signed HTTPS model
    /// endpoints on private addresses. Default false keeps the HTTPS-only,
    /// public-address contract. It applies to the model endpoint only; web
    /// tool GETs and POSTs stay public-only HTTPS regardless.
    pub allow_insecure: bool,
}

impl HttpPolicy {
    pub fn new(allow_hosts: Vec<String>) -> Self {
        Self {
            allow_hosts,
            max_requests: 32,
            max_response_bytes: 1 << 20,
            timeout: Duration::from_secs(10),
            json_posts: Vec::new(),
            workspace: None,
            get: None,
            post: None,
            allow_insecure: false,
        }
    }
}

/// The lowercase host of an http(s) URL, without port, credentials or path.
pub(crate) fn url_host(url: &str) -> Option<String> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let authority = rest.split('/').next()?;
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    let host = authority
        .rsplit_once(':')
        .map_or(authority, |(host, _)| host);
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// A validated egress destination with its resolved address.
#[derive(Debug, PartialEq, Eq)]
struct Authorized {
    scheme: String,
    host: String,
    port: u16,
    ip: IpAddr,
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

/// Host-owned mediated transport. It receives only the validated provider body,
/// never a guest-selected destination or headers. The implementation owns the
/// fixed gateway origin, scoped credential, request identity and cancellation.
pub trait ModelRelay: Send {
    fn invoke(&mut self, body: &[u8]) -> Result<Vec<u8>, FetchDenied>;
}

/// Per-cell host capability state. It lives with `warden`, never in the
/// guest, so a compromised guest can at most spend its own bounded allowance.
pub struct HttpBroker {
    policy: HttpPolicy,
    used: usize,
    get_used: usize,
    post_used: usize,
    post_output_reserved: std::collections::BTreeMap<String, u64>,
    model_relay: Option<Box<dyn ModelRelay>>,
}

impl HttpBroker {
    pub fn new(policy: HttpPolicy) -> Self {
        Self {
            policy,
            used: 0,
            get_used: 0,
            post_used: 0,
            post_output_reserved: Default::default(),
            model_relay: None,
        }
    }

    /// Separate constructor: mediated model execution cannot carry a standing
    /// provider credential file or silently fall back to the legacy transport.
    pub fn new_mediated(
        policy: HttpPolicy,
        relay: Box<dyn ModelRelay>,
    ) -> Result<Self, FetchDenied> {
        if policy.allow_insecure
            || policy.json_posts.len() != 1
            || !policy.json_posts[0]
                .bearer_token_file
                .as_os_str()
                .is_empty()
        {
            return Err(FetchDenied::Fetch(
                "mediated model grant requires exactly one credential-free route".into(),
            ));
        }
        let mut broker = Self::new(policy);
        broker.model_relay = Some(relay);
        Ok(broker)
    }

    /// Transport identity only; exposes neither credentials nor mutable policy.
    pub fn is_mediated(&self) -> bool {
        self.model_relay.is_some()
    }

    /// Attach independently admitted, child-bound artifact authority only
    /// after validating the model-only transfer. No network grant is added.
    pub fn with_scoped_artifacts(
        mut self,
        grant: crate::workspace_broker::Grant,
    ) -> Result<Self, FetchDenied> {
        if !self.is_mediated()
            || self.policy.workspace.is_some()
            || !self.policy.allow_hosts.is_empty()
            || self.policy.get.is_some()
            || self.policy.post.is_some()
        {
            return Err(FetchDenied::Fetch(
                "invalid scoped artifact transport".into(),
            ));
        }
        self.policy.workspace = Some(grant);
        Ok(self)
    }

    /// Check a model-only transfer against an already reserved native turn.
    /// This cannot establish tenant identity; the supplying owner must bind the
    /// relay to that turn's independently verified capability context.
    pub fn fits_mediated_turn(&self, requests: u64, output_tokens: u64) -> bool {
        self.is_mediated()
            && self.policy.allow_hosts.is_empty()
            && self.policy.workspace.is_none()
            && self.policy.get.is_none()
            && self.policy.post.is_none()
            && (self.policy.max_requests as u128) <= u128::from(requests)
            && self.policy.json_posts.len() == 1
            && self.policy.json_posts[0].max_total_output_tokens <= output_tokens
            && self.policy.json_posts[0].max_output_tokens
                <= self.policy.json_posts[0].max_total_output_tokens
    }

    pub fn used(&self) -> usize {
        self.used
    }

    /// Validate a request and pin its DNS result before curl is allowed to
    /// connect. Pinning closes a DNS-rebinding SSRF hole. `allow_insecure`
    /// relaxes scheme, port and address only for `Reach::Model`.
    fn authorize(&self, raw: &str, reach: Reach<'_>) -> Result<Authorized, FetchDenied> {
        let insecure = matches!(reach, Reach::Model) && self.policy.allow_insecure;
        let (scheme, rest) = if let Some(rest) = raw.strip_prefix("https://") {
            ("https", rest)
        } else if insecure {
            (
                "http",
                raw.strip_prefix("http://").ok_or(FetchDenied::Scheme)?,
            )
        } else {
            return Err(FetchDenied::Scheme);
        };
        let authority = rest.split('/').next().unwrap_or_default();
        if authority.is_empty() || authority.contains('@') {
            return Err(FetchDenied::Authority);
        }
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) => {
                let port: u16 = port.parse().map_err(|_| FetchDenied::Authority)?;
                if port == 0 {
                    return Err(FetchDenied::Authority);
                }
                (host.to_ascii_lowercase(), port)
            }
            None => (
                authority.to_ascii_lowercase(),
                if scheme == "https" { 443 } else { 80 },
            ),
        };
        if host.is_empty() || (!insecure && port != 443) {
            return Err(FetchDenied::Authority);
        }
        let admitted = match reach {
            // The model origin is an exact operator-pinned name, never "*".
            Reach::Model => self
                .policy
                .allow_hosts
                .iter()
                .any(|h| h != ANY_PUBLIC_HOST && h.eq_ignore_ascii_case(&host)),
            Reach::Tool(list) => host_allowed(list, &host),
        };
        if !admitted {
            return Err(FetchDenied::Host(host));
        }
        let addresses: Vec<IpAddr> = if celln_control::current().is_some() {
            // NSS resolution can block. Keep it in an owned subprocess under
            // the same execution deadline, never an abandoned resolver thread.
            let out = celln_control::process::output_with_timeout(
                Command::new("getent").args(["--", "ahostsv4", &host]),
                Some(self.policy.timeout),
            )
            .map_err(|e| FetchDenied::Fetch(e.to_string()))?;
            if !out.status.success() {
                return Err(FetchDenied::Address);
            }
            String::from_utf8_lossy(&out.stdout)
                .lines()
                .filter_map(|line| line.split_whitespace().next()?.parse().ok())
                .collect()
        } else {
            (host.as_str(), port)
                .to_socket_addrs()
                .map_err(|_| FetchDenied::Address)?
                .map(|a| a.ip())
                .collect()
        };
        // IPv6 is never used: only an A record is pinned, so a tool cannot
        // reach a v6 link-local, ULA or v4-mapped private address.
        let ip = if insecure {
            addresses
                .into_iter()
                .find(|a| matches!(a, IpAddr::V4(_)))
                .ok_or(FetchDenied::Address)?
        } else {
            addresses
                .into_iter()
                .find_map(|a| match a {
                    IpAddr::V4(v) if is_public_v4(v.octets()) => Some(IpAddr::V4(v)),
                    _ => None,
                })
                .ok_or(FetchDenied::Address)?
        };
        Ok(Authorized {
            scheme: scheme.into(),
            host,
            port,
            ip,
        })
    }

    /// HTTPS GET only, bounded body and time, DNS result pinned. Redirects are
    /// followed one hop at a time so every destination is independently
    /// authorised; `curl --location` would bypass the allowlist on hop two.
    pub fn fetch(&mut self, raw: &str) -> Result<Vec<u8>, FetchDenied> {
        // Model requests carry every tool schema and the conversation; the
        // workspace and plain POST paths bound themselves more tightly below.
        if raw.len() > 32768 {
            return Err(FetchDenied::Fetch(
                "request exceeds broker wire budget".into(),
            ));
        }
        if raw.starts_with('{') {
            let value: serde_json::Value = serde_json::from_str(raw)
                .map_err(|_| FetchDenied::Fetch("invalid broker request".into()))?;
            if value.get("apiVersion").and_then(|v| v.as_str()) == Some("celln.workspace/v1") {
                return self
                    .policy
                    .workspace
                    .as_ref()
                    .ok_or_else(|| FetchDenied::Fetch("workspace access not granted".into()))?
                    .request(raw)
                    .map_err(FetchDenied::Fetch);
            }
            return self.post_json(raw);
        }
        let mut url = raw.to_owned();
        for _ in 0..=5 {
            let (max_requests, max_response_bytes, timeout, used) = match &self.policy.get {
                Some(grant) => (
                    grant.max_requests,
                    grant.max_response_bytes,
                    grant.timeout,
                    self.get_used,
                ),
                None => (
                    self.policy.max_requests,
                    self.policy.max_response_bytes,
                    self.policy.timeout,
                    self.used,
                ),
            };
            if used >= max_requests {
                return Err(FetchDenied::Budget);
            }
            // A GET is always a web tool request: the independent GET
            // allowlist (or the legacy shared one), checked before any DNS
            // or I/O, then public-only HTTPS whatever the model profile says.
            let hosts = match &self.policy.get {
                Some(grant) => &grant.allow_hosts,
                None => &self.policy.allow_hosts,
            };
            let authorized = self.authorize(&url, Reach::Tool(hosts))?;
            self.used += 1;
            self.get_used += 1;
            let header =
                tempfile::NamedTempFile::new().map_err(|e| FetchDenied::Fetch(e.to_string()))?;
            let out = celln_control::process::output_with_timeout(
                Command::new("curl")
                    .args([
                        "--disable",
                        "--globoff",
                        "--noproxy",
                        "*",
                        "--silent",
                        "--show-error",
                        "--proto",
                        "=https",
                        "--max-redirs",
                        "0",
                    ])
                    .arg("--max-time")
                    .arg(timeout.as_secs_f64().to_string())
                    .arg("--max-filesize")
                    .arg(max_response_bytes.to_string())
                    .arg("--resolve")
                    .arg(format!(
                        "{}:{}:{}",
                        authorized.host, authorized.port, authorized.ip
                    ))
                    .arg("--dump-header")
                    .arg(header.path())
                    .arg(&url),
                Some(timeout),
            )
            .map_err(|e| FetchDenied::Fetch(e.to_string()))?;
            let headers = std::fs::read_to_string(header.path()).unwrap_or_default();
            if !out.status.success() {
                return Err(FetchDenied::Fetch(
                    String::from_utf8_lossy(&out.stderr).trim().into(),
                ));
            }
            if out.stdout.len() > max_response_bytes {
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
            let location =
                location.ok_or_else(|| FetchDenied::Fetch("redirect without Location".into()))?;
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
        name.eq_ignore_ascii_case("location")
            .then(|| value.trim().to_owned())
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
    let rest = current
        .strip_prefix("https://")
        .ok_or(FetchDenied::Scheme)?;
    let authority = rest.split('/').next().ok_or(FetchDenied::Authority)?;
    if location.starts_with('/') {
        return Ok(format!("https://{authority}{location}"));
    }
    let base = current.rsplit_once('/').map(|(p, _)| p).unwrap_or(current);
    Ok(format!("{base}/{location}"))
}

/// Globally routable unicast IPv4 only. Refused: 0/8 (this network),
/// 10/8, 100.64/10 (CGNAT), 127/8, 169.254/16 (link-local, cloud metadata),
/// 172.16/12, 192.0.0/16 (covers 192.0.0/24 IETF and 192.0.2/24 TEST-NET-1),
/// 192.88.99/24 (6to4 relay), 192.168/16, 198.18/15 (benchmarking),
/// 198.51.100/24 (TEST-NET-2), 203.0.113/24 (TEST-NET-3) and 224/3
/// (multicast, reserved, 255.255.255.255 broadcast).
fn is_public_v4(o: [u8; 4]) -> bool {
    let [a, b, c, _] = o;
    !(matches!(a, 0 | 10 | 127 | 224..=255)
        || a == 100 && (64..=127).contains(&b)
        || a == 169 && b == 254
        || a == 172 && (16..=31).contains(&b)
        || a == 192 && (b == 0 || b == 168)
        || a == 192 && b == 88 && c == 99
        || a == 198 && (b == 18 || b == 19)
        || a == 198 && b == 51 && c == 100
        || a == 203 && b == 0 && c == 113)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_ambient_and_undeclared_reach() {
        let b = HttpBroker::new(HttpPolicy::new(vec!["example.com".into()]));
        assert_eq!(
            b.authorize("http://example.com/", Reach::Model)
                .unwrap_err(),
            FetchDenied::Scheme
        );
        assert!(matches!(
            b.authorize("https://evil.example/", Reach::Model),
            Err(FetchDenied::Host(_))
        ));
        assert_eq!(
            b.authorize("https://example.com:444/", Reach::Model),
            Err(FetchDenied::Authority)
        );
    }

    #[test]
    fn insecure_opt_in_allows_private_http_and_ports() {
        let mut policy = HttpPolicy::new(vec!["192.168.1.237".into()]);
        policy.allow_insecure = true;
        let broker = HttpBroker::new(policy);
        let authorized = broker
            .authorize(
                "http://192.168.1.237:8080/v1/chat/completions",
                Reach::Model,
            )
            .unwrap();
        assert_eq!(authorized.scheme, "http");
        assert_eq!(authorized.host, "192.168.1.237");
        assert_eq!(authorized.port, 8080);
        assert_eq!(authorized.ip.to_string(), "192.168.1.237");
        // Without the opt-in the same request stays refused.
        let strict = HttpBroker::new(HttpPolicy::new(vec!["192.168.1.237".into()]));
        assert_eq!(
            strict
                .authorize("http://192.168.1.237:8080/v1", Reach::Model)
                .unwrap_err(),
            FetchDenied::Scheme
        );
    }

    #[test]
    fn url_host_is_the_bare_lowercase_authority() {
        assert_eq!(
            url_host("https://Hooks.Example/in?x=1"),
            Some("hooks.example".into())
        );
        assert_eq!(
            url_host("http://echo.svc:8080/post"),
            Some("echo.svc".into())
        );
        assert_eq!(url_host("https://user@hooks.example/"), None);
        assert_eq!(url_host("ftp://hooks.example/"), None);
        assert_eq!(url_host("https:///path"), None);
    }

    #[test]
    fn private_addresses_are_never_public() {
        for private in [
            [0, 0, 0, 0],
            [0, 255, 255, 255],
            [10, 0, 0, 1],
            [10, 255, 255, 255],
            [100, 64, 0, 1],
            [100, 127, 255, 255],
            [127, 0, 0, 1],
            [127, 255, 255, 254],
            [169, 254, 0, 1],
            [169, 254, 169, 254],
            [172, 16, 0, 1],
            [172, 31, 255, 255],
            [192, 0, 0, 1],
            [192, 0, 2, 1],
            [192, 88, 99, 1],
            [192, 168, 1, 1],
            [198, 18, 0, 1],
            [198, 19, 255, 255],
            [198, 51, 100, 7],
            [203, 0, 113, 9],
            [224, 0, 0, 1],
            [239, 255, 255, 250],
            [240, 0, 0, 1],
            [255, 255, 255, 255],
        ] {
            assert!(!is_public_v4(private), "{private:?} must not be public");
        }
        for public in [
            [1, 1, 1, 1],
            [8, 8, 8, 8],
            [93, 184, 215, 14],
            [100, 63, 255, 255],
            [100, 128, 0, 1],
            [172, 15, 255, 255],
            [172, 32, 0, 1],
            [192, 88, 98, 1],
            [192, 169, 0, 1],
            [198, 17, 255, 255],
            [198, 20, 0, 1],
            [198, 51, 101, 1],
            [203, 0, 114, 1],
            [223, 255, 255, 254],
        ] {
            assert!(is_public_v4(public), "{public:?} is public");
        }
    }

    fn hosts(list: &[&str]) -> Vec<String> {
        list.iter().map(|h| (*h).into()).collect()
    }

    #[test]
    fn host_allowed_matrix() {
        // Exactly ["*"]: any host name (the address check still applies).
        assert!(host_allowed(&hosts(&["*"]), "example.com"));
        assert!(host_allowed(&hosts(&["*"]), "anything.example"));
        // Explicit lists stay exact and case-insensitive.
        assert!(host_allowed(&hosts(&["example.com"]), "EXAMPLE.com"));
        assert!(!host_allowed(&hosts(&["example.com"]), "evil.example"));
        assert!(!host_allowed(&hosts(&["example.com"]), "sub.example.com"));
        // Empty is no egress, never fail open.
        assert!(!host_allowed(&[], "example.com"));
        assert!(!host_allowed(&[], "*"));
        // "*" mixed with others is not a wildcard (and validation refuses it).
        assert!(!host_allowed(&hosts(&["*", "a.com"]), "b.com"));
        assert!(host_allowed(&hosts(&["*", "a.com"]), "a.com"));
        assert!(!host_allowed(&hosts(&["*", "*"]), "b.com"));
        // Patterns are not globs.
        assert!(!host_allowed(&hosts(&["*.example.com"]), "a.example.com"));
        assert!(!host_allowed(&hosts(&["*"]), ""));
    }

    /// A model profile that opts into private/insecure model reach, with
    /// wildcard web tool grants: the worst case for tool SSRF.
    fn insecure_wildcard_policy() -> HttpPolicy {
        let mut policy = HttpPolicy::new(vec!["192.168.1.237".into()]);
        policy.allow_insecure = true;
        policy.get = Some(GetGrant {
            allow_hosts: hosts(&["*"]),
            max_requests: 8,
            max_response_bytes: 4096,
            timeout: Duration::from_secs(1),
        });
        policy.post = Some(PostGrant {
            allow_hosts: hosts(&["*"]),
            max_requests: 8,
            max_body_bytes: 4096,
            max_response_bytes: 4096,
            timeout: Duration::from_secs(1),
        });
        policy
    }

    #[test]
    fn wildcard_tool_reach_is_public_https_only() {
        let broker = HttpBroker::new(insecure_wildcard_policy());
        let any = hosts(&["*"]);
        // A public literal is admitted under the wildcard, pinned, port 443.
        let ok = broker
            .authorize("https://1.1.1.1/x", Reach::Tool(&any))
            .unwrap();
        assert_eq!((ok.scheme.as_str(), ok.port), ("https", 443));
        assert_eq!(ok.ip.to_string(), "1.1.1.1");
        for private in [
            "https://10.0.0.1/",
            "https://127.0.0.1/",
            "https://localhost/",
            "https://169.254.169.254/latest/meta-data/",
            "https://192.168.1.237/v1",
            "https://100.64.0.1/",
            "https://198.51.100.7/",
            "https://203.0.113.9/",
            "https://192.88.99.1/",
            "https://0.0.0.0/",
            "https://255.255.255.255/",
        ] {
            assert_eq!(
                broker.authorize(private, Reach::Tool(&any)).unwrap_err(),
                FetchDenied::Address,
                "{private}"
            );
        }
        // Even with allow_insecure on the model profile: no http, no port.
        assert_eq!(
            broker
                .authorize("http://1.1.1.1/", Reach::Tool(&any))
                .unwrap_err(),
            FetchDenied::Scheme
        );
        assert_eq!(
            broker
                .authorize("https://1.1.1.1:8443/", Reach::Tool(&any))
                .unwrap_err(),
            FetchDenied::Authority
        );
        // IPv6 literals are never pinned for a tool.
        assert!(broker
            .authorize("https://[::1]/", Reach::Tool(&any))
            .is_err());
    }

    #[test]
    fn tool_get_refuses_private_http_and_redirects_despite_insecure_model() {
        let mut broker = HttpBroker::new(insecure_wildcard_policy());
        for url in [
            "https://10.0.0.1/",
            "https://169.254.169.254/latest/meta-data/",
            "https://192.168.1.237/v1/models",
        ] {
            assert_eq!(broker.fetch(url).unwrap_err(), FetchDenied::Address);
        }
        assert_eq!(
            broker.fetch("http://192.168.1.237:8080/").unwrap_err(),
            FetchDenied::Scheme
        );
        assert_eq!(
            broker.fetch("http://example.com/").unwrap_err(),
            FetchDenied::Scheme
        );
        // Refused before any I/O: no budget spent.
        assert_eq!((broker.used, broker.get_used), (0, 0));
        // A redirect hop is re-authorised as a tool request: a public origin
        // cannot bounce the broker into private or plaintext reach.
        let any = hosts(&["*"]);
        for location in [
            "https://169.254.169.254/latest/meta-data/",
            "//127.0.0.1/admin",
            "https://192.168.1.237:8080/",
        ] {
            let next = redirect_url("https://1.1.1.1/start", location).unwrap();
            assert!(
                broker.authorize(&next, Reach::Tool(&any)).is_err(),
                "{next}"
            );
        }
        // A plaintext Location never leaves the current https origin.
        let next = redirect_url("https://1.1.1.1/a/b", "http://10.0.0.1/").unwrap();
        assert!(next.starts_with("https://1.1.1.1/"), "{next}");
    }

    #[test]
    fn legacy_get_without_grant_is_tool_reach_too() {
        // The legacy shared list also names the private model host, but a
        // GET is a tool request: allow_insecure does not extend to it.
        let mut policy = HttpPolicy::new(vec!["192.168.1.237".into()]);
        policy.allow_insecure = true;
        let mut broker = HttpBroker::new(policy);
        assert_eq!(
            broker.fetch("https://192.168.1.237/").unwrap_err(),
            FetchDenied::Address
        );
        assert_eq!(
            broker.fetch("http://192.168.1.237:8080/").unwrap_err(),
            FetchDenied::Scheme
        );
    }

    #[test]
    fn model_reach_never_honours_the_wildcard() {
        let mut policy = HttpPolicy::new(hosts(&["*"]));
        policy.allow_insecure = true;
        let broker = HttpBroker::new(policy);
        assert!(matches!(
            broker.authorize("http://192.168.1.237:8080/v1", Reach::Model),
            Err(FetchDenied::Host(_))
        ));
        assert!(matches!(
            broker.authorize("https://1.1.1.1/v1", Reach::Model),
            Err(FetchDenied::Host(_))
        ));
        // Empty tool list denies everything.
        assert!(matches!(
            broker.authorize("https://1.1.1.1/", Reach::Tool(&[])),
            Err(FetchDenied::Host(_))
        ));
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
