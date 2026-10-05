//! Scoped web tool authority (`celln.scoped-https/v1`) derived exclusively
//! from admitted signed tools. It mints no new transport: the derived grants
//! are the fleet path's own `GetGrant`/`PostGrant`, enforced by the same
//! broker (`Reach::Tool`: public IPv4 HTTPS on 443, pinned DNS, redirects
//! re-authorised, POST never redirected). The mediated model route's
//! settings never reach a tool request.
use serde::Deserialize;
use serde_json::Value;
use std::time::Duration;

/// The two signed starter web tools and the broker method each one uses.
/// The entry point is publisher-signed closure identity (checked against the
/// material before this runs), never a guest- or name-chosen label.
const GET_ENTRY: &str = "/https-fetch";
const POST_ENTRY: &str = "/https-post-json";

/// The fleet profile's POST body ceiling; never more than the signed
/// argument bound of the tool that carries it.
const POST_BODY_BYTES: u64 = 4096;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Limits {
    allow_hosts: Vec<String>,
    max_requests: u64,
    max_response_bytes: u64,
    timeout_millis: u64,
}

fn any(hosts: &[String]) -> bool {
    hosts.len() == 1 && hosts[0] == warden::egress::ANY_PUBLIC_HOST
}

/// The same host rules Sympozium's resolver applies: exactly `["*"]`, or
/// 1..16 distinct lowercase multi-label DNS names. No globs, ports or URLs.
fn valid_hosts(hosts: &[String]) -> bool {
    if hosts.is_empty() || hosts.len() > 16 {
        return false;
    }
    if any(hosts) {
        return true;
    }
    let mut seen = std::collections::BTreeSet::new();
    hosts.iter().all(|host| {
        host.len() <= 253
            && host.contains('.')
            && seen.insert(host.as_str())
            && host.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            })
    })
}

fn limits(value: &Value, tool_timeout: &Value) -> Result<Limits, String> {
    let limits: Limits =
        serde_json::from_value(value.clone()).map_err(|_| "AUTH_PROTOCOL_UNSUPPORTED")?;
    let tool_timeout = tool_timeout.as_u64().ok_or("AUTH_PROTOCOL_UNSUPPORTED")?;
    if !valid_hosts(&limits.allow_hosts) {
        return Err("AUTH_PROTOCOL_UNSUPPORTED".into());
    }
    if !(1..=16).contains(&limits.max_requests)
        || !(1..=4096).contains(&limits.max_response_bytes)
        || !(1..=30000).contains(&limits.timeout_millis)
        || limits.timeout_millis > tool_timeout
    {
        return Err("AUTH_LIMIT_OUT_OF_RANGE".into());
    }
    Ok(limits)
}

/// Every signed host must be admitted by the material: `["*"]` only by
/// `["*"]`, an explicit name only by `["*"]` or the same name.
fn within(signed: &[String], declared: &[String]) -> bool {
    any(declared) || (!any(signed) && signed.iter().all(|h| declared.contains(h)))
}

/// One method's cell-wide grant: the minimum of every selected tool's
/// signed ceilings for that method, never a sum.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Grant {
    hosts: Vec<String>,
    requests: usize,
    response_bytes: usize,
    timeout_ms: u64,
    body_bytes: usize,
}

impl Grant {
    fn intersect(&mut self, other: Grant) -> Result<(), String> {
        self.hosts = if any(&other.hosts) {
            std::mem::take(&mut self.hosts)
        } else if any(&self.hosts) {
            other.hosts
        } else {
            self.hosts
                .iter()
                .filter(|h| other.hosts.contains(h))
                .cloned()
                .collect()
        };
        if self.hosts.is_empty() {
            return Err("AUTH_REQUEST_BINDING_MISMATCH".into());
        }
        self.requests = self.requests.min(other.requests);
        self.response_bytes = self.response_bytes.min(other.response_bytes);
        self.timeout_ms = self.timeout_ms.min(other.timeout_ms);
        self.body_bytes = self.body_bytes.min(other.body_bytes);
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Policy {
    get: Option<Grant>,
    post: Option<Grant>,
}

impl Policy {
    /// The broker grants for one disposable turn or one-shot run, each
    /// timeout also bounded by the work's remaining deadline.
    pub(super) fn grants(
        &self,
        remaining: Duration,
    ) -> (
        Option<warden::egress::GetGrant>,
        Option<warden::egress::PostGrant>,
    ) {
        let timeout = |ms: u64| Duration::from_millis(ms).min(remaining);
        (
            self.get.as_ref().map(|g| warden::egress::GetGrant {
                allow_hosts: g.hosts.clone(),
                max_requests: g.requests,
                max_response_bytes: g.response_bytes,
                timeout: timeout(g.timeout_ms),
            }),
            self.post.as_ref().map(|g| warden::egress::PostGrant {
                allow_hosts: g.hosts.clone(),
                max_requests: g.requests,
                max_body_bytes: g.body_bytes,
                max_response_bytes: g.response_bytes,
                timeout: timeout(g.timeout_ms),
            }),
        )
    }
}

/// Called at prepare, at start and before every turn. The existing v1
/// decision already signs `tools[].limits.https`; material may attenuate
/// neither away nor beyond it.
pub(super) fn derive(execution: &Value, decision: &Value) -> Result<Option<Policy>, String> {
    let materials = execution["tools"]
        .as_array()
        .ok_or("AUTH_PROTOCOL_UNSUPPORTED")?;
    let tools = decision["tools"]
        .as_array()
        .ok_or("AUTH_PROTOCOL_UNSUPPORTED")?;
    if materials.len() != tools.len() {
        return Err("AUTH_REQUEST_BINDING_MISMATCH".into());
    }
    let mut policy: Option<Policy> = None;
    for (material, tool) in materials.iter().zip(tools) {
        let signed_limits = &tool["limits"];
        let declared_limits = &material["spec"]["limits"];
        let signed = &signed_limits["https"];
        let declared = &declared_limits["https"];
        if signed.is_null() && declared.is_null() {
            continue;
        }
        // One broker capability per tool, a model route to carry it, and
        // no runtime workspace: exactly the artifact rules.
        if decision["route"]["provider"] == "none"
            || signed_limits["workspace"] != "none"
            || declared_limits["workspace"] != "none"
            || !signed_limits["artifacts"].is_null()
            || !declared_limits["artifacts"].is_null()
            || signed_limits["effects"] != "external-side-effects"
            || declared_limits["effects"] != "external-side-effects"
        {
            return Err("AUTH_PROTOCOL_UNSUPPORTED".into());
        }
        let signed = limits(signed, &signed_limits["timeoutMillis"])?;
        let declared = limits(declared, &declared_limits["timeoutMillis"])?;
        if !within(&signed.allow_hosts, &declared.allow_hosts)
            || signed.max_requests > declared.max_requests
            || signed.max_response_bytes > declared.max_response_bytes
            || signed.timeout_millis > declared.timeout_millis
        {
            return Err("AUTH_REQUEST_BINDING_MISMATCH".into());
        }
        let argument_bytes = signed_limits["argumentBytes"]
            .as_u64()
            .ok_or("AUTH_PROTOCOL_UNSUPPORTED")?;
        let grant = Grant {
            hosts: signed.allow_hosts,
            requests: signed.max_requests as usize,
            response_bytes: signed.max_response_bytes as usize,
            timeout_ms: signed.timeout_millis,
            body_bytes: argument_bytes.min(POST_BODY_BYTES) as usize,
        };
        let current = policy.get_or_insert_with(Policy::default);
        let slot = match material["spec"]["entryPoint"].as_str() {
            Some(GET_ENTRY) => &mut current.get,
            Some(POST_ENTRY) => &mut current.post,
            _ => return Err("AUTH_PROTOCOL_UNSUPPORTED".into()),
        };
        match slot {
            Some(existing) => existing.intersect(grant)?,
            None => *slot = Some(grant),
        }
    }
    Ok(policy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn tool(entry: &str, https: Value) -> (Value, Value) {
        let limits = json!({"timeoutMillis":30000,"memoryBytes":268435456,"argumentBytes":8192,
            "outputBytes":32768,"workspace":"none","effects":"external-side-effects",
            "artifacts":null,"https":https});
        (
            json!({"name":entry.trim_start_matches('/'),"spec":{"entryPoint":entry,"limits":limits}}),
            json!({"limits":limits}),
        )
    }

    fn fixture(tools: &[(&str, Value)]) -> (Value, Value) {
        let (materials, bindings): (Vec<_>, Vec<_>) = tools
            .iter()
            .map(|(entry, https)| tool(entry, https.clone()))
            .unzip();
        (
            json!({"tools":materials}),
            json!({"lifecycle":"one-shot","route":{"provider":"fixture"},"tools":bindings}),
        )
    }

    fn starter() -> Value {
        json!({"allowHosts":["*"],"maxRequests":4,"maxResponseBytes":4096,"timeoutMillis":10000})
    }

    #[test]
    fn shared_contract_vectors() {
        let vectors: Value =
            serde_json::from_str(include_str!("../../../tests/fixtures/scoped-https/v1.json"))
                .unwrap();
        assert_eq!(
            vectors["apiVersion"],
            crate::capabilities::SCOPED_HTTPS_CONTRACT
        );
        for vector in vectors["vectors"].as_array().unwrap() {
            let declared = match &vector["declared"] {
                Value::Null => vectors["declared"].clone(),
                value => value.clone(),
            };
            let effects = match &vector["effects"] {
                Value::Null => vectors["effects"].clone(),
                value => value.clone(),
            };
            let mut signed = declared.clone();
            for (key, value) in vector["patch"].as_object().unwrap() {
                signed[key] = value.clone();
            }
            let (mut execution, mut decision) = fixture(&[("/https-fetch", declared)]);
            decision["tools"][0]["limits"]["https"] = signed;
            decision["tools"][0]["limits"]["effects"] = effects.clone();
            execution["tools"][0]["spec"]["limits"]["effects"] = effects;
            assert_eq!(
                derive(&execution, &decision).is_ok(),
                vector["accepted"].as_bool().unwrap(),
                "{}",
                vector["name"]
            );
        }
    }

    #[test]
    fn the_starter_web_tools_become_the_fleet_get_and_post_grants() {
        let (execution, decision) =
            fixture(&[("/https-fetch", starter()), ("/https-post-json", starter())]);
        let policy = derive(&execution, &decision).unwrap().unwrap();
        let (get, post) = policy.grants(Duration::from_secs(60));
        let get = get.unwrap();
        let post = post.unwrap();
        assert_eq!(get.allow_hosts, vec!["*".to_string()]);
        assert_eq!(
            (get.max_requests, get.max_response_bytes, get.timeout),
            (4, 4096, Duration::from_secs(10))
        );
        assert_eq!((post.max_requests, post.max_body_bytes), (4, 4096));
        // The remaining deadline bounds every grant's timeout.
        let (get, _) = policy.grants(Duration::from_secs(2));
        assert_eq!(get.unwrap().timeout, Duration::from_secs(2));
        // A fetch-only selection never implies POST.
        let (execution, decision) = fixture(&[("/https-fetch", starter())]);
        let (get, post) = derive(&execution, &decision)
            .unwrap()
            .unwrap()
            .grants(Duration::from_secs(60));
        assert!(get.is_some() && post.is_none());
        // No web tools: no policy.
        let (execution, decision) = fixture(&[]);
        assert_eq!(derive(&execution, &decision).unwrap(), None);
    }

    #[test]
    fn selected_ceilings_intersect_and_unknown_entry_points_refuse() {
        let mut narrow = starter();
        narrow["allowHosts"] = json!(["docs.example.com"]);
        narrow["maxRequests"] = json!(2);
        let (execution, decision) = fixture(&[
            ("/https-fetch", starter()),
            ("/https-fetch", narrow.clone()),
        ]);
        let (get, _) = derive(&execution, &decision)
            .unwrap()
            .unwrap()
            .grants(Duration::from_secs(60));
        let get = get.unwrap();
        assert_eq!(get.allow_hosts, vec!["docs.example.com".to_string()]);
        assert_eq!(get.max_requests, 2);
        let mut other = narrow.clone();
        other["allowHosts"] = json!(["other.example.com"]);
        let (execution, decision) = fixture(&[("/https-fetch", narrow), ("/https-fetch", other)]);
        assert!(derive(&execution, &decision).is_err());
        let (execution, decision) = fixture(&[("/workspace-read", starter())]);
        assert!(derive(&execution, &decision).is_err());
    }

    #[test]
    fn unsupported_shapes_stay_closed() {
        let (execution, decision) = fixture(&[("/https-fetch", starter())]);
        for (pointer, value) in [
            ("/route/provider", json!("none")),
            ("/tools/0/limits/workspace", json!("read-write")),
            ("/tools/0/limits/effects", json!("none")),
            ("/tools/0/limits/artifacts", json!({"operation":"read"})),
            ("/tools/0/limits/https", Value::Null),
            ("/tools/0/limits/timeoutMillis", json!(5000)),
        ] {
            let mut changed = decision.clone();
            *changed.pointer_mut(pointer).unwrap() = value;
            assert!(derive(&execution, &changed).is_err(), "{pointer}");
        }
        let mut changed = execution.clone();
        changed["tools"][0]["spec"]["limits"]["https"] = Value::Null;
        assert!(derive(&changed, &decision).is_err());
        let mut changed = decision.clone();
        changed["tools"] = json!([]);
        assert!(derive(&execution, &changed).is_err());
        // Enduring lifecycles accept the same authority.
        for lifecycle in ["enduring-initial", "enduring-turn"] {
            let mut enduring = decision.clone();
            enduring["lifecycle"] = json!(lifecycle);
            assert!(derive(&execution, &enduring).unwrap().is_some());
        }
    }
}
