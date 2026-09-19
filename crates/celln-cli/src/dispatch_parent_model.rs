//! Host-only model authority for a fixed native worker. Unlike a one-shot
//! Harness grant, this profile authorizes fresh child-local brokers under one
//! admitted parent ledger; it never authorizes resetting that ledger.
use celln_manifest::Hash;
use celln_spec::{ConfigurationRole, ExecutionRequest};
use pilot::turn_worker::Template;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    io::Read,
    path::{Path, PathBuf},
};
use warden::{parent_lease::ReservedTurn, parent_permit::Binding};

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Profile {
    #[serde(default)]
    protocol: warden::egress::ModelProtocol,
    api_version: String,
    principal: String,
    request_binding: Hash,
    template_binding: Hash,
    credential_file: PathBuf,
    url: String,
    model: String,
    max_requests: u64,
    max_output_tokens: u64,
    max_total_output_tokens: u64,
    /// Operator opt-in for an HTTP or self-signed private model endpoint.
    #[serde(default)]
    allow_insecure: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    workspace: Option<WorkspaceProfile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    fetch: Option<FetchProfile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    post: Option<PostProfile>,
    /// Operator-chosen provider request fields (`modelConnection.parameters`).
    /// Absent when empty, so a profile without them keeps the bytes, and
    /// therefore the pinned hash, it had before parameters existed.
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    parameters: serde_json::Map<String, serde_json::Value>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PostProfile {
    allow_hosts: Vec<String>,
    max_requests: usize,
    max_body_bytes: usize,
    max_response_bytes: usize,
    timeout_ms: u64,
}

/// Starter tools that read run data and those that change it. A profile's
/// read or write flag must agree with the tools the template selects.
const WORKSPACE_READERS: [&str; 3] = ["workspace-read", "workspace-list", "workspace-search"];
const WORKSPACE_WRITERS: [&str; 3] = ["workspace-write", "workspace-append", "workspace-delete"];

fn valid_hosts(hosts: &[String]) -> bool {
    !hosts.is_empty()
        && hosts.len() <= 16
        && hosts.iter().all(|host| {
            host.len() <= 253
                && host.contains('.')
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

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FetchProfile {
    allow_hosts: Vec<String>,
    max_requests: usize,
    max_response_bytes: usize,
    timeout_ms: u64,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WorkspaceProfile {
    read: bool,
    write: bool,
    max_operations: usize,
    max_files: usize,
    max_file_bytes: usize,
    max_total_bytes: usize,
}

pub(super) fn worker_binding(
    request: &ExecutionRequest,
    template: &Template,
    profile: &Hash,
) -> Result<Hash, String> {
    let request = request.configuration_binding(ConfigurationRole::Worker)?;
    Ok(Hash::of(
        &serde_json::to_vec(&(
            "celln.native-worker-admission/v1",
            request,
            template.binding(),
            profile,
        ))
        .map_err(|_| "invalid worker binding")?,
    ))
}

pub(super) struct ChildBrokers {
    root: PathBuf,
    profile: Hash,
    binding: Binding,
    request: Hash,
    template: Hash,
    url: String,
    model: String,
    requests: u64,
    claimed: BTreeSet<String>,
    workspace: Option<warden::workspace_broker::Owner>,
}

impl ChildBrokers {
    /// Construct once in the live owner after validating the parent permit and
    /// independently admitting the worker closure. This does not read the key.
    pub(super) fn new(
        root: &Path,
        profile: Hash,
        binding: Binding,
        request: &ExecutionRequest,
        template: &Template,
    ) -> Result<Self, String> {
        if worker_binding(request, template, &profile)? != binding.worker_configuration
            || request.workload.caller != binding.principal
        {
            return Err("worker model authority is not bound to parent permit".into());
        }
        let mut issuer = Self {
            root: root.into(),
            profile,
            binding,
            request: request.configuration_binding(ConfigurationRole::Worker)?,
            template: template.binding().clone(),
            url: template.policy().url.clone(),
            model: template.policy().model.clone(),
            requests: template.policy().max_turns as u64,
            claimed: BTreeSet::new(),
            workspace: None,
        };
        let admitted = issuer.read_profile()?;
        let has_tool = |name: &str| template.policy().tools.iter().any(|t| t.name == name);
        if admitted.fetch.is_some() && !has_tool("https-fetch") {
            return Err("fetch profile lacks explicitly selected starter tool".into());
        }
        if admitted.post.is_some() && !has_tool("https-post-json") {
            return Err("post profile lacks explicitly selected starter tool".into());
        }
        if let Some(workspace) = admitted.workspace {
            // The entire profile is content-hash pinned to the parent permit.
            // Tool selection still requires independent upstream admission.
            if workspace.read != WORKSPACE_READERS.iter().any(|name| has_tool(name))
                || workspace.write != WORKSPACE_WRITERS.iter().any(|name| has_tool(name))
                || (!workspace.read && !workspace.write)
                || !(1..=64).contains(&workspace.max_operations)
            {
                return Err("workspace profile does not match selected starter tools".into());
            }
            issuer.workspace = Some(warden::workspace_broker::Owner::new(
                issuer.binding.incarnation.clone(),
                celln_store::workspace::Limits {
                    files: workspace.max_files,
                    file_bytes: workspace.max_file_bytes,
                    total_bytes: workspace.max_total_bytes,
                },
            )?);
        }
        Ok(issuer)
    }

    fn read_profile(&self) -> Result<Profile, String> {
        let hash = self
            .profile
            .0
            .strip_prefix("blake3:")
            .filter(|s| {
                s.len() == 64
                    && s.bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
            .ok_or("invalid parent model profile hash")?;
        let mut bytes = Vec::new();
        std::fs::File::open(
            self.root
                .join("trusted-parent-models")
                .join(format!("{hash}.json")),
        )
        .and_then(|f| f.take(65537).read_to_end(&mut bytes))
        .map_err(|_| "parent model profile unavailable")?;
        if bytes.len() > 65536 || Hash::of(&bytes) != self.profile {
            return Err("parent model profile revision mismatch".into());
        }
        let profile: Profile =
            serde_json::from_slice(&bytes).map_err(|_| "invalid parent model profile")?;
        if profile.api_version != "celln.parent-model-profile/v1"
            || profile.principal != self.binding.principal
            || profile.request_binding != self.request
            || profile.template_binding != self.template
            || profile.url != self.url
            || profile.model != self.model
            || warden::egress::model_endpoint_target(&profile.url, profile.allow_insecure).is_err()
            || !profile.credential_file.is_absolute()
            || profile.max_output_tokens != 512
            || profile.max_requests != self.requests
            || !(1..=6).contains(&profile.max_requests)
            || profile.max_requests > self.binding.turn_model_requests
            || profile.max_total_output_tokens < profile.max_requests * 512
            || profile.max_total_output_tokens > self.binding.turn_output_tokens
        {
            return Err("parent model profile policy mismatch".into());
        }
        // The hash already pins these bytes; the rules are held here as well
        // so a profile installed by any other means cannot widen them.
        warden::model_parameters::validate(&profile.parameters)
            .map_err(|reason| format!("invalid parent model profile: {reason}"))?;
        if let Some(fetch) = &profile.fetch {
            if !(1..=16).contains(&fetch.max_requests)
                || !(1..=65536).contains(&fetch.max_response_bytes)
                || !(1..=30000).contains(&fetch.timeout_ms)
                || !valid_hosts(&fetch.allow_hosts)
            {
                return Err("invalid bounded HTTPS starter profile".into());
            }
        }
        if let Some(post) = &profile.post {
            if !(1..=16).contains(&post.max_requests)
                || !(1..=8192).contains(&post.max_body_bytes)
                || !(1..=65536).contains(&post.max_response_bytes)
                || !(1..=30000).contains(&post.timeout_ms)
                || !valid_hosts(&post.allow_hosts)
            {
                return Err("invalid bounded JSON POST starter profile".into());
            }
        }
        Ok(profile)
    }

    /// One broker per reserved child. No refund/retry on profile failure. The
    /// ParentLease/ParentJournal remain responsible for aggregate budgets and
    /// durable pre-spawn reservation; this in-memory set is not restart recovery.
    pub(super) fn for_turn(
        &mut self,
        turn: &ReservedTurn,
    ) -> Result<warden::egress::HttpPolicy, String> {
        let expected = Hash::of(
            &serde_json::to_vec(&(&self.binding.incarnation.0, &turn.request.turn_id))
                .map_err(|_| "invalid child binding")?,
        );
        if turn.parent != self.binding.incarnation
            || turn.child != expected
            || self.claimed.len() >= self.binding.max_turns
            || turn.limits.model_requests > self.binding.turn_model_requests
            || turn.limits.output_tokens > self.binding.turn_output_tokens
            || turn.limits.memory_bytes > self.binding.child_memory_bytes
            || turn.limits.timeout.is_zero()
            || turn.limits.timeout > std::time::Duration::from_millis(self.binding.turn_timeout_ms)
        {
            return Err("child model reservation mismatch".into());
        }
        if !self.claimed.insert(turn.child.0.clone()) {
            return Err("child broker already claimed".into());
        }
        let profile = self.read_profile()?;
        if profile.max_requests > turn.limits.model_requests
            || profile.max_total_output_tokens > turn.limits.output_tokens
        {
            return Err("model profile exceeds child reservation".into());
        }
        let target = warden::egress::model_endpoint_target(&profile.url, profile.allow_insecure)?;
        let mut policy = warden::egress::HttpPolicy::new(vec![target.host.clone()]);
        // A model request may use the whole turn: slow local models are
        // legitimate, and the turn deadline is the enforced bound.
        policy.timeout = turn.limits.timeout;
        policy.max_requests = profile.max_requests as usize;
        policy.allow_insecure = profile.allow_insecure;
        let get = match profile.fetch {
            Some(fetch) => warden::egress::GetGrant {
                allow_hosts: fetch.allow_hosts,
                max_requests: fetch.max_requests,
                max_response_bytes: fetch.max_response_bytes,
                timeout: std::time::Duration::from_millis(fetch.timeout_ms)
                    .min(turn.limits.timeout),
            },
            None => warden::egress::GetGrant {
                allow_hosts: vec![],
                max_requests: 0,
                max_response_bytes: 0,
                timeout: std::time::Duration::from_secs(1),
            },
        };
        policy.allow_hosts.extend(get.allow_hosts.iter().cloned());
        policy.get = Some(get);
        if let Some(post) = profile.post {
            policy.allow_hosts.extend(post.allow_hosts.iter().cloned());
            policy.post = Some(warden::egress::PostGrant {
                allow_hosts: post.allow_hosts,
                max_requests: post.max_requests,
                max_body_bytes: post.max_body_bytes,
                max_response_bytes: post.max_response_bytes,
                timeout: std::time::Duration::from_millis(post.timeout_ms).min(turn.limits.timeout),
            });
        }
        policy.json_posts.push(warden::egress::JsonPostGrant {
            protocol: profile.protocol,
            url: profile.url,
            model: profile.model,
            bearer_token_file: profile.credential_file,
            max_output_tokens: 512,
            max_total_output_tokens: profile.max_total_output_tokens,
            parameters: profile.parameters,
        });
        Ok(policy)
    }

    pub(super) fn workspace_for_turn(
        &mut self,
        turn: &ReservedTurn,
        policy: &mut warden::egress::HttpPolicy,
    ) -> Result<Option<warden::workspace_broker::Lease>, String> {
        if !self.claimed.contains(&turn.child.0) {
            return Err("workspace requires an admitted child broker".into());
        }
        let Some(profile) = self.read_profile()?.workspace else {
            return Ok(None);
        };
        let control = celln_control::current().ok_or("workspace requires live child control")?;
        let (lease, grant) = self
            .workspace
            .as_mut()
            .ok_or("workspace owner unavailable")?
            .begin(
                turn,
                profile.read,
                profile.write,
                profile.max_operations,
                control,
            )?;
        policy.workspace = Some(grant);
        Ok(Some(lease))
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    type Fixture = (
        tempfile::TempDir,
        ChildBrokers,
        warden::parent_lease::ParentLease,
        PathBuf,
    );
    fn fixture() -> Fixture {
        fixture_with(serde_json::json!({})).unwrap()
    }
    fn fixture_with(parameters: serde_json::Value) -> Result<Fixture, String> {
        let root = tempfile::tempdir().unwrap();
        let request = super::super::parent_tests::request();
        let mut binding = super::super::parent_tests::binding(&request);
        binding.turn_model_requests = 1;
        binding.turn_output_tokens = 512;
        binding.total_model_requests = 2;
        binding.total_output_tokens = 1024;
        let template = Template::new(
            serde_json::from_value(serde_json::json!({
                "contract":"celln.json-tools/v1","task":"","system":"host persona",
                "url":"https://api.deepseek.com/chat/completions","model":"deepseek-chat",
                "tools":[],"max_turns":1,"max_calls":0
            }))
            .unwrap(),
        )
        .unwrap();
        let profile = Profile {
            protocol: Default::default(),
            api_version: "celln.parent-model-profile/v1".into(),
            principal: binding.principal.clone(),
            request_binding: request
                .configuration_binding(ConfigurationRole::Worker)
                .unwrap(),
            template_binding: template.binding().clone(),
            credential_file: root.path().join("must-not-be-opened"),
            url: template.policy().url.clone(),
            model: template.policy().model.clone(),
            max_requests: 1,
            max_output_tokens: 512,
            max_total_output_tokens: 512,
            allow_insecure: false,
            workspace: None,
            fetch: None,
            post: None,
            parameters: parameters.as_object().unwrap().clone(),
        };
        let bytes = serde_json::to_vec(&profile).unwrap();
        let hash = Hash::of(&bytes);
        binding.worker_configuration = worker_binding(&request, &template, &hash).unwrap();
        std::fs::create_dir(root.path().join("trusted-parent-models")).unwrap();
        let path = root
            .path()
            .join("trusted-parent-models")
            .join(format!("{}.json", &hash.0[7..]));
        std::fs::write(&path, &bytes).unwrap();
        let issuer = ChildBrokers::new(root.path(), hash, binding.clone(), &request, &template)?;
        let mut wrong = binding.clone();
        wrong.worker_configuration = Hash::of(b"wrong");
        assert!(ChildBrokers::new(
            root.path(),
            issuer.profile.clone(),
            wrong,
            &request,
            &template
        )
        .is_err());
        let lease = warden::parent_lease::ParentLease::new(
            binding.incarnation,
            std::time::Duration::from_secs(30),
            warden::parent_lease::TurnLimits {
                memory_bytes: binding.child_memory_bytes,
                timeout: std::time::Duration::from_millis(binding.turn_timeout_ms),
                model_requests: 1,
                output_tokens: 512,
            },
            2,
            2,
            1024,
        )
        .unwrap();
        Ok((root, issuer, lease, path))
    }
    #[test]
    fn a_profile_without_parameters_keeps_the_bytes_existing_fleets_pinned() {
        let hash = |c: &str| Hash(format!("blake3:{}", c.repeat(64)));
        let mut profile = Profile {
            protocol: Default::default(),
            api_version: "celln.parent-model-profile/v1".into(),
            principal: "sympozium:celln-agents".into(),
            request_binding: hash("a"),
            template_binding: hash("b"),
            credential_file: "/etc/celln-native/model-token".into(),
            url: "https://api.deepseek.com/chat/completions".into(),
            model: "deepseek-chat".into(),
            max_requests: 6,
            max_output_tokens: 512,
            max_total_output_tokens: 3072,
            allow_insecure: false,
            workspace: None,
            fetch: None,
            post: None,
            parameters: Default::default(),
        };
        // Literal output of the struct as it was before `parameters` existed.
        let before = format!(
            r#"{{"protocol":"openai-chat","apiVersion":"celln.parent-model-profile/v1","principal":"sympozium:celln-agents","requestBinding":"blake3:{}","templateBinding":"blake3:{}","credentialFile":"/etc/celln-native/model-token","url":"https://api.deepseek.com/chat/completions","model":"deepseek-chat","maxRequests":6,"maxOutputTokens":512,"maxTotalOutputTokens":3072,"allowInsecure":false}}"#,
            "a".repeat(64),
            "b".repeat(64)
        );
        assert_eq!(serde_json::to_string(&profile).unwrap(), before);
        // A profile written before this field existed still reads, as none.
        let old: Profile = serde_json::from_str(&before).unwrap();
        assert!(old.parameters.is_empty());
        // With parameters they are part of the hashed bytes and round-trip.
        profile.parameters = serde_json::json!({"chat_template_kwargs":{"enable_thinking":false}})
            .as_object()
            .unwrap()
            .clone();
        let with = serde_json::to_vec(&profile).unwrap();
        assert_eq!(
            String::from_utf8(with.clone()).unwrap(),
            format!(
                r#"{},"parameters":{{"chat_template_kwargs":{{"enable_thinking":false}}}}}}"#,
                &before[..before.len() - 1]
            )
        );
        assert_ne!(Hash::of(&with), Hash::of(before.as_bytes()));
        let back: Profile = serde_json::from_slice(&with).unwrap();
        assert_eq!(back.parameters, profile.parameters);
        assert_eq!(serde_json::to_vec(&back).unwrap(), with);
        // The shape starter-configure writes (a JSON object, sorted keys).
        let configured: Profile = serde_json::from_value(serde_json::json!({
            "apiVersion":"celln.parent-model-profile/v1","protocol":"openai-chat","allowInsecure":true,
            "principal":"p","requestBinding":hash("a"),"templateBinding":hash("b"),
            "credentialFile":"/etc/token","url":"http://10.0.0.5:8080/v1/chat/completions","model":"qwen",
            "maxRequests":6,"maxOutputTokens":512,"maxTotalOutputTokens":3072,
            "parameters":{"chat_template_kwargs":{"enable_thinking":false}}
        }))
        .unwrap();
        assert_eq!(configured.parameters, profile.parameters);
    }
    #[test]
    fn pinned_parameters_reach_the_child_grant_and_are_revalidated_on_read() {
        let pinned =
            serde_json::json!({"chat_template_kwargs":{"enable_thinking":false},"top_k":20});
        let (_root, mut issuer, mut lease, path) = fixture_with(pinned.clone()).unwrap();
        let turn = reserve(&mut lease, "one");
        let policy = issuer.for_turn(&turn).unwrap();
        assert_eq!(
            serde_json::Value::Object(policy.json_posts[0].parameters.clone()),
            pinned
        );
        // Parameters are hashed with the rest: editing them in place breaks
        // the pin held by the parent permit.
        let edited = String::from_utf8(std::fs::read(&path).unwrap())
            .unwrap()
            .replace(r#""enable_thinking":false"#, r#""enable_thinking":true "#);
        std::fs::write(&path, edited).unwrap();
        lease.confirm_child_destroyed(&turn.child).unwrap();
        let turn = reserve(&mut lease, "two");
        assert_eq!(
            issuer.for_turn(&turn).unwrap_err(),
            "parent model profile revision mismatch"
        );
        // A correctly hashed profile that breaks the rules is still refused.
        for bad in [
            serde_json::json!({"max_tokens":4096}),
            serde_json::json!({"messages":[]}),
            serde_json::json!({"Upper":1}),
            serde_json::json!({"a":{"b":{"c":{"d":1}}}}),
        ] {
            let error = fixture_with(bad).err().unwrap();
            assert!(
                error.starts_with("invalid parent model profile: model parameter"),
                "{error}"
            );
        }
    }
    fn reserve(lease: &mut warden::parent_lease::ParentLease, id: &str) -> ReservedTurn {
        lease.reserve(&serde_json::to_vec(&serde_json::json!({"apiVersion":warden::parent_protocol::VERSION,"turnId":id,"task":"input"})).unwrap()).unwrap()
    }
    #[test]
    fn child_local_brokers_are_bounded_one_use_and_do_not_read_credentials() {
        let (_root, mut issuer, mut lease, _path) = fixture();
        for id in ["one", "two"] {
            let turn = reserve(&mut lease, id);
            let policy = issuer.for_turn(&turn).unwrap();
            assert_eq!(policy.max_requests, 1);
            assert_eq!(policy.json_posts[0].max_total_output_tokens, 512);
            assert!(!policy.json_posts[0].bearer_token_file.exists());
            assert!(issuer.for_turn(&turn).is_err());
            lease.confirm_child_destroyed(&turn.child).unwrap();
        }
        assert_eq!(issuer.claimed.len(), 2);
    }
    #[test]
    fn workspace_and_post_profiles_must_match_selected_starter_tools() {
        let (root, issuer, _lease, path) = fixture();
        let request = super::super::parent_tests::request();
        let empty =
            r#"{"type":"object","properties":{},"required":[],"additionalProperties":false}"#;
        let schema = serde_json::json!({"hash":Hash::of(empty.as_bytes()).0,"bytes":empty});
        let tool = |name: &str| {
            serde_json::json!({"name":name,"path":format!("/{name}"),"hash":format!("blake3:{}", "a".repeat(64)),"description":name,
                "input_schema":schema,"output_schema":schema,
                "input_bytes":1024,"output_bytes":1024,"timeout_ms":1000})
        };
        let attempt = |tools: Vec<serde_json::Value>,
                       workspace: Option<WorkspaceProfile>,
                       post: Option<PostProfile>| {
            let template = Template::new(
                serde_json::from_value(serde_json::json!({
                    "contract":"celln.json-tools/v1","task":"","system":"host persona",
                    "url":"https://api.deepseek.com/chat/completions","model":"deepseek-chat",
                    "tools":tools,"max_turns":1,"max_calls":0
                }))
                .unwrap(),
            )
            .unwrap();
            let mut profile: Profile =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            profile.template_binding = template.binding().clone();
            profile.workspace = workspace;
            profile.post = post;
            let bytes = serde_json::to_vec(&profile).unwrap();
            let hash = Hash::of(&bytes);
            let mut binding = issuer.binding.clone();
            binding.worker_configuration = worker_binding(&request, &template, &hash).unwrap();
            std::fs::write(
                root.path()
                    .join("trusted-parent-models")
                    .join(format!("{}.json", &hash.0[7..])),
                &bytes,
            )
            .unwrap();
            ChildBrokers::new(root.path(), hash, binding, &request, &template).map(|_| ())
        };
        let workspace = |read: bool, write: bool| {
            Some(WorkspaceProfile {
                read,
                write,
                max_operations: 4,
                max_files: 8,
                max_file_bytes: 4096,
                max_total_bytes: 16384,
            })
        };
        let post = || {
            Some(PostProfile {
                allow_hosts: vec!["hooks.example".into()],
                max_requests: 4,
                max_body_bytes: 4096,
                max_response_bytes: 4096,
                timeout_ms: 10000,
            })
        };
        // list and search are readers; append and delete are writers.
        assert!(attempt(
            vec![tool("workspace-list"), tool("workspace-search")],
            workspace(true, false),
            None
        )
        .is_ok());
        assert!(attempt(
            vec![tool("workspace-append"), tool("workspace-delete")],
            workspace(false, true),
            None
        )
        .is_ok());
        assert!(attempt(vec![tool("workspace-list")], workspace(true, true), None).is_err());
        assert!(attempt(vec![tool("workspace-append")], workspace(true, true), None).is_err());
        // A post profile needs the tool, and the tool alone grants nothing.
        assert!(attempt(vec![tool("https-post-json")], None, post()).is_ok());
        assert!(attempt(vec![], None, post()).is_err());
        assert!(attempt(
            vec![tool("https-post-json")],
            None,
            Some(PostProfile {
                allow_hosts: vec!["Hooks.Example".into()],
                ..post().unwrap()
            })
        )
        .is_err());
        assert!(attempt(
            vec![tool("https-post-json")],
            None,
            Some(PostProfile {
                max_body_bytes: 0,
                ..post().unwrap()
            })
        )
        .is_err());
    }
    #[test]
    fn live_profile_revocation_consumes_claim_without_retry_or_refund() {
        let (_root, mut issuer, mut lease, path) = fixture();
        let turn = reserve(&mut lease, "one");
        let bytes = std::fs::read(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert!(issuer.for_turn(&turn).is_err());
        std::fs::write(&path, bytes).unwrap();
        assert!(issuer
            .for_turn(&turn)
            .unwrap_err()
            .contains("already claimed"));
    }
    #[test]
    fn changed_child_identity_and_widened_limits_are_refused() {
        let (_root, mut issuer, mut lease, _path) = fixture();
        let mut turn = reserve(&mut lease, "one");
        let child = turn.child.clone();
        turn.child = Hash::of(b"forged");
        assert!(issuer.for_turn(&turn).is_err());
        turn.child = child;
        turn.limits.model_requests = 2;
        assert!(issuer.for_turn(&turn).is_err());
        turn.limits.model_requests = 1;
        assert!(issuer.for_turn(&turn).is_ok());
    }
}
