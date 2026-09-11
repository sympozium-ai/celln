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
        if admitted.fetch.is_some()
            && !template
                .policy()
                .tools
                .iter()
                .any(|t| t.name == "https-fetch")
        {
            return Err("fetch profile lacks explicitly selected starter tool".into());
        }
        if let Some(workspace) = admitted.workspace {
            // The entire profile is content-hash pinned to the parent permit.
            // Tool selection still requires independent upstream admission.
            let has_tool = |name: &str| template.policy().tools.iter().any(|t| t.name == name);
            if workspace.read != has_tool("workspace-read")
                || workspace.write != has_tool("workspace-write")
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
        if let Some(fetch) = &profile.fetch {
            if !(1..=16).contains(&fetch.max_requests)
                || !(1..=65536).contains(&fetch.max_response_bytes)
                || !(1..=30000).contains(&fetch.timeout_ms)
                || fetch.allow_hosts.is_empty()
                || fetch.allow_hosts.len() > 16
                || fetch.allow_hosts.iter().any(|host| {
                    host.len() > 253
                        || !host.contains('.')
                        || host.split('.').any(|label| {
                            label.is_empty()
                                || label.len() > 63
                                || label.starts_with('-')
                                || label.ends_with('-')
                                || !label.bytes().all(|b| {
                                    b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'
                                })
                        })
                })
            {
                return Err("invalid bounded HTTPS starter profile".into());
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
        policy.timeout = turn.limits.timeout.min(std::time::Duration::from_secs(45));
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
        policy.json_posts.push(warden::egress::JsonPostGrant {
            protocol: profile.protocol,
            url: profile.url,
            model: profile.model,
            bearer_token_file: profile.credential_file,
            max_output_tokens: 512,
            max_total_output_tokens: profile.max_total_output_tokens,
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
    fn fixture() -> (
        tempfile::TempDir,
        ChildBrokers,
        warden::parent_lease::ParentLease,
        PathBuf,
    ) {
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
        let issuer =
            ChildBrokers::new(root.path(), hash, binding.clone(), &request, &template).unwrap();
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
        (root, issuer, lease, path)
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
