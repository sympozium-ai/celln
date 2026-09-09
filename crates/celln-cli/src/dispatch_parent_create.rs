//! Operator-owned launch selection. HTTP supplies only a content hash; it may
//! not upload runtime policy or choose paths in the operator namespace.
use super::*;
use celln_manifest::Hash;
use std::{
    io::{Read, Write},
    path::PathBuf,
    time::Duration,
};

#[derive(Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Profile {
    api_version: String,
    parent: ExecutionRequest,
    worker: ExecutionRequest,
    template: pilot::json_harness::Config,
    model_profile: Hash,
    permit: Hash,
    binding: warden::parent_permit::Binding,
    /// Operator's logical host-memory reservation, including retained motes,
    /// both VMs, artifact buffers and overhead. Not a physical RSS guarantee.
    reserved_memory_bytes: u64,
}

pub(crate) struct Admission {
    profile: Profile,
    template: pilot::turn_worker::Template,
    root: PathBuf,
}

pub(crate) type Handler = Box<dyn FnMut(&[u8]) -> Result<Vec<u8>, String>>;

pub(crate) fn admit(root: &Path, hash: &Hash, principal: &str) -> Result<Admission, String> {
    if !hash.0.strip_prefix("blake3:").is_some_and(|s| {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }) {
        return Err("invalid launch profile hash".into());
    }
    let mut bytes = Vec::new();
    std::fs::File::open(
        root.join("trusted-parent-launches")
            .join(format!("{}.json", &hash.0[7..])),
    )
    .map_err(|_| "parent launch profile unavailable")?
    .take(65537)
    .read_to_end(&mut bytes)
    .map_err(|_| "parent launch profile unreadable")?;
    if bytes.len() > 65536 || Hash::of(&bytes) != *hash {
        return Err("parent launch profile integrity mismatch".into());
    }
    validate(root, &bytes, principal)
}

fn validate(root: &Path, bytes: &[u8], principal: &str) -> Result<Admission, String> {
    if bytes.len() > 65536 {
        return Err("parent launch profile exceeds size limit".into());
    }
    let profile: Profile =
        serde_json::from_slice(bytes).map_err(|_| "invalid parent launch profile")?;
    if profile.api_version != "celln.parent-launch/v1" {
        return Err("unsupported parent launch profile".into());
    }
    warden::parent_permit::authorize(root, &profile.permit, &profile.binding, principal)
        .map_err(|e| e.to_string())?;
    validate_policy(root, profile)
}

fn validate_policy(root: &Path, profile: Profile) -> Result<Admission, String> {
    validate_parent_request(&profile.parent, &profile.binding)?;
    let template =
        pilot::turn_worker::Template::new(profile.template.clone()).map_err(|e| e.to_string())?;
    // No model secret is read here. Independent broker policy and caller binding
    // are checked before durable claim, node reservation or warm preparation.
    parent_model::ChildBrokers::new(
        root,
        profile.model_profile.clone(),
        profile.binding.clone(),
        &profile.worker,
        &template,
    )?;
    // Necessary floor only, not sufficient sizing: include two retained motes
    // and two live guest allocations. Operator must add artifacts/host overhead.
    let floor = profile
        .binding
        .parent_memory_bytes
        .checked_add(profile.binding.child_memory_bytes)
        .and_then(|bytes| bytes.checked_mul(2))
        .ok_or("parent reservation overflow")?;
    if profile.reserved_memory_bytes <= floor {
        return Err("parent reservation must include warm motes and host overhead".into());
    }
    Ok(Admission {
        profile,
        template,
        root: root.into(),
    })
}

/// Publish independently authorized, operator-local launch policy. This is not
/// an HTTP upload interface and does not claim an incarnation or prepare a VM.
/// The protected directory must already exist. Exact retries are recoverable;
/// a corrupt existing record is never replaced. Startup rechecks live authority.
pub(crate) fn publish(root: &Path, bytes: &[u8], principal: &str) -> Result<Hash, String> {
    if !root.is_absolute() {
        return Err("parent launch root must be absolute".into());
    }
    validate(root, bytes, principal)?;
    let directory = root.join("trusted-parent-launches");
    let hash = Hash::of(bytes);
    let destination = directory.join(format!("{}.json", &hash.0[7..]));
    let mut temporary = tempfile::NamedTempFile::new_in(&directory)
        .map_err(|e| format!("parent launch staging failed: {e}"))?;
    temporary.write_all(bytes).map_err(|e| e.to_string())?;
    temporary.as_file().sync_all().map_err(|e| e.to_string())?;
    match temporary.persist_noclobber(&destination) {
        Ok(_) => (),
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
            let mut existing = Vec::new();
            std::fs::File::open(&destination)
                .map_err(|e| e.to_string())?
                .take(65537)
                .read_to_end(&mut existing)
                .map_err(|e| e.to_string())?;
            if existing != bytes {
                return Err("existing parent launch profile differs".into());
            }
        }
        Err(error) => return Err(error.error.to_string()),
    }
    std::fs::File::open(&directory)
        .and_then(|file| file.sync_all())
        .map_err(|e| e.to_string())?;
    // Expiry or revocation during publication must not produce an approval.
    // Keep the durable record on failure; publication never renews authority.
    admit(root, &hash, principal)?;
    Ok(hash)
}

/// Trusted local input, never a tenant-supplied execution request. The caller
/// must independently authorize the complete Kubernetes intent and selection.
#[derive(Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProvisionPlan {
    api_version: String,
    scope: String,
    run_uid: String,
    #[serde(rename = "intentSHA256")]
    intent_sha256: String,
    admission_window_ms: u64,
    parent: ExecutionRequest,
    worker: ExecutionRequest,
    template: pilot::json_harness::Config,
    model_profile: Hash,
    reserved_memory_bytes: u64,
    max_turns: usize,
    turn_model_requests: u64,
    turn_output_tokens: u64,
    total_model_requests: u64,
    total_output_tokens: u64,
}

pub(crate) fn provision_file(root: &Path, path: &Path, principal: &str) -> anyhow::Result<u8> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(65537)
        .read_to_end(&mut bytes)?;
    let (profile, incarnation) = provision(root, &bytes, principal).map_err(anyhow::Error::msg)?;
    println!(
        "{}",
        serde_json::json!({"apiVersion":"celln.parent-provisioned/v1", "launchProfile":profile, "incarnation":incarnation})
    );
    Ok(0)
}

fn provision(root: &Path, bytes: &[u8], principal: &str) -> Result<(Hash, Hash), String> {
    if bytes.len() > 65536 || !root.is_absolute() {
        return Err("bounded local parent plan and absolute root required".into());
    }
    let plan: ProvisionPlan =
        serde_json::from_slice(bytes).map_err(|_| "invalid parent provision plan")?;
    if plan.api_version != "celln.parent-provision-plan/v1"
        || !plan
            .intent_sha256
            .strip_prefix("sha256:")
            .is_some_and(|value| {
                value.len() == 64
                    && value
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
        || plan.parent.workload.caller != principal
        || plan.worker.workload.caller != principal
    {
        return Err("parent provision version, intent or principal mismatch".into());
    }
    // Bind the entire typed plan, including logical reservation and model
    // policy, as well as the upstream SHA256 intent. No cross-language JSON
    // canonicalization is required: the upstream digest is an opaque identity.
    let intent = Hash::of(
        &serde_json::to_vec(&("celln.parent-provision-intent/v1", &plan))
            .map_err(|e| e.to_string())?,
    );
    let incarnation = warden::parent_permit::run_incarnation(&plan.scope, &plan.run_uid)
        .map_err(|e| e.to_string())?;
    let template =
        pilot::turn_worker::Template::new(plan.template.clone()).map_err(|e| e.to_string())?;
    let binding = warden::parent_permit::Binding {
        principal: principal.into(),
        incarnation: incarnation.clone(),
        parent_configuration: plan
            .parent
            .configuration_binding(celln_spec::ConfigurationRole::Parent)?,
        worker_configuration: parent_model::worker_binding(
            &plan.worker,
            &template,
            &plan.model_profile,
        )?,
        parent_memory_bytes: plan.parent.capabilities.memory_bytes,
        child_memory_bytes: plan.worker.capabilities.memory_bytes,
        lifetime_ms: plan.parent.capabilities.timeout_ms,
        turn_timeout_ms: plan.worker.capabilities.timeout_ms,
        max_turns: plan.max_turns,
        turn_model_requests: plan.turn_model_requests,
        turn_output_tokens: plan.turn_output_tokens,
        total_model_requests: plan.total_model_requests,
        total_output_tokens: plan.total_output_tokens,
    };
    let profile = Profile {
        api_version: "celln.parent-launch/v1".into(),
        parent: plan.parent,
        worker: plan.worker,
        template: plan.template,
        model_profile: plan.model_profile,
        permit: Hash::of(b"not-yet-issued"),
        binding: binding.clone(),
        reserved_memory_bytes: plan.reserved_memory_bytes,
    };
    // Reject policy mistakes before consuming the durable issuance identity.
    let mut admission = validate_policy(root, profile)?;
    if serde_json::to_vec(&admission.profile)
        .map_err(|e| e.to_string())?
        .len()
        > 65536
    {
        return Err("resulting parent launch profile exceeds size limit".into());
    }
    for directory in [
        "parent-issuance",
        "trusted-parent-permits",
        "trusted-parent-launches",
    ] {
        if !root.join(directory).is_dir() {
            return Err("pre-existing protected parent publication directories required".into());
        }
    }
    let permit = warden::parent_permit::issue_for_run(
        root,
        &plan.scope,
        &plan.run_uid,
        &intent,
        binding,
        Duration::from_millis(plan.admission_window_ms),
    )
    .map_err(|e| e.to_string())?;
    admission.profile.permit = permit.publish(root).map_err(|e| e.to_string())?;
    let bytes = serde_json::to_vec(&admission.profile).map_err(|e| e.to_string())?;
    let launch = publish(root, &bytes, principal)?;
    Ok((launch, incarnation))
}

impl Admission {
    pub(crate) fn incarnation(&self) -> &Hash {
        &self.profile.binding.incarnation
    }
    pub(crate) fn lifetime(&self) -> Duration {
        Duration::from_millis(self.profile.binding.lifetime_ms)
    }
    pub(crate) fn reserved_memory_bytes(&self) -> u64 {
        self.profile.reserved_memory_bytes
    }

    /// Claim on the serving thread before any runtime preparation or creation.
    /// Failure after this point burns the incarnation, including capacity races.
    pub(crate) fn claim(
        self,
        principal: &str,
    ) -> Result<
        impl FnOnce(
                std::sync::Arc<warden::parent_child_control::ChildControlSlot>,
            ) -> Result<Handler, String>
            + Send,
        String,
    > {
        let claim = warden::parent_permit::claim(
            &self.root,
            &self.profile.permit,
            &self.profile.binding,
            principal,
        )
        .map_err(|e| e.to_string())?;
        Ok(move |children| {
            let profile = self.profile;
            let motes = self.root.join("motes");
            let tools = self.root.join("tools");
            let parent = prepare_parent(
                &profile.parent,
                &motes,
                &tools,
                &self.root,
                &profile.permit,
                &profile.binding,
                &profile.binding.principal,
            )?;
            let worker = parent_worker::prepare_worker(
                &profile.worker,
                self.template,
                profile.model_profile,
                &profile.binding,
                &motes,
                &tools,
                &self.root,
            )?;
            let mut session = parent.into_claimed_session(worker, Some(claim), Some(children))?;
            Ok(
                Box::new(move |bytes: &[u8]| session.submit(bytes).map_err(|e| e.to_string()))
                    as Handler,
            )
        })
    }
}

#[cfg(all(test, target_os = "linux"))]
mod publication_tests {
    use super::*;
    use serde_json::json;

    fn fixture() -> (tempfile::TempDir, Vec<u8>) {
        let root = tempfile::tempdir().unwrap();
        let request = super::super::parent_tests::request();
        let mut binding = super::super::parent_tests::binding(&request);
        binding.turn_model_requests = 1;
        binding.turn_output_tokens = 512;
        binding.total_model_requests = 2;
        binding.total_output_tokens = 1024;
        let template = pilot::turn_worker::Template::new(
            serde_json::from_value(json!({
                "contract":"celln.json-tools/v1", "task":"", "system":"host persona",
                "url":"https://api.deepseek.com/chat/completions", "model":"deepseek-chat",
                "tools":[], "max_turns":1, "max_calls":0
            }))
            .unwrap(),
        )
        .unwrap();
        let model = serde_json::to_vec(&json!({
            "apiVersion":"celln.parent-model-profile/v1", "principal":binding.principal,
            "requestBinding":request.configuration_binding(celln_spec::ConfigurationRole::Worker).unwrap(),
            "templateBinding":template.binding(), "credentialFile":root.path().join("absent-secret"),
            "url":template.policy().url, "model":template.policy().model,
            "maxRequests":1, "maxOutputTokens":512, "maxTotalOutputTokens":512
        })).unwrap();
        let model_hash = Hash::of(&model);
        for directory in [
            "trusted-parent-models",
            "trusted-parent-permits",
            "trusted-parent-launches",
        ] {
            std::fs::create_dir(root.path().join(directory)).unwrap();
        }
        std::fs::write(
            root.path()
                .join("trusted-parent-models")
                .join(format!("{}.json", &model_hash.0[7..])),
            model,
        )
        .unwrap();
        binding.worker_configuration =
            parent_model::worker_binding(&request, &template, &model_hash).unwrap();
        let permit = warden::parent_permit::Permit::issue(binding.clone(), Duration::from_secs(60))
            .unwrap()
            .publish(root.path())
            .unwrap();
        let bytes = serde_json::to_vec(&json!({
            "apiVersion":"celln.parent-launch/v1", "parent":request, "worker":request,
            "template":template.policy(), "modelProfile":model_hash, "permit":permit,
            "binding":binding, "reservedMemoryBytes":2 * (binding.parent_memory_bytes + binding.child_memory_bytes) + 1
        })).unwrap();
        (root, bytes)
    }

    #[test]
    fn provision_plan_recovers_exact_launch_and_refuses_changed_intent() {
        let (root, bytes) = fixture();
        std::fs::create_dir(root.path().join("parent-issuance")).unwrap();
        let profile: Profile = serde_json::from_slice(&bytes).unwrap();
        let mut plan = ProvisionPlan {
            api_version: "celln.parent-provision-plan/v1".into(),
            scope: "test-cluster".into(),
            run_uid: "immutable-run-uid".into(),
            intent_sha256: format!("sha256:{}", "a".repeat(64)),
            admission_window_ms: 60000,
            parent: profile.parent,
            worker: profile.worker,
            template: profile.template,
            model_profile: profile.model_profile,
            reserved_memory_bytes: profile.reserved_memory_bytes,
            max_turns: 2,
            turn_model_requests: 1,
            turn_output_tokens: 512,
            total_model_requests: 2,
            total_output_tokens: 1024,
        };
        let encode = |plan: &ProvisionPlan| serde_json::to_vec(plan).unwrap();
        assert!(serde_json::to_value(&plan)
            .unwrap()
            .get("intentSHA256")
            .is_some());
        let first = provision(root.path(), &encode(&plan), "test:parent").unwrap();
        assert_eq!(
            provision(
                root.path(),
                &serde_json::to_vec_pretty(&plan).unwrap(),
                "test:parent"
            )
            .unwrap(),
            first
        );
        assert_eq!(
            first.1,
            warden::parent_permit::run_incarnation("test-cluster", "immutable-run-uid").unwrap()
        );
        assert_eq!(
            provision(root.path(), &encode(&plan), "test:parent").unwrap(),
            first
        );
        assert!(admit(root.path(), &first.0, "test:parent").is_ok());
        plan.intent_sha256 = format!("sha256:{}", "b".repeat(64));
        assert!(provision(root.path(), &encode(&plan), "test:parent").is_err());
        plan.intent_sha256 = format!("sha256:{}", "a".repeat(64));
        plan.reserved_memory_bytes += 1;
        assert!(provision(root.path(), &encode(&plan), "test:parent").is_err());
        plan.reserved_memory_bytes -= 1;
        assert!(provision(root.path(), &encode(&plan), "another-tenant").is_err());
        plan.run_uid = "second-run-uid".into();
        let second = provision(root.path(), &encode(&plan), "test:parent").unwrap();
        assert_ne!(first, second);
        assert_eq!(
            std::fs::read_dir(root.path().join("parent-issuance"))
                .unwrap()
                .count(),
            2
        );
        assert!(!root.path().join("parent-journal").exists());
    }

    #[test]
    fn launch_publication_is_durable_repeatable_and_never_claims() {
        use std::os::unix::fs::PermissionsExt;
        let (root, bytes) = fixture();
        let hash = publish(root.path(), &bytes, "test:parent").unwrap();
        assert_eq!(hash, Hash::of(&bytes));
        assert_eq!(publish(root.path(), &bytes, "test:parent").unwrap(), hash);
        let path = root
            .path()
            .join("trusted-parent-launches")
            .join(format!("{}.json", &hash.0[7..]));
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(!root.path().join("parent-journal").exists());
        assert!(!root.path().join("absent-secret").exists());
        std::fs::write(&path, b"corrupt").unwrap();
        assert!(publish(root.path(), &bytes, "test:parent").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"corrupt");
        assert_eq!(
            std::fs::read_dir(root.path().join("trusted-parent-launches"))
                .unwrap()
                .count(),
            1
        );
    }

    #[test]
    fn launch_publication_refuses_invalid_or_unbound_policy_before_writes() {
        let (root, bytes) = fixture();
        assert!(publish(Path::new("relative"), &bytes, "test:parent").is_err());
        assert!(publish(root.path(), &bytes, "other-tenant").is_err());
        assert!(publish(root.path(), &vec![b' '; 65537], "test:parent").is_err());
        for (pointer, value) in [
            ("/reservedMemoryBytes", json!(1)),
            ("/template/system", json!("unapproved persona")),
            ("/binding/maxTurns", json!(3)),
            ("/worker/workload/caller", json!("other-tenant")),
            ("/parent/capabilities/workspace", json!("read-only")),
        ] {
            let mut changed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            *changed.pointer_mut(pointer).unwrap() = value;
            assert!(
                publish(
                    root.path(),
                    &serde_json::to_vec(&changed).unwrap(),
                    "test:parent"
                )
                .is_err(),
                "{pointer}"
            );
        }
        assert_eq!(
            std::fs::read_dir(root.path().join("trusted-parent-launches"))
                .unwrap()
                .count(),
            0
        );
        assert!(!root.path().join("parent-journal").exists());
    }
}
