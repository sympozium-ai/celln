//! Local operator issuance. This is not an upload endpoint or a tenant authority.
use super::*;

#[path = "dispatch_harness_expiry.rs"]
mod expiry;
pub(crate) use expiry::inspect_clock;

#[cfg(test)]
#[path = "dispatch_harness_issuer_tests.rs"]
mod tests;
#[cfg(test)]
pub(crate) fn prove_issuance(request: &ExecutionRequest, root: &Path) {
    tests::prove_issuance(request, root);
}

pub(crate) fn inspect_binding(path: &Path) -> anyhow::Result<u8> {
    let bytes = crate::closure_policy::read_bounded(path).map_err(anyhow::Error::msg)?;
    if bytes.len() > 65536 {
        anyhow::bail!("issuance request exceeds 64 KiB");
    }
    let request: ExecutionRequest = serde_json::from_slice(&bytes)?;
    println!(
        "{}",
        serde_json::json!({"apiVersion":"celln.dev/harness-request-binding-v1","requestBinding":request_binding(&request).map_err(anyhow::Error::msg)?,"executionAuthorized":false})
    );
    Ok(0)
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Binding {
    profile: String,
    policy_hash: String,
    request_binding: String,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Profile {
    api_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expiry: Option<expiry::Expiry>,
    request_binding: String,
    credential_file: PathBuf,
    model: String,
    url: String,
    max_requests: usize,
    max_output_tokens: u64,
    max_total_output_tokens: u64,
}

// Normalize only the self-referential grant hash. Task, caller, execution ID,
// persona, limits and every artifact/schema identity remain bound.
fn request_binding(request: &ExecutionRequest) -> Result<String, String> {
    let mut value = serde_json::to_value(request).map_err(|_| "invalid request")?;
    if request.harness.is_none() || !request.problems().is_empty() {
        return Err("valid Harness request required".into());
    }
    value["harness"]["modelGrant"]["hash"] = serde_json::json!(Hash::of(b"").0);
    Ok(Hash::of(&serde_json::to_vec(&value).map_err(|_| "invalid request")?).0)
}

fn profile(root: &Path, name: &str) -> Result<(Profile, String), String> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
    {
        return Err("invalid operator profile name".into());
    }
    let bytes = crate::closure_policy::read_bounded(
        &root
            .join("trusted-model-profiles")
            .join(format!("{name}.json")),
    )?;
    if bytes.len() > 65536 {
        return Err("model profile exceeds 64 KiB".into());
    }
    let p: Profile =
        serde_json::from_slice(&bytes).map_err(|_| "invalid operator model profile")?;
    match (p.api_version.as_str(), &p.expiry) {
        ("celln.dev/model-issuer-profile-v1", None) => {}
        ("celln.dev/model-issuer-profile-v2", Some(expiry)) => expiry.validate_current()?,
        _ => return Err("unsupported operator model profile expiry contract".into()),
    }
    if !p.credential_file.is_absolute()
        || p.url != "https://api.deepseek.com/chat/completions"
        || p.model.is_empty()
        || p.model.len() > 128
        || p.max_requests == 0
        || p.max_requests > 6
        || p.max_output_tokens != 512
        || p.max_total_output_tokens < 512
        || p.max_total_output_tokens > 3072
    {
        return Err("unsupported operator model profile".into());
    }
    Ok((p, Hash::of(&bytes).0))
}

pub(super) fn validate(
    request: &ExecutionRequest,
    grant: &Grant,
    root: &Path,
) -> Result<(), String> {
    if grant.api_version != "celln.dev/harness-grant-v3" {
        return if grant.issuer.is_none() {
            Ok(())
        } else {
            Err("issuer binding requires grant v3".into())
        };
    }
    let b = grant
        .issuer
        .as_ref()
        .ok_or("issued grant missing policy binding")?;
    let (p, hash) = profile(root, &b.profile)?;
    if hash != b.policy_hash
        || p.request_binding != b.request_binding
        || request_binding(request)? != b.request_binding
        || p.credential_file != grant.credential_file
        || p.model != grant.model
        || p.url != grant.url
        || p.max_requests != grant.max_requests
        || p.max_output_tokens != grant.max_output_tokens
        || p.max_total_output_tokens != grant.max_total_output_tokens
    {
        return Err("issued grant policy withdrawn, changed or request mismatched".into());
    }
    Ok(())
}

fn candidate(request: &ExecutionRequest, name: &str, root: &Path) -> Result<Vec<u8>, String> {
    let identity = request_binding(request)?;
    let (p, policy_hash) = profile(root, name)?;
    let h = request.harness.as_ref().ok_or("missing Harness")?;
    if h.contract_version != "celln.json-tools/v1"
        || h.model != p.model
        || identity != p.request_binding
    {
        return Err("request is not independently approved by host model profile".into());
    }
    let options = h.json.as_ref().ok_or("missing JSON Harness options")?;
    if p.max_requests < options.max_turns
        || p.max_total_output_tokens < options.max_turns as u64 * 512
    {
        return Err("issuer profile cannot fund the configured turn ceiling".into());
    }
    let mut grant = serde_json::json!({
        "apiVersion":"celln.dev/harness-grant-v3", "contractVersion":h.contract_version,
        "json":h.json,"caller":request.workload.caller,"mote":request.mote.as_ref().ok_or("missing mote")?.hash,
        "runtime":request.tools[0].hash,"closure":request.tools[0].closure.as_ref().ok_or("missing closure")?.hash,
        "borrowedTools":h.borrowed_tools,"url":p.url,"model":p.model,"credentialFile":p.credential_file,
        "maxRequests":p.max_requests,"maxOutputTokens":p.max_output_tokens,"maxTotalOutputTokens":p.max_total_output_tokens
    });
    grant["issuer"] = serde_json::to_value(Binding {
        profile: name.into(),
        policy_hash,
        request_binding: identity,
    })
    .map_err(|_| "invalid issuer binding")?;
    let bytes = serde_json::to_vec(&grant).map_err(|_| "invalid grant")?;
    if bytes.len() > 65536 {
        return Err("issued grant exceeds 64 KiB".into());
    }
    Ok(bytes)
}

pub(crate) fn issue(request_path: &Path, name: &str, root: &Path) -> anyhow::Result<u8> {
    let bytes = crate::closure_policy::read_bounded(request_path).map_err(anyhow::Error::msg)?;
    if bytes.len() > 65536 {
        anyhow::bail!("issuance request exceeds 64 KiB");
    }
    let mut request: ExecutionRequest = serde_json::from_slice(&bytes)?;
    let grant = candidate(&request, name, root).map_err(anyhow::Error::msg)?;
    // Member verification deliberately removes execution/model authority. This
    // CLI's cache is not the serving dispatcher's cache or a readiness lease.
    let mut check = serde_json::to_value(&request)?;
    check["apiVersion"] = serde_json::json!("celln.dev/v1alpha1");
    check.as_object_mut().unwrap().remove("harness");
    check["capabilities"]["egress"] = serde_json::json!([]);
    let check: ExecutionRequest = serde_json::from_value(check)?;
    let control = celln_control::Control::new(std::time::Duration::from_secs(30))?;
    let report = control
        .scope(|| {
            crate::dispatch::check_members(&check, &root.join("motes"), &root.join("tools"), root)
        })
        .map_err(anyhow::Error::msg)?;
    let bundle =
        crate::dispatch::resolve_bundle(&request, &root.join("motes"), &root.join("tools"))
            .map_err(anyhow::Error::msg)?;
    let closure = crate::dispatch::closure::resolve(&request, &bundle, root)
        .map_err(anyhow::Error::msg)?
        .ok_or_else(|| anyhow::anyhow!("admitted closure required"))?;
    resolve_bytes(&request, &closure, root, &grant).map_err(anyhow::Error::msg)?;
    let hash = Hash::of(&grant);
    let directory = root.join("trusted-harness");
    std::fs::create_dir_all(&directory)?;
    let mut temp = tempfile::NamedTempFile::new_in(&directory)?;
    temp.write_all(&grant)?;
    temp.as_file().sync_all()?;
    // Recheck the independently provisioned policy immediately before publish.
    if candidate(&request, name, root).map_err(anyhow::Error::msg)? != grant {
        anyhow::bail!("issuer policy changed during verification");
    }
    let path = directory.join(format!("{}.json", hash.0.trim_start_matches("blake3:")));
    if let Err(error) = temp.persist_noclobber(&path) {
        if error.error.kind() != std::io::ErrorKind::AlreadyExists
            || crate::closure_policy::read_bounded(&path).map_err(anyhow::Error::msg)? != grant
        {
            anyhow::bail!("cannot publish issued grant without overwriting existing data");
        }
    }
    std::fs::File::open(&directory)?.sync_all()?;
    request.harness.as_mut().unwrap().model_grant.hash = hash.0.clone();
    println!(
        "{}",
        serde_json::json!({"apiVersion":"celln.dev/harness-issuance-v1","grant":hash.0,"request":request,"verification":report,"artifactReadiness":"not_checked","conformance":"not_checked","executed":false})
    );
    Ok(0)
}
