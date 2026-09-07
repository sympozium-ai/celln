//! Operator-owned grants: possessing artifact bytes is not model authority.
use celln_manifest::Hash;
use celln_spec::{BorrowedTool, ExecutionRequest};
use serde::Deserialize;
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Grant {
    api_version: String,
    caller: String,
    mote: String,
    runtime: String,
    closure: String,
    borrowed_tools: Vec<BorrowedTool>,
    url: String,
    model: String,
    credential_file: PathBuf,
    max_requests: usize,
    max_output_tokens: u64,
    max_total_output_tokens: u64,
}
pub struct Resolved {
    pub policy: warden::egress::HttpPolicy,
    pub args: Vec<String>,
}

pub fn resolve(
    request: &ExecutionRequest,
    closure: Option<&super::closure::Admitted>,
    root: &Path,
) -> Result<Option<Resolved>, String> {
    let Some(binding) = &request.harness else {
        return Ok(None);
    };
    if !request.problems().is_empty() {
        return Err("invalid Harness binding".into());
    }
    let closure = closure.ok_or("Harness requires an admitted closure")?;
    // Operator-maintained directory, deliberately not an uploadable store.
    let path = root.join("trusted-harness").join(format!(
        "{}.json",
        binding.model_grant.hash.trim_start_matches("blake3:")
    ));
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .and_then(|f| f.take(65537).read_to_end(&mut bytes))
        .map_err(|_| "Harness grant unavailable")?;
    if bytes.len() > 65536 || Hash::of(&bytes).0 != binding.model_grant.hash {
        return Err("Harness grant revision mismatch".into());
    }
    let grant: Grant = serde_json::from_slice(&bytes).map_err(|_| "invalid Harness grant")?;
    if grant.api_version != "celln.dev/harness-grant-v1"
        || grant.caller != request.workload.caller
        || grant.mote != request.mote.as_ref().unwrap().hash
        || grant.runtime != request.tools[0].hash
        || grant.closure != closure.provenance.hash
        || grant.borrowed_tools != binding.borrowed_tools
        || grant.model != binding.model
    {
        return Err("Harness identity is not authorized by operator grant".into());
    }
    let origin = &request.capabilities.egress[0];
    if grant.url != format!("{origin}/chat/completions")
        || grant.model.is_empty()
        || grant.model.len() > 128
        || !grant.credential_file.is_absolute()
        || grant.max_requests == 0
        || grant.max_requests > 6
        || grant.max_output_tokens != 512
        || grant.max_total_output_tokens < 512
        || grant.max_total_output_tokens > 3072
    {
        return Err("unsupported Harness model policy".into());
    }
    let c = &closure.signed.closure;
    // Static adapter only. Broader closures require a dependency/tool contract.
    let mut expected = std::collections::BTreeSet::from([c.entrypoint.as_str(), "/pilot-fetch"]);
    if expected.len() != 2 {
        return Err("Harness runtime cannot be the broker client".into());
    }
    for tool in &binding.borrowed_tools {
        if !expected.insert(&tool.path)
            || c.members
                .get(&tool.path)
                .map_or(true, |m| m.hash != tool.hash)
        {
            return Err("borrowed tool is not a distinct matching closure member".into());
        }
    }
    if c.interpreter
        || c.members
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>()
            != expected
    {
        return Err("unsupported Harness closure composition".into());
    }
    let mut policy =
        warden::egress::HttpPolicy::new(vec![origin.trim_start_matches("https://").into()]);
    policy.max_requests = grant.max_requests;
    policy.timeout = std::time::Duration::from_secs(45).min(std::time::Duration::from_millis(
        request.capabilities.timeout_ms,
    ));
    policy.json_posts.push(warden::egress::JsonPostGrant {
        url: grant.url.clone(),
        bearer_token_file: grant.credential_file,
        model: grant.model.clone(),
        max_output_tokens: grant.max_output_tokens,
        max_total_output_tokens: grant.max_total_output_tokens,
    });
    let config = serde_json::json!({"task":binding.task,"url":grant.url,"model":grant.model,"tools":binding.borrowed_tools});
    Ok(Some(Resolved {
        policy,
        args: vec![config.to_string()],
    }))
}

/// Conservative durable local tombstone: restart must not recreate allowance
/// for an ambiguous provider attempt. Not distributed metering or recovery.
pub fn claim(request: &ExecutionRequest, root: &Path) -> Result<(), String> {
    if request.harness.is_none() {
        return Ok(());
    }
    let identity = serde_json::to_vec(&(&request.workload.caller, &request.id))
        .map_err(|_| "invalid attempt identity")?;
    let dir = root.join("harness-attempts");
    std::fs::create_dir_all(&dir).map_err(|_| "Harness attempt journal unavailable")?;
    let file = dir.join(Hash::of(&identity).0.trim_start_matches("blake3:"));
    let mut record = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(file)
        .map_err(|_| {
            "Harness attempt already claimed or journal unavailable; automatic replay refused"
        })?;
    record
        .write_all(
            Hash::of(&serde_json::to_vec(request).map_err(|_| "invalid Harness request")?)
                .0
                .as_bytes(),
        )
        .and_then(|_| record.sync_all())
        .map_err(|_| "Harness attempt journal sync failed")?;
    std::fs::File::open(&dir)
        .and_then(|f| f.sync_all())
        .map_err(|_| "Harness attempt directory sync failed")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use celln_manifest::closure::{Closure, Member};
    use serde_json::json;
    use std::collections::{BTreeMap, BTreeSet};

    #[test]
    fn operator_binding_and_local_replay_fail_closed_without_io_to_provider() {
        let mut request: ExecutionRequest = serde_json::from_str(include_str!(
            "../../../examples/execution/harness-reference.json"
        ))
        .unwrap();
        let root = tempfile::tempdir().unwrap();
        let h = request.harness.as_ref().unwrap();
        let mut members = BTreeMap::new();
        for tool in &h.borrowed_tools {
            members.insert(
                tool.path.clone(),
                Member {
                    hash: tool.hash.clone(),
                    dependencies: BTreeSet::new(),
                },
            );
        }
        members.insert(
            "/pilot-fetch".into(),
            Member {
                hash: Hash::of(b"fetch").0,
                dependencies: BTreeSet::new(),
            },
        );
        members.insert(
            "/harness".into(),
            Member {
                hash: request.tools[0].hash.clone(),
                dependencies: members.keys().cloned().collect(),
            },
        );
        // Resolve's input is already admitted by the separate signature layer;
        // this unit test exercises binding, not filesystem/signature admission.
        let signed = Closure {
            api_version: "celln.dev/closure-v1".into(),
            toolfs: Hash::of(b"image").0,
            entrypoint: "/harness".into(),
            interpreter: false,
            members,
        }
        .sign(&[19; 32])
        .unwrap();
        let closure = super::super::closure::Admitted {
            provenance: super::super::closure::Provenance {
                hash: request.tools[0].closure.as_ref().unwrap().hash.clone(),
                publisher: signed.publisher.clone(),
                toolfs: signed.closure.toolfs.clone(),
                members: signed.closure.members.clone(),
            },
            signed,
        };
        let grant=serde_json::to_vec(&json!({"apiVersion":"celln.dev/harness-grant-v1","caller":request.workload.caller,"mote":request.mote.as_ref().unwrap().hash,"runtime":request.tools[0].hash,"closure":closure.provenance.hash,"borrowedTools":h.borrowed_tools,"url":"https://api.deepseek.com/chat/completions","model":h.model,"credentialFile":"/not-read-by-resolution","maxRequests":3,"maxOutputTokens":512,"maxTotalOutputTokens":1536})).unwrap();
        request.harness.as_mut().unwrap().model_grant.hash = Hash::of(&grant).0;
        let dir = root.path().join("trusted-harness");
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join(format!(
            "{}.json",
            Hash::of(&grant).0.trim_start_matches("blake3:")
        ));
        assert!(resolve(&request, Some(&closure), root.path()).is_err());
        std::fs::write(&path, &grant).unwrap();
        let resolved = resolve(&request, Some(&closure), root.path())
            .unwrap()
            .unwrap();
        assert_eq!(resolved.policy.json_posts[0].model, "deepseek-chat");
        assert!(!resolved.args[0].contains("not-read-by-resolution"));
        for change in ["caller", "model", "tool", "runtime"] {
            let mut bad = request.clone();
            match change {
                "caller" => bad.workload.caller = "another-caller".into(),
                "model" => bad.harness.as_mut().unwrap().model = "other-model".into(),
                "tool" => {
                    bad.harness.as_mut().unwrap().borrowed_tools[0].hash = Hash::of(b"other").0
                }
                _ => bad.tools[0].hash = Hash::of(b"runtime").0,
            }
            assert!(
                resolve(&bad, Some(&closure), root.path()).is_err(),
                "{change}"
            );
        }
        claim(&request, root.path()).unwrap();
        assert!(claim(&request, root.path()).is_err());
        request.harness.as_mut().unwrap().task = "different task, same attempt".into();
        assert!(claim(&request, root.path()).is_err());
        std::fs::write(&path, b"tampered").unwrap();
        assert!(resolve(&request, Some(&closure), root.path()).is_err());
        std::fs::remove_file(&path).unwrap();
        assert!(resolve(&request, Some(&closure), root.path()).is_err());
    }
}
