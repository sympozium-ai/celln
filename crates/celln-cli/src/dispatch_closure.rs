//! Resolve authenticated, precomposed closures without consulting host runtimes.
use celln_manifest::{closure::SignedClosure, Hash};
use celln_spec::ExecutionRequest;
use serde::Serialize;
use std::path::Path;

#[cfg(all(test, target_os = "linux"))]
#[path = "dispatch_closure_tests.rs"]
mod tests;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Provenance {
    pub hash: String,
    pub publisher: String,
    pub toolfs: String,
    pub members: std::collections::BTreeMap<String, celln_manifest::closure::Member>,
}

pub struct Admitted {
    pub signed: SignedClosure,
    pub provenance: Provenance,
}

pub fn resolve(
    request: &ExecutionRequest,
    bundle: &super::ResolvedBundle,
    root: &Path,
) -> Result<Option<Admitted>, String> {
    let Some(reference) = request.tools.first().and_then(|t| t.closure.as_ref()) else {
        if bundle.format.as_deref() == Some("celln.warm-closure-v1") {
            return Err("closure substrate requires explicit closure identity".into());
        }
        return Ok(None);
    };
    if bundle.format.as_deref() != Some("celln.warm-closure-v1") {
        return Err(
            "unsupported authority: closure requires celln.warm-closure-v1 substrate".into(),
        );
    }
    let store = celln_store::Store::open(root.join("closures")).map_err(|e| e.to_string())?;
    let bytes = store
        .get_bounded(&Hash(reference.hash.clone()), 262144)
        .map_err(|e| e.to_string())?;
    if bytes.len() > 262144 {
        return Err("closure descriptor exceeds limit".into());
    }
    let verified = crate::closure_policy::verify(&bytes, root)?;
    let signed = verified.signed;
    let closure = &signed.closure;
    if bundle.toolfs_bytes.len() as u64 > crate::image::MAX_IMAGE_BYTES {
        return Err("unsupported closure filesystem exceeds 512 MiB".into());
    }
    if closure.toolfs != bundle.toolfs_hash
        || closure.members[&closure.entrypoint].hash != bundle.program_hash
    {
        return Err("closure does not bind selected filesystem and executable".into());
    }
    let provenance = Provenance {
        hash: reference.hash.clone(),
        publisher: signed.publisher.clone(),
        toolfs: closure.toolfs.clone(),
        members: closure.members.clone(),
    };
    Ok(Some(Admitted { signed, provenance }))
}
