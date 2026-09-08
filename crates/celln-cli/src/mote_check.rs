//! Isolated cold-path member verification; never admits to a production host.
use anyhow::{ensure, Result};
use celln_manifest::{closure::SignedClosure, Hash};
use celln_store::Store;
use serde_json::{json, Value};
use std::{fs, io::Read, path::Path};

fn read_manifest(path: &Path) -> Result<Option<Vec<u8>>> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = match options.open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    ensure!(
        file.metadata()?.is_file(),
        "regular local manifest required"
    );
    let mut bytes = Vec::new();
    file.take((8 << 20) + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 8 << 20, "local manifest exceeds check limit");
    Ok(Some(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn local_manifest_read_is_bounded_and_refuses_nonregular_inputs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("manifest");
        assert!(read_manifest(&path).unwrap().is_none());
        fs::write(&path, b"{}").unwrap();
        assert_eq!(read_manifest(&path).unwrap(), Some(b"{}".to_vec()));
        fs::File::create(&path)
            .unwrap()
            .set_len((8 << 20) + 1)
            .unwrap();
        assert!(read_manifest(&path).is_err());
        assert!(read_manifest(dir.path()).is_err());
        #[cfg(unix)]
        {
            let link = dir.path().join("link");
            std::os::unix::fs::symlink(&path, &link).unwrap();
            assert!(read_manifest(&link).is_err());
        }
    }
}

pub fn check(
    candidate: &Path,
    template_hash: &str,
    mote_store: &Path,
    tool_store: &Path,
    root: &Path,
) -> Result<Value> {
    let work = crate::agent::tempdir()?;
    let prepared = work.path().join("prepared");
    // Regenerate from verified inputs; never trust a caller's prepared.json or
    // mote.json to grant authority. Template hash comes from operator config.
    let report = crate::mote_prepare::prepare(
        &candidate.join("template.json"),
        template_hash,
        &candidate.join("signed-closure.json"),
        &candidate.join("toolfs.ext2"),
        mote_store,
        &prepared,
        root,
    )?;
    let raw = crate::closure_policy::read_bounded(&prepared.join("signed-closure.json"))
        .map_err(anyhow::Error::msg)?;
    let signed: SignedClosure = serde_json::from_slice(&raw)?;
    let policy_path = root.join("trusted-closures.json");
    let policy = crate::closure_policy::read_bounded(&policy_path).map_err(anyhow::Error::msg)?;
    ensure!(
        report["policyHash"] == Hash::of(&policy).0,
        "policy changed before member check"
    );
    let manifest_path = root.join("assay/manifest.json");
    let manifest = read_manifest(&manifest_path)?;
    let stage = work.path().join("stage");
    fs::create_dir(&stage)?;
    fs::write(stage.join("trusted-closures.json"), &policy)?;
    if let Some(bytes) = &manifest {
        fs::create_dir(stage.join("assay"))?;
        fs::write(stage.join("assay/manifest.json"), bytes)?;
    }
    let motes = Store::open(stage.join("motes"))?;
    for name in ["kernel", "initrd", "toolfs.ext2", "mote.json"] {
        motes.put(&fs::read(prepared.join(name))?)?;
    }
    Store::open(stage.join("closures"))?.put(&raw)?;
    // This allowlist exists only in the owned temporary verification root. It
    // cannot be used by the production dispatcher and is removed on return.
    fs::write(
        stage.join("trusted-motes.json"),
        serde_json::to_vec(
            &json!({"apiVersion":"celln.dev/v1alpha1","bundles":[report["mote"]["hash"]]}),
        )?,
    )?;
    let request = serde_json::from_value(json!({
        "apiVersion":"celln.dev/v1alpha1","id":"candidate-member-check","workload":{"id":"candidate-member-check","caller":"operator:admission-review"},
        "mote":report["mote"],"tools":[{"alias":signed.closure.entrypoint,"hash":signed.closure.members[&signed.closure.entrypoint].hash,"closure":report["closure"]}],
        "invocation":{"alias":signed.closure.entrypoint,"args":[]},
        "capabilities":{"workspace":"none","egress":[],"timeoutMs":10000,"memoryBytes":268435456,"outputBytes":4096},
        "execution":{"lane":"agent","requireHardwareIsolation":true}
    }))?;
    let members =
        crate::dispatch::check_members(&request, &stage.join("motes"), tool_store, &stage)
            .map_err(anyhow::Error::msg)?;
    let current = crate::closure_policy::verify(&raw, root).map_err(anyhow::Error::msg)?;
    ensure!(
        current.policy_hash.0 == report["policyHash"],
        "policy changed during member check"
    );
    let current_manifest = read_manifest(&manifest_path)?;
    ensure!(
        current_manifest == manifest,
        "local manifest changed during member check"
    );
    Ok(
        json!({"apiVersion":"celln.dev/prepared-members-check-v1","template":template_hash,"mote":report["mote"],"closure":report["closure"],"policyHash":report["policyHash"],"members":members,"admitted":false,"executionAuthorized":false,"runtimeConformance":"not_checked","readiness":"not_established"}),
    )
}
