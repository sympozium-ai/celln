//! Offline publisher tooling. Private keys never enter a dispatcher request.
use anyhow::{Context, Result};
use celln_manifest::closure::Closure;
use std::{io::Read, path::Path};

fn read(path: &Path) -> Result<Vec<u8>> {
    crate::closure_policy::read_bounded(path).map_err(anyhow::Error::msg)
}

pub fn sign(descriptor: &Path, key: &Path) -> Result<u8> {
    let closure: Closure = serde_json::from_slice(&read(descriptor)?)?;
    let mut seed = zeroize::Zeroizing::new([0u8; 32]);
    let mut source = std::fs::File::open(key).context("opening private seed file")?;
    source
        .read_exact(&mut *seed)
        .context("private seed must contain exactly 32 raw bytes")?;
    let mut extra = [0];
    anyhow::ensure!(
        source.read(&mut extra)? == 0,
        "private seed must contain exactly 32 raw bytes"
    );
    let signed = closure.sign(&seed).map_err(anyhow::Error::msg);
    println!("{}", serde_json::to_string_pretty(&signed?)?);
    Ok(0)
}

pub fn admit(descriptor: &Path, root: &Path) -> Result<u8> {
    let bytes = read(descriptor)?;
    let verified = crate::closure_policy::verify(&bytes, root).map_err(anyhow::Error::msg)?;
    let hash = celln_store::Store::open(root.join("closures"))?.put(&bytes)?;
    println!(
        "{}",
        serde_json::json!({"closure": hash.0,"publisher": verified.signed.publisher})
    );
    Ok(0)
}

pub fn verify(
    descriptor: &Path,
    root: &Path,
    expected_hash: &str,
    publisher: &str,
    entry_point: &str,
    executable: &str,
    toolfs: Option<&Path>,
) -> Result<u8> {
    let bytes = read(descriptor)?;
    let mut report = verification_report(
        &bytes,
        root,
        expected_hash,
        publisher,
        entry_point,
        executable,
    )?;
    if let Some(path) = toolfs {
        let size = verify_toolfs(path, report["toolfs"].as_str().unwrap())?;
        // A large artifact read must not hide a policy change during review.
        let current = verification_report(
            &bytes,
            root,
            expected_hash,
            publisher,
            entry_point,
            executable,
        )?;
        anyhow::ensure!(
            current["policyHash"] == report["policyHash"],
            "policy changed during verification"
        );
        report["scope"] = "descriptor-and-local-toolfs-bytes".into();
        report["localToolfsBytes"] = size.into();
        report["localToolfsVerified"] = true.into();
        // Distribution, member semantics and guest conformance remain separate gates.
    }
    println!("{}", serde_json::to_string(&report)?);
    Ok(0)
}

fn verify_toolfs(path: &Path, expected: &str) -> Result<u64> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Refuse symlinks and avoid hanging on a FIFO supplied as an artifact.
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .context("opening local closure filesystem")?;
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.is_file(),
        "closure filesystem must be a regular file"
    );
    anyhow::ensure!(
        metadata.len() > 0 && metadata.len() <= crate::image::MAX_IMAGE_BYTES,
        "closure filesystem must contain 1..512 MiB"
    );
    let mut bytes = Vec::new();
    file.take(crate::image::MAX_IMAGE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(
        !bytes.is_empty() && bytes.len() as u64 <= crate::image::MAX_IMAGE_BYTES,
        "closure filesystem exceeds byte ceiling or is empty"
    );
    anyhow::ensure!(
        celln_manifest::Hash::of(&bytes).0 == expected,
        "closure filesystem identity mismatch"
    );
    Ok(bytes.len() as u64)
}

fn verification_report(
    bytes: &[u8],
    root: &Path,
    expected_hash: &str,
    publisher: &str,
    entry_point: &str,
    executable: &str,
) -> Result<serde_json::Value> {
    let verified = crate::closure_policy::verify(bytes, root).map_err(anyhow::Error::msg)?;
    anyhow::ensure!(
        verified.identity.0 == expected_hash,
        "closure identity mismatch"
    );
    anyhow::ensure!(
        verified.signed.publisher == publisher,
        "catalogue publisher mismatch"
    );
    let closure = &verified.signed.closure;
    anyhow::ensure!(
        closure
            .members
            .get(entry_point)
            .is_some_and(|member| member.hash == executable),
        "catalogue executable member mismatch"
    );
    Ok(serde_json::json!({
        "apiVersion": "celln.dev/closure-verification-v1",
        "scope": "descriptor-authenticity-only",
        "closure": verified.identity.0,
        "policyHash": verified.policy_hash.0,
        "publisher": verified.signed.publisher,
        "entryPoint": entry_point,
        "executable": executable,
        "toolfs": closure.toolfs,
        "closureEntryPoint": closure.entrypoint,
        "interpreter": closure.interpreter,
        "members": closure.members,
        "artifactReadiness": "not_checked",
        "conformance": "not_checked"
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use celln_manifest::{closure::Member, Hash};
    use std::collections::{BTreeMap, BTreeSet};

    #[test]
    fn local_artifact_refuses_missing_empty_oversized_and_nonregular_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("toolfs");
        let expected = Hash::of(b"test").0;
        assert!(verify_toolfs(&path, &expected).is_err());
        assert!(verify_toolfs(dir.path(), &expected).is_err());
        std::fs::write(&path, b"").unwrap();
        assert!(verify_toolfs(&path, &expected).is_err());
        std::fs::File::create(&path)
            .unwrap()
            .set_len(crate::image::MAX_IMAGE_BYTES + 1)
            .unwrap();
        assert!(verify_toolfs(&path, &expected).is_err());
        std::fs::write(&path, b"test").unwrap();
        assert_eq!(verify_toolfs(&path, &expected).unwrap(), 4);
        #[cfg(unix)]
        {
            let alias = dir.path().join("alias");
            std::os::unix::fs::symlink(&path, &alias).unwrap();
            assert!(verify_toolfs(&alias, &expected).is_err());
        }
    }

    fn fixture() -> (tempfile::TempDir, Vec<u8>, String, String) {
        let root = tempfile::tempdir().unwrap();
        let executable = Hash::of(b"fixture executable").0;
        let signed = Closure {
            api_version: "celln.dev/closure-v1".into(),
            toolfs: Hash::of(b"fixture filesystem").0,
            entrypoint: "/tools/example".into(),
            interpreter: false,
            members: BTreeMap::from([(
                "/tools/example".into(),
                Member {
                    hash: executable.clone(),
                    dependencies: BTreeSet::new(),
                },
            )]),
        }
        .sign(&[42; 32])
        .unwrap();
        let publisher = signed.publisher.clone();
        std::fs::write(root.path().join("trusted-closures.json"), serde_json::to_vec(&serde_json::json!({"apiVersion":"celln.dev/closure-policy-v1","publishers":[publisher],"revoked":[]})).unwrap()).unwrap();
        (
            root,
            serde_json::to_vec_pretty(&signed).unwrap(),
            publisher,
            executable,
        )
    }

    #[test]
    fn report_binds_exact_bytes_and_does_not_admit_or_claim_readiness() {
        let (root, bytes, publisher, executable) = fixture();
        let expected = Hash::of(&bytes).0;
        let report = verification_report(
            &bytes,
            root.path(),
            &expected,
            &publisher,
            "/tools/example",
            &executable,
        )
        .unwrap();
        assert_eq!(report["closure"], expected);
        assert_eq!(report["artifactReadiness"], "not_checked");
        assert_eq!(report["conformance"], "not_checked");
        assert_eq!(report["scope"], "descriptor-authenticity-only");
        assert_eq!(
            report["policyHash"],
            Hash::of(&std::fs::read(root.path().join("trusted-closures.json")).unwrap()).0
        );
        assert!(!root.path().join("closures").exists());
        for (hash, key, path, program) in [
            (
                "wrong",
                publisher.as_str(),
                "/tools/example",
                executable.as_str(),
            ),
            (
                expected.as_str(),
                "wrong",
                "/tools/example",
                executable.as_str(),
            ),
            (
                expected.as_str(),
                publisher.as_str(),
                "/tools/unlisted",
                executable.as_str(),
            ),
            (
                expected.as_str(),
                publisher.as_str(),
                "/tools/example",
                "wrong",
            ),
        ] {
            assert!(verification_report(&bytes, root.path(), hash, key, path, program).is_err());
        }
        let mut reformatted = bytes.clone();
        reformatted.push(b'\n');
        assert!(verification_report(
            &reformatted,
            root.path(),
            &expected,
            &publisher,
            "/tools/example",
            &executable
        )
        .is_err());
    }

    #[test]
    fn shared_verifier_rechecks_policy_and_all_revocation_targets() {
        let (root, bytes, publisher, executable) = fixture();
        let signed: celln_manifest::closure::SignedClosure =
            serde_json::from_slice(&bytes).unwrap();
        for revoked in [Hash::of(&bytes).0, signed.closure.toolfs, executable] {
            std::fs::write(root.path().join("trusted-closures.json"),serde_json::to_vec(&serde_json::json!({"apiVersion":"celln.dev/closure-policy-v1","publishers":[publisher],"revoked":[revoked]})).unwrap()).unwrap();
            assert!(crate::closure_policy::verify(&bytes, root.path())
                .err()
                .unwrap()
                .contains("revoked"));
        }
    }

    #[test]
    fn shared_verifier_refuses_tampering_missing_trust_and_oversize() {
        let (root, bytes, _, _) = fixture();
        let mut tampered: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        tampered["closure"]["interpreter"] = true.into();
        assert!(crate::closure_policy::verify(
            &serde_json::to_vec(&tampered).unwrap(),
            root.path()
        )
        .is_err());
        assert!(crate::closure_policy::verify(&vec![b' '; 262145], root.path()).is_err());
        for policy in [
            serde_json::json!({"apiVersion":"unknown","publishers":[],"revoked":[]}).to_string(),
            serde_json::json!({"apiVersion":"celln.dev/closure-policy-v1","publishers":[],"revoked":[]}).to_string(),
            " ".repeat(262145),
            "invalid".into(),
        ] {
            std::fs::write(root.path().join("trusted-closures.json"),policy).unwrap();
            assert!(crate::closure_policy::verify(&bytes,root.path()).is_err());
        }
        let absent = tempfile::tempdir().unwrap();
        assert!(crate::closure_policy::verify(&bytes, absent.path()).is_err());
    }
}
