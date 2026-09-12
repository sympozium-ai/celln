//! Explicit administrator-only host admission. Never exposed to guest requests.
use anyhow::{ensure, Result};
use celln_manifest::Hash;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::BTreeSet, fs, io::Write, path::Path};

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Policy {
    api_version: String,
    bundles: BTreeSet<String>,
}

fn valid_hash(hash: &str) -> bool {
    hash.strip_prefix("blake3:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

// flock belongs to an open file description: an unrelated concurrent fork can
// retain it after this process closes its fd. End the critical section explicitly
// in its owning process; a child dropping an inherited guard must not unlock it.
struct AdmissionLock {
    #[cfg(target_os = "linux")]
    file: fs::File,
    #[cfg(target_os = "linux")]
    owner_pid: u32,
}
impl Drop for AdmissionLock {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        if std::process::id() == self.owner_pid {
            use std::os::fd::AsRawFd;
            loop {
                if unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) } == 0
                    || std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted
                {
                    break;
                }
            }
        }
    }
}

fn lock(root: &Path) -> Result<AdmissionLock> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = root;
        anyhow::bail!("Unsupported: durable admission requires Linux");
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::{fd::AsRawFd, unix::fs::OpenOptionsExt};
        fs::create_dir_all(root)?;
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(root.join("mote-admission.lock"))?;
        ensure!(
            file.metadata()?.is_file(),
            "regular admission lock required"
        );
        ensure!(
            unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "admission is busy; retry later"
        );
        Ok(AdmissionLock {
            file,
            owner_pid: std::process::id(),
        })
    }
}

fn read_policy(root: &Path) -> Result<(Policy, Option<Vec<u8>>)> {
    let path = root.join("trusted-motes.json");
    if !path.try_exists()? {
        return Ok((
            Policy {
                api_version: "celln.dev/v1alpha1".into(),
                bundles: BTreeSet::new(),
            },
            None,
        ));
    }
    let bytes = crate::closure_policy::read_bounded(&path).map_err(anyhow::Error::msg)?;
    let policy: Policy = serde_json::from_slice(&bytes)?;
    ensure!(
        policy.api_version == "celln.dev/v1alpha1"
            && policy.bundles.len() <= 1024
            && policy.bundles.iter().all(|h| valid_hash(h)),
        "invalid or oversized mote policy"
    );
    Ok((policy, Some(bytes)))
}

fn atomic_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("parent required"))?;
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.write_all(bytes)?;
    file.as_file().sync_all()?;
    file.persist(path).map_err(|e| e.error)?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

fn commit_policy(root: &Path, policy: &Policy, previous: &Option<Vec<u8>>) -> Result<()> {
    ensure!(
        &read_policy(root)?.1 == previous,
        "mote policy changed outside admission lock"
    );
    ensure!(policy.bundles.len() <= 1024, "mote admission policy full");
    atomic_file(
        &root.join("trusted-motes.json"),
        &serde_json::to_vec(policy)?,
    )
}

// Publish immutable objects durably before granting authority. A corrupt
// pre-existing object refuses; never trust Store::put's dedup result alone.
fn publish(root: &Path, bytes: &[u8]) -> Result<Hash> {
    let hash = Hash::of(bytes);
    let hex = &hash.0[7..];
    let objects = root.join("objects");
    let parent = objects.join(&hex[..2]);
    fs::create_dir_all(&parent)?;
    let target = parent.join(hex);
    let mut temp = tempfile::NamedTempFile::new_in(&parent)?;
    temp.write_all(bytes)?;
    temp.as_file().sync_all()?;
    match temp.persist_noclobber(&target) {
        Ok(_) => (),
        Err(e) if e.error.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(e) => return Err(e.error.into()),
    }
    let stored = celln_store::Store::open(root)?.get_bounded(&hash, bytes.len())?;
    ensure!(stored == bytes, "published object mismatch");
    fs::File::open(&target)?.sync_all()?;
    for dir in [&parent, &objects, &root.to_path_buf()] {
        fs::File::open(dir)?.sync_all()?;
    }
    Ok(hash)
}

pub fn admit(
    candidate: &Path,
    template_hash: &str,
    expected_mote: &str,
    motes: &Path,
    tools: &Path,
    root: &Path,
) -> Result<Value> {
    ensure!(
        valid_hash(expected_mote),
        "exact approved mote hash required"
    );
    let _lock = lock(root)?;
    let (mut policy, previous) = read_policy(root)?;
    let work = crate::agent::tempdir()?;
    let prepared = work.path().join("prepared");
    let report = crate::mote_prepare::prepare(
        &candidate.join("template.json"),
        template_hash,
        &candidate.join("signed-closure.json"),
        &candidate.join("toolfs.ext2"),
        motes,
        &prepared,
        root,
    )?;
    ensure!(
        report["mote"]["hash"] == expected_mote,
        "candidate differs from explicit administrator approval"
    );
    let checked = crate::mote_check::check(&prepared, template_hash, motes, tools, root)?;
    ensure!(
        checked["mote"] == report["mote"]
            && checked["closure"] == report["closure"]
            && checked["policyHash"] == report["policyHash"],
        "candidate or policy changed during checking"
    );
    for name in ["kernel", "initrd", "toolfs.ext2", "mote.json"] {
        publish(motes, &fs::read(prepared.join(name))?)?;
    }
    let raw = fs::read(prepared.join("signed-closure.json"))?;
    publish(&root.join("closures"), &raw)?;
    let current = crate::closure_policy::verify(&raw, root).map_err(anyhow::Error::msg)?;
    ensure!(
        current.policy_hash.0 == report["policyHash"],
        "closure policy changed before admission"
    );
    // Evidence precedes the authority commit. A record alone is never admission;
    // readers must consult current host policy. Unused blobs are safe on failure.
    let records = root.join("mote-admission-evidence");
    fs::create_dir_all(&records)?;
    atomic_file(
        &records.join(format!("{}.json", &expected_mote[7..])),
        &serde_json::to_vec(&checked)?,
    )?;
    policy.bundles.insert(expected_mote.into());
    let manifest = crate::mote_check::read_manifest(&root.join("assay/manifest.json"))?;
    ensure!(
        serde_json::to_value(manifest.as_ref().map(|b| Hash::of(b).0))?
            == checked["localManifestHash"],
        "local manifest changed before admission"
    );
    commit_policy(root, &policy, &previous)?;
    Ok(
        json!({"mote":{"hash":expected_mote},"closure":report["closure"],"admitted":true,"executionAuthorized":false,"readiness":"not_established","scope":"explicit administrator host admission; independent run/model grants still required"}),
    )
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    #[test]
    fn forked_child_cannot_unlock_owners_admission() {
        let dir = tempfile::tempdir().unwrap();
        let guard = lock(dir.path()).unwrap();
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            // Child path uses only getpid/close then _exit; no allocator, logging
            // or general Rust cleanup after forking a multithreaded test runner.
            drop(guard);
            unsafe { libc::_exit(0) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert_eq!(status, 0);
        assert!(lock(dir.path()).is_err());
        drop(guard);
        assert!(lock(dir.path()).is_ok());
    }

    #[test]
    fn duplicated_descriptor_cannot_extend_completed_admission_lock() {
        use std::os::fd::{AsRawFd, FromRawFd};
        let dir = tempfile::tempdir().unwrap();
        let guard = lock(dir.path()).unwrap();
        let duplicate = unsafe { libc::dup(guard.file.as_raw_fd()) };
        assert!(duplicate >= 0);
        let duplicate = unsafe { fs::File::from_raw_fd(duplicate) };
        assert!(lock(dir.path()).is_err());
        drop(guard);
        let next = lock(dir.path()).unwrap();
        drop(duplicate);
        assert!(lock(dir.path()).is_err());
        drop(next);
        assert!(lock(dir.path()).is_ok());
    }

    #[test]
    fn policy_commit_preserves_other_motes_and_detects_external_changes() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let _lock = lock(root).unwrap();
        assert!(lock(root).is_err());
        let (mut policy, previous) = read_policy(root).unwrap();
        let a = Hash::of(b"a").0;
        let b = Hash::of(b"b").0;
        policy.bundles.extend([a.clone(), b.clone()]);
        commit_policy(root, &policy, &previous).unwrap();
        assert!(commit_policy(root, &policy, &previous).is_err());
        drop(_lock);
        withdraw(&a, root).unwrap();
        withdraw(&a, root).unwrap();
        assert_eq!(read_policy(root).unwrap().0.bundles, BTreeSet::from([b]));
        fs::write(root.join("trusted-motes.json"), b"{}").unwrap();
        assert!(withdraw(&a, root).is_err());
        assert_eq!(fs::read(root.join("trusted-motes.json")).unwrap(), b"{}");
    }
    #[test]
    fn publication_is_verified_and_corrupt_dedup_refuses() {
        let dir = tempfile::tempdir().unwrap();
        let hash = publish(dir.path(), b"bytes").unwrap();
        assert_eq!(publish(dir.path(), b"bytes").unwrap(), hash);
        let hex = &hash.0[7..];
        let path = dir.path().join("objects").join(&hex[..2]).join(hex);
        fs::write(&path, b"corrupt").unwrap();
        assert!(publish(dir.path(), b"bytes").is_err());
        assert_eq!(fs::read(&path).unwrap(), b"corrupt");
    }
    #[test]
    fn bad_approval_refuses_before_creating_authority() {
        let dir = tempfile::tempdir().unwrap();
        assert!(admit(dir.path(), "bad", "bad", dir.path(), dir.path(), dir.path()).is_err());
        assert!(!dir.path().join("trusted-motes.json").exists());
    }
}

pub fn withdraw(mote: &str, root: &Path) -> Result<()> {
    ensure!(valid_hash(mote), "exact mote hash required");
    let _lock = lock(root)?;
    let (mut policy, previous) = read_policy(root)?;
    policy.bundles.remove(mote);
    commit_policy(root, &policy, &previous)?;
    println!(
        "{}",
        json!({"mote":mote,"admitted":false,"activeCellsCancelled":false})
    );
    Ok(())
}
