//! Durable admission tombstones and terminal records. An interrupted claim is
//! NOT evidence of teardown and never authorizes automatic execution replay.
use super::{execution_is_active, ExecutionRecord};
use anyhow::{bail, Context, Result};
use celln_manifest::Hash;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};

const CAPACITY: usize = 100_000;
const MAX_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Snapshot {
    version: u8,
    pub request_hash: String,
    pub record: ExecutionRecord,
    pub audit: serde_json::Value,
}

fn directory(root: &Path) -> PathBuf {
    root.join("execution-journal")
}
fn path(root: &Path, id: &str) -> PathBuf {
    directory(root).join(format!(
        "{}.json",
        Hash::of(id.as_bytes()).0.trim_start_matches("blake3:")
    ))
}

pub(super) fn prepare(root: &Path) -> Result<()> {
    fs::create_dir_all(directory(root))?;
    for ancestor in fs::canonicalize(directory(root))?.ancestors() {
        fs::File::open(ancestor)?
            .sync_all()
            .context("Unsupported: dispatcher journal requires directory fsync")?;
    }
    Ok(())
}

pub(super) fn read(root: &Path, id: &str) -> Result<Option<Snapshot>> {
    let file = match fs::File::open(path(root, id)) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_BYTES {
        bail!("dispatcher journal record too large");
    }
    let snapshot: Snapshot = serde_json::from_slice(&bytes)?;
    if snapshot.version != 1 || snapshot.record.request_id != id {
        bail!("invalid dispatcher journal identity/version");
    }
    if let Some(receipt) = &snapshot.record.receipt {
        if receipt.request_id != id || format!("{:?}", receipt.phase) != snapshot.record.phase {
            bail!("invalid dispatcher journal receipt");
        }
    }
    // Also finish a directory sync that may have failed after publication in
    // the same process. Never acknowledge terminal durability on equality alone.
    fs::File::open(directory(root))?.sync_all()?;
    Ok(Some(snapshot))
}

fn publish(root: &Path, snapshot: &Snapshot, new: bool) -> Result<()> {
    let bytes = serde_json::to_vec(snapshot)?;
    if bytes.len() as u64 > MAX_BYTES {
        bail!("dispatcher journal record too large");
    }
    let mut file = tempfile::NamedTempFile::new_in(directory(root))?;
    file.write_all(&bytes)?;
    file.as_file().sync_all()?;
    let destination = path(root, &snapshot.record.request_id);
    if new {
        file.persist_noclobber(destination)?;
    } else {
        file.persist(destination)?;
    }
    fs::File::open(directory(root))?.sync_all()?;
    Ok(())
}

// Caller holds the execution registry lock; serve also owns dispatcher.lock.
pub(super) fn claim(
    root: &Path,
    body: &[u8],
    record: &ExecutionRecord,
    audit: &super::audit::Audit,
) -> Result<()> {
    claim_with_capacity(root, body, record, audit, CAPACITY)
}

fn claim_with_capacity(
    root: &Path,
    body: &[u8],
    record: &ExecutionRecord,
    audit: &super::audit::Audit,
    capacity: usize,
) -> Result<()> {
    prepare(root)?;
    if fs::read_dir(directory(root))?
        .filter(|e| {
            e.as_ref()
                .map_or(true, |e| e.path().extension().is_some_and(|s| s == "json"))
        })
        .take(capacity)
        .count()
        >= capacity
    {
        bail!("dispatcher journal capacity exhausted; operator reconciliation required");
    }
    publish(
        root,
        &Snapshot {
            version: 1,
            request_hash: Hash::of(body).0,
            record: record.clone(),
            audit: serde_json::to_value(audit)?,
        },
        true,
    )
}

pub(super) fn complete(
    root: &Path,
    record: &ExecutionRecord,
    audit: &super::audit::Audit,
) -> Result<()> {
    if execution_is_active(record) {
        bail!("cannot archive active execution as terminal");
    }
    let previous = read(root, &record.request_id)?.context("missing durable admission claim")?;
    let snapshot = Snapshot {
        version: 1,
        request_hash: previous.request_hash.clone(),
        record: record.clone(),
        audit: serde_json::to_value(audit)?,
    };
    if !execution_is_active(&previous.record) {
        if serde_json::to_vec(&previous)? != serde_json::to_vec(&snapshot)? {
            bail!("terminal journal record is immutable");
        }
        // Retry the sync too: a previous publication may have succeeded while
        // its directory fsync failed. Equality alone does not prove durability.
        fs::File::open(directory(root))?.sync_all()?;
        return Ok(());
    }
    publish(root, &snapshot, false)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    #[test]
    fn claims_survive_restart_and_terminal_records_are_immutable() {
        let root = tempfile::tempdir().unwrap();
        let mut record = ExecutionRecord {
            request_id: "../safe-hashed-id".into(),
            phase: "Admitting".into(),
            reason: None,
            output: None,
            receipt: None,
        };
        let request: celln_spec::ExecutionRequest = serde_json::from_value(serde_json::json!({
            "apiVersion":"celln.dev/v1alpha1", "id":record.request_id,
            "workload":{"id":"test","caller":"test"},
            "capabilities":{"workspace":"none","timeoutMs":1000,"memoryBytes":1,"outputBytes":1},
            "execution":{"lane":"tool","requireHardwareIsolation":true}
        }))
        .unwrap();
        let audit = super::super::audit::Audit::new(&request, "test");
        claim(root.path(), b"body", &record, &audit).unwrap();
        let mut another = record.clone();
        another.request_id = "second".into();
        assert!(claim_with_capacity(root.path(), b"second", &another, &audit, 1).is_err());
        assert!(read(root.path(), "second").unwrap().is_none());
        assert!(execution_is_active(
            &read(root.path(), &record.request_id)
                .unwrap()
                .unwrap()
                .record
        ));
        assert!(claim(root.path(), b"body", &record, &audit).is_err());
        record.phase = "Refused".into();
        record.reason = Some("test refusal".into());
        complete(root.path(), &record, &audit).unwrap();
        complete(root.path(), &record, &audit).unwrap();
        assert_eq!(
            read(root.path(), &record.request_id)
                .unwrap()
                .unwrap()
                .record
                .reason,
            record.reason
        );
        record.reason = Some("changed".into());
        assert!(complete(root.path(), &record, &audit).is_err());
        fs::write(path(root.path(), &record.request_id), b"corrupt").unwrap();
        assert!(read(root.path(), &record.request_id).is_err());
    }
}
