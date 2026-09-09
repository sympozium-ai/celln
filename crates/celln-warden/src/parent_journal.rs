//! Durable parent incarnation tombstone and immutable turn stages. This is
//! audit/replay prevention, NOT a guest checkpoint. Creation refuses an existing
//! incarnation; after owner loss callers must report context loss, not resume.
use crate::{parent_lease::ReservedTurn, parent_protocol::TurnRequest};
use celln_manifest::Hash;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

pub struct ParentJournal {
    directory: PathBuf,
    parent: Hash,
    reservations: usize,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reservation {
    pub version: u8,
    pub parent: Hash,
    pub child: Hash,
    pub request: TurnRequest,
    pub memory_bytes: u64,
    pub timeout_nanos: u128,
    pub model_requests: u64,
    pub output_tokens: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DestroyedRecord {
    pub version: u8,
    pub parent: Hash,
    pub child: Hash,
    pub turn_id: String,
    pub succeeded: bool,
    pub answer: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CommittedRecord {
    version: u8,
    parent: Hash,
    child: Hash,
    turn_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ParentRecord {
    version: u8,
    parent: Hash,
    recovery: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerRecord {
    version: u8,
    parent: Hash,
    principal: String,
}

/// Authorize historical reads only. Never reconstruct an owner from this record
/// or accept its principal from an unauthenticated request body.
pub fn historical_owner(root: &Path, parent: &Hash, principal: &str) -> io::Result<bool> {
    let directory = parent_directory(root, parent);
    let identity: ParentRecord = read_record(&directory.join("parent.json"))?;
    let owner: OwnerRecord = read_record(&directory.join("owner.json"))?;
    if identity.version != 1
        || identity.parent != *parent
        || identity.recovery != "context-lost-without-live-owner"
        || owner.version != 1
        || owner.parent != *parent
        || !valid_principal(&owner.principal)
    {
        return Err(invalid());
    }
    Ok(owner.principal == principal)
}

fn valid_principal(principal: &str) -> bool {
    !principal.is_empty() && principal.len() <= 512 && !principal.chars().any(char::is_control)
}

/// Durable observations only. None of these stages proves that a live parent
/// still exists or permits replay. Missing records are not permission to spawn.
#[derive(Debug, Serialize)]
#[serde(tag = "stage", content = "record", rename_all = "kebab-case")]
pub enum TurnStatus {
    Reserved(Reservation),
    ChildDestroyed(DestroyedRecord),
    ParentCommitted(DestroyedRecord),
}

fn read_record<T: serde::de::DeserializeOwned>(path: &Path) -> io::Result<T> {
    let mut bytes = Vec::new();
    fs::File::open(path)?.take(16385).read_to_end(&mut bytes)?;
    if bytes.len() > 16384 {
        return Err(invalid());
    }
    serde_json::from_slice(&bytes).map_err(|_| invalid())
}

fn parent_directory(root: &Path, parent: &Hash) -> PathBuf {
    root.join(
        Hash::of(parent.0.as_bytes())
            .0
            .trim_start_matches("blake3:"),
    )
}

/// Inspect an old incarnation without reopening it for execution. The caller
/// must independently consult its live-owner registry; absent that owner, report
/// context loss even when this returns ParentCommitted. Reads concurrent with
/// the owner can lag publication, so this is not a linearizable serving status.
pub fn inspect_turn(root: &Path, parent: &Hash, turn: &str) -> io::Result<TurnStatus> {
    let journal = ParentJournal {
        directory: parent_directory(root, parent),
        parent: parent.clone(),
        reservations: 0,
    };
    let identity: ParentRecord = read_record(&journal.directory.join("parent.json"))?;
    if identity.version != 1
        || identity.parent != *parent
        || identity.recovery != "context-lost-without-live-owner"
    {
        return Err(invalid());
    }
    let reservation = journal.reservation(turn)?;
    let committed = match read_record::<CommittedRecord>(
        &journal
            .directory
            .join(ParentJournal::filename(turn, "committed")),
    ) {
        Ok(record) => {
            if record.version != 1
                || record.parent != *parent
                || record.child != reservation.child
                || record.turn_id != turn
            {
                return Err(invalid());
            }
            true
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err(error),
    };
    match journal.destroyed(turn, &reservation.child) {
        Ok(record) if committed => Ok(TurnStatus::ParentCommitted(record)),
        Ok(record) => Ok(TurnStatus::ChildDestroyed(record)),
        Err(error) if error.kind() == io::ErrorKind::NotFound && !committed => {
            Ok(TurnStatus::Reserved(reservation))
        }
        Err(error) => Err(error),
    }
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid parent journal identity or transition",
    )
}
fn publish(directory: &Path, name: &str, value: &impl Serialize) -> io::Result<()> {
    let bytes = serde_json::to_vec(value).map_err(|_| invalid())?;
    if bytes.len() > 16384 {
        return Err(invalid());
    }
    let mut file = tempfile::NamedTempFile::new_in(directory)?;
    file.write_all(&bytes)?;
    file.as_file().sync_all()?;
    file.persist_noclobber(directory.join(name))
        .map_err(|e| e.error)?;
    fs::File::open(directory)?.sync_all()
}

impl ParentJournal {
    /// Persist the independently authenticated owner before runtime creation.
    /// A missing/partial record permits no historical access and no replay.
    pub fn bind_owner(&self, principal: &str) -> io::Result<()> {
        if !valid_principal(principal) {
            return Err(invalid());
        }
        publish(
            &self.directory,
            "owner.json",
            &OwnerRecord {
                version: 1,
                parent: self.parent.clone(),
                principal: principal.into(),
            },
        )
    }

    /// Root is an operator-owned directory. Must complete before starting a
    /// parent. A partially-created directory remains a fail-closed tombstone.
    pub fn create(root: &Path, parent: Hash) -> io::Result<Self> {
        fs::create_dir_all(root)?;
        let directory = parent_directory(root, &parent);
        fs::create_dir(&directory)?;
        for ancestor in fs::canonicalize(&directory)?.ancestors() {
            fs::File::open(ancestor)?.sync_all()?;
        }
        publish(
            &directory,
            "parent.json",
            &serde_json::json!({"version":1,"parent":parent,"recovery":"context-lost-without-live-owner"}),
        )?;
        Ok(Self {
            directory,
            parent,
            reservations: 0,
        })
    }

    fn filename(turn_id: &str, stage: &str) -> String {
        format!(
            "{}.{stage}.json",
            Hash::of(turn_id.as_bytes()).0.trim_start_matches("blake3:")
        )
    }

    /// Caller must reserve in-memory authority first, then persist here, then
    /// spawn. Any failure consumes the attempted reservation; never refund it.
    pub fn reserve(&mut self, turn: &ReservedTurn) -> io::Result<()> {
        let request = serde_json::to_vec(&turn.request).map_err(|_| invalid())?;
        if self.reservations >= 1024
            || turn.parent != self.parent
            || TurnRequest::decode(&request).is_err()
            || turn.child
                != Hash::of(
                    &serde_json::to_vec(&(&turn.parent.0, &turn.request.turn_id))
                        .map_err(|_| invalid())?,
                )
        {
            return Err(invalid());
        }
        self.reservations += 1;
        publish(
            &self.directory,
            &Self::filename(&turn.request.turn_id, "reserved"),
            &Reservation {
                version: 1,
                parent: turn.parent.clone(),
                child: turn.child.clone(),
                request: turn.request.clone(),
                memory_bytes: turn.limits.memory_bytes,
                timeout_nanos: turn.limits.timeout.as_nanos(),
                model_requests: turn.limits.model_requests,
                output_tokens: turn.limits.output_tokens,
            },
        )
    }

    fn reservation(&self, turn: &str) -> io::Result<Reservation> {
        let record: Reservation =
            read_record(&self.directory.join(Self::filename(turn, "reserved")))?;
        if record.version != 1
            || record.parent != self.parent
            || record.request.turn_id != turn
            || TurnRequest::decode(&serde_json::to_vec(&record.request).map_err(|_| invalid())?)
                .is_err()
            || record.child
                != Hash::of(&serde_json::to_vec(&(&self.parent.0, turn)).map_err(|_| invalid())?)
        {
            return Err(invalid());
        }
        Ok(record)
    }

    fn destroyed(&self, turn: &str, child: &Hash) -> io::Result<DestroyedRecord> {
        let record: DestroyedRecord =
            read_record(&self.directory.join(Self::filename(turn, "destroyed")))?;
        if record.version != 1
            || record.parent != self.parent
            || &record.child != child
            || record.turn_id != turn
            || record.answer.len() > 8192
        {
            return Err(invalid());
        }
        Ok(record)
    }

    /// Only after the actual owner has confirmed destruction. The journal
    /// records that observation; it does not itself terminate a child VM.
    pub fn child_destroyed(
        &self,
        turn: &str,
        child: &Hash,
        succeeded: bool,
        answer: &str,
    ) -> io::Result<()> {
        let record = self.reservation(turn)?;
        if &record.child != child || answer.len() > 8192 {
            return Err(invalid());
        }
        publish(
            &self.directory,
            &Self::filename(turn, "destroyed"),
            &serde_json::json!({
                "version":1,"parent":self.parent,"child":child,"turnId":turn,"succeeded":succeeded,"answer":answer
            }),
        )
    }

    /// Acknowledgement from the same live guest parent, distinct from child
    /// completion. A missing acknowledgement never authorizes replay.
    pub fn parent_committed(&self, turn: &str, child: &Hash) -> io::Result<()> {
        let record = self.reservation(turn)?;
        if &record.child != child {
            return Err(invalid());
        }
        self.destroyed(turn, child)?;
        publish(
            &self.directory,
            &Self::filename(turn, "committed"),
            &serde_json::json!({
                "version":1,"parent":self.parent,"child":child,"turnId":turn
            }),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn historical_owner_is_immutable_scoped_and_not_execution_authority() {
        let root = tempfile::tempdir().unwrap();
        let id = Hash::of(b"historical");
        let journal = ParentJournal::create(root.path(), id.clone()).unwrap();
        assert!(historical_owner(root.path(), &id, "tenant").is_err());
        assert!(journal.bind_owner("bad\nprincipal").is_err());
        journal.bind_owner("tenant").unwrap();
        assert!(journal.bind_owner("other").is_err());
        assert!(historical_owner(root.path(), &id, "tenant").unwrap());
        assert!(!historical_owner(root.path(), &id, "other").unwrap());
        drop(journal);
        assert!(historical_owner(root.path(), &id, "tenant").unwrap());
        assert!(ParentJournal::create(root.path(), id.clone()).is_err());
        fs::write(parent_directory(root.path(), &id).join("owner.json"), b"{}").unwrap();
        assert!(historical_owner(root.path(), &id, "tenant").is_err());
        assert!(ParentJournal::create(root.path(), id).is_err());
    }
    use crate::parent_lease::{ParentLease, TurnLimits};
    use std::time::Duration;
    fn turn() -> ReservedTurn {
        let mut lease = ParentLease::new(
            Hash::of(b"incarnation"),
            Duration::from_secs(60),
            TurnLimits {
                memory_bytes: 4096,
                timeout: Duration::from_secs(1),
                model_requests: 0,
                output_tokens: 0,
            },
            1,
            0,
            0,
        )
        .unwrap();
        lease
            .reserve(br#"{"apiVersion":"celln.parent-turn/v1","turnId":"one","task":"hello"}"#)
            .unwrap()
    }
    #[test]
    fn durable_claim_blocks_recreation_and_duplicate_execution() {
        let root = tempfile::tempdir().unwrap();
        let turn = turn();
        let mut journal = ParentJournal::create(root.path(), turn.parent.clone()).unwrap();
        journal.reserve(&turn).unwrap();
        assert!(journal.reserve(&turn).is_err());
        assert_eq!(journal.reservation("one").unwrap().child, turn.child);
        drop(journal);
        assert!(ParentJournal::create(root.path(), turn.parent).is_err());
    }
    #[test]
    fn teardown_and_parent_commit_are_distinct_immutable_stages() {
        let root = tempfile::tempdir().unwrap();
        let turn = turn();
        let mut journal = ParentJournal::create(root.path(), turn.parent.clone()).unwrap();
        journal.reserve(&turn).unwrap();
        assert!(journal.parent_committed("one", &turn.child).is_err());
        assert!(journal
            .child_destroyed("one", &Hash::of(b"wrong"), true, "answer")
            .is_err());
        journal
            .child_destroyed("one", &turn.child, true, "answer")
            .unwrap();
        assert!(journal
            .child_destroyed("one", &turn.child, true, "changed")
            .is_err());
        journal.parent_committed("one", &turn.child).unwrap();
        assert!(journal.parent_committed("one", &turn.child).is_err());
    }

    #[test]
    fn inspection_survives_owner_loss_but_cannot_reopen_incarnation() {
        let root = tempfile::tempdir().unwrap();
        let turn = turn();
        let mut journal = ParentJournal::create(root.path(), turn.parent.clone()).unwrap();
        assert!(inspect_turn(root.path(), &turn.parent, "one").is_err());
        journal.reserve(&turn).unwrap();
        assert!(matches!(
            inspect_turn(root.path(), &turn.parent, "one").unwrap(),
            TurnStatus::Reserved(_)
        ));
        journal
            .child_destroyed("one", &turn.child, false, "tool failed")
            .unwrap();
        assert!(
            matches!(inspect_turn(root.path(), &turn.parent, "one").unwrap(), TurnStatus::ChildDestroyed(record) if !record.succeeded && record.answer == "tool failed")
        );
        journal.parent_committed("one", &turn.child).unwrap();
        drop(journal);
        assert!(
            matches!(inspect_turn(root.path(), &turn.parent, "one").unwrap(), TurnStatus::ParentCommitted(record) if !record.succeeded)
        );
        assert!(ParentJournal::create(root.path(), turn.parent).is_err());
    }

    #[test]
    fn corrupt_teardown_never_authorizes_commit_or_status() {
        for corruption in [
            ("version", serde_json::json!(2)),
            ("child", serde_json::json!(Hash::of(b"other"))),
            ("parent", serde_json::json!(Hash::of(b"other"))),
            ("turnId", serde_json::json!("other")),
            ("succeeded", serde_json::json!("true")),
            ("answer", serde_json::json!("x".repeat(8193))),
            ("extra", serde_json::json!(true)),
        ] {
            let root = tempfile::tempdir().unwrap();
            let turn = turn();
            let mut journal = ParentJournal::create(root.path(), turn.parent.clone()).unwrap();
            journal.reserve(&turn).unwrap();
            journal
                .child_destroyed("one", &turn.child, true, "answer")
                .unwrap();
            let path = journal
                .directory
                .join(ParentJournal::filename("one", "destroyed"));
            let mut value: serde_json::Value = read_record(&path).unwrap();
            value[corruption.0] = corruption.1;
            fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
            assert!(
                journal.parent_committed("one", &turn.child).is_err(),
                "{}",
                corruption.0
            );
            assert!(
                inspect_turn(root.path(), &turn.parent, "one").is_err(),
                "{}",
                corruption.0
            );
        }
    }

    #[test]
    fn changed_reservation_child_and_orphan_commit_fail_closed() {
        let root = tempfile::tempdir().unwrap();
        let turn = turn();
        let mut journal = ParentJournal::create(root.path(), turn.parent.clone()).unwrap();
        journal.reserve(&turn).unwrap();
        let path = journal
            .directory
            .join(ParentJournal::filename("one", "reserved"));
        let original = fs::read(&path).unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&original).unwrap();
        let wrong = Hash::of(b"other");
        value["child"] = serde_json::json!(wrong);
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(journal
            .child_destroyed("one", &wrong, true, "answer")
            .is_err());
        assert!(inspect_turn(root.path(), &turn.parent, "one").is_err());
        fs::write(path, original).unwrap();
        publish(&journal.directory, &ParentJournal::filename("one", "committed"),
            &serde_json::json!({"version":1,"parent":turn.parent,"child":turn.child,"turnId":"one"})).unwrap();
        assert!(inspect_turn(root.path(), &turn.parent, "one").is_err());
    }
}
