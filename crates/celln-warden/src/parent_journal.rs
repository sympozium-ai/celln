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

/// Host-process identity, not a checkpoint or authority to restart. Kept in a
/// separate record so journals from older owners remain readable but cannot
/// acquire a teardown guarantee retroactively.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProcessRecord {
    version: u8,
    parent: Hash,
    boot: String,
    pid_namespace: u64,
    uid: u32,
    pid: u32,
    start_ticks: u64,
}

#[cfg(target_os = "linux")]
fn process_context() -> io::Result<(String, u64)> {
    use std::os::unix::fs::MetadataExt;
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let boot = boot.trim().to_owned();
    if boot.len() != 36 || !boot.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-') {
        return Err(invalid());
    }
    Ok((boot, fs::metadata("/proc/self/ns/pid")?.ino()))
}

#[cfg(target_os = "linux")]
fn process_start(pid: u32) -> io::Result<u64> {
    let mut stat = String::new();
    fs::File::open(format!("/proc/{pid}/stat"))?
        .take(16385)
        .read_to_string(&mut stat)?;
    if stat.len() > 16384 {
        return Err(invalid());
    }
    // comm (field 2) may contain whitespace and parentheses. Field 22 is
    // starttime; parse only after the final closing parenthesis.
    stat.rsplit_once(')')
        .and_then(|(_, fields)| fields.split_whitespace().nth(19))
        .and_then(|ticks| ticks.parse::<u64>().ok())
        .filter(|ticks| *ticks != 0)
        .ok_or_else(invalid)
}

/// Confirm the original *whole host process* is gone on the same Linux boot
/// and PID namespace. Native parent/child KVM fds live in that process, never
/// a detached VMM process. Missing registry entries alone prove nothing.
/// Different boots/namespaces, legacy journals and unreadable procfs refuse.
/// This must not be reused for an out-of-process VMM backend.
pub fn historical_teardown(root: &Path, parent: &Hash, principal: &str) -> io::Result<bool> {
    if !historical_owner(root, parent, principal)? {
        return Ok(false);
    }
    #[cfg(target_os = "linux")]
    {
        let process: ProcessRecord =
            read_record(&parent_directory(root, parent).join("process.json"))?;
        let (boot, namespace) = process_context()?;
        use std::os::unix::fs::MetadataExt;
        if process.version != 1
            || process.parent != *parent
            || process.pid == 0
            || process.start_ticks == 0
            || process.boot != boot
            || process.pid_namespace != namespace
            || process.uid != fs::metadata("/proc/self")?.uid()
        {
            return Err(invalid());
        }
        match process_start(process.pid) {
            Ok(start) => Ok(start != process.start_ticks), // PID reused: old group has exited.
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                // procfs may hide another process. ESRCH from the kernel's
                // signal-zero lookup independently confirms absence; EPERM
                // and a successful lookup are never teardown evidence.
                #[cfg(feature = "kvm")]
                {
                    let pid = i32::try_from(process.pid).map_err(|_| invalid())?;
                    let result = unsafe { libc::kill(pid, 0) };
                    Ok(result == -1
                        && io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH))
                }
                #[cfg(not(feature = "kvm"))]
                Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "process exit confirmation requires native backend",
                ))
            }
            Err(error) => Err(error),
        }
    }
    #[cfg(not(target_os = "linux"))]
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "host process teardown requires Linux procfs",
    ))
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
    /// Called before native VM launch, while running in the process which owns
    /// all native parent/child KVM file descriptors. Never backfill old journals.
    pub fn bind_process(&self) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            let (boot, pid_namespace) = process_context()?;
            let pid = std::process::id();
            use std::os::unix::fs::MetadataExt;
            publish(
                &self.directory,
                "process.json",
                &ProcessRecord {
                    version: 1,
                    parent: self.parent.clone(),
                    boot,
                    pid_namespace,
                    uid: fs::metadata("/proc/self")?.uid(),
                    pid,
                    start_ticks: process_start(pid)?,
                },
            )
        }
        #[cfg(not(target_os = "linux"))]
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "host process identity requires Linux procfs",
        ))
    }
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
    #[cfg(target_os = "linux")]
    fn process_identity_helper() {
        let Some(root) = std::env::var_os("CELLN_PROCESS_IDENTITY_TEST_ROOT") else {
            return;
        };
        let journal = ParentJournal::create(Path::new(&root), Hash::of(b"process-test")).unwrap();
        journal.bind_owner("tenant").unwrap();
        journal.bind_process().unwrap();
        // Parent kills and joins this real process after reading its record.
        std::thread::sleep(std::time::Duration::from_secs(30));
    }

    #[test]
    #[cfg(all(target_os = "linux", feature = "kvm"))]
    fn historical_teardown_requires_real_process_exit_and_preserves_tombstone() {
        let root = tempfile::tempdir().unwrap();
        let id = Hash::of(b"process-test");
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "parent_journal::tests::process_identity_helper"])
            .env("CELLN_PROCESS_IDENTITY_TEST_ROOT", root.path())
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let path = parent_directory(root.path(), &id).join("process.json");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !path.exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let live = historical_teardown(root.path(), &id, "tenant");
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(!live.unwrap());
        assert!(!historical_teardown(root.path(), &id, "other").unwrap());
        assert!(historical_teardown(root.path(), &id, "tenant").unwrap());
        assert!(ParentJournal::create(root.path(), id.clone()).is_err());
        let mut record: ProcessRecord = read_record(&path).unwrap();
        record.pid_namespace += 1;
        fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
        assert!(historical_teardown(root.path(), &id, "tenant").is_err());
        fs::remove_file(&path).unwrap();
        assert!(historical_teardown(root.path(), &id, "tenant").is_err());
    }
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
