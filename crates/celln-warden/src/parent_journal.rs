//! Durable parent incarnation tombstone and immutable turn stages. This is
//! audit/replay prevention, NOT a guest checkpoint. Creation refuses an existing
//! incarnation; after owner loss callers must report context loss, not resume.
use crate::{
    parent_lease::ReservedTurn,
    parent_protocol::{TurnRequest, MAX_ANSWER_BYTES},
};
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

/// One journal record. The widest are a reservation, which holds the encoded
/// turn request, and a destroyed record, which holds an answer whose JSON
/// escaping is at most sixfold.
const MAX_RECORD_BYTES: usize = 65536;
const _: () = assert!(
    MAX_RECORD_BYTES >= crate::parent_protocol::MAX_REQUEST_BYTES + 2048
        && MAX_RECORD_BYTES >= 6 * MAX_ANSWER_BYTES + 2048
);

fn read_record<T: serde::de::DeserializeOwned>(path: &Path) -> io::Result<T> {
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(MAX_RECORD_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_RECORD_BYTES {
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
    open_historical(root, parent)?.turn_status(turn)
}

/// Read-only view of an existing incarnation. Never published through and never
/// returned to callers, so it cannot become a second writer for the tombstone.
fn open_historical(root: &Path, parent: &Hash) -> io::Result<ParentJournal> {
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
    Ok(journal)
}

/// Operator-facing turn observation: identifiers, stage, outcome and limits.
/// Deliberately has no field that could carry task, message or answer text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TurnSummary {
    pub turn_id: String,
    /// `reserved` | `child-destroyed` | `parent-committed`, as [`TurnStatus`].
    pub stage: &'static str,
    pub child: Hash,
    /// Known only once the owner recorded the child's destruction.
    pub succeeded: Option<bool>,
    pub timeout_nanos: u128,
    /// Reservation file mtime, Unix milliseconds. Advisory ordering only.
    pub reserved_ms: u64,
}

/// Durable observations of one incarnation. Like [`inspect_turn`], this proves
/// nothing about a live owner and authorizes no replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParentSummary {
    pub parent: Hash,
    /// Journal directory mtime, Unix milliseconds.
    pub updated_ms: u64,
    /// Newest first, at most the requested bound.
    pub turns: Vec<TurnSummary>,
    /// Reservation files present, including ones omitted or skipped above.
    pub turns_total: usize,
}

fn modified_ms(metadata: &fs::Metadata) -> u64 {
    metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

/// Summarize one incarnation without reading it for execution. Turns whose
/// records are unreadable, inconsistent or mid-publication are skipped rather
/// than failing the listing; a missing or foreign `parent.json` is an error.
pub fn summarize_parent(root: &Path, parent: &Hash, max_turns: usize) -> io::Result<ParentSummary> {
    let journal = open_historical(root, parent)?;
    let updated_ms = modified_ms(&fs::metadata(&journal.directory)?);
    let mut reserved: Vec<(u64, PathBuf)> = fs::read_dir(&journal.directory)?
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.ends_with(".reserved.json"))
        })
        .filter_map(|entry| Some((modified_ms(&entry.metadata().ok()?), entry.path())))
        .collect();
    let turns_total = reserved.len();
    reserved.sort_by(|a, b| b.cmp(a));
    let turns = reserved
        .into_iter()
        .take(max_turns)
        .filter_map(|(reserved_ms, path)| {
            // The file name is a hash of the turn id; recover the id from the
            // record, then let the ordinary validated path re-derive the name.
            let record: Reservation = read_record(&path).ok()?;
            let (turn_id, timeout_nanos) = (record.request.turn_id, record.timeout_nanos);
            if path.file_name()?.to_str()? != ParentJournal::filename(&turn_id, "reserved") {
                return None; // Filed under another turn's name: never listed twice.
            }
            let (stage, child, succeeded) = match journal.turn_status(&turn_id).ok()? {
                TurnStatus::Reserved(reserved) => ("reserved", reserved.child, None),
                TurnStatus::ChildDestroyed(destroyed) => (
                    "child-destroyed",
                    destroyed.child,
                    Some(destroyed.succeeded),
                ),
                TurnStatus::ParentCommitted(destroyed) => (
                    "parent-committed",
                    destroyed.child,
                    Some(destroyed.succeeded),
                ),
            };
            Some(TurnSummary {
                turn_id,
                stage,
                child,
                succeeded,
                timeout_nanos,
                reserved_ms,
            })
        })
        .collect();
    Ok(ParentSummary {
        parent: parent.clone(),
        updated_ms,
        turns,
        turns_total,
    })
}

/// Newest `max_parents` incarnations by journal directory mtime. Read-only and
/// lock-free: a listing concurrent with an owner may lag its publications.
/// Unreadable, malformed or foreign directories are skipped, not reported.
pub fn list_parents(root: &Path, max_parents: usize, max_turns: usize) -> Vec<ParentSummary> {
    let Ok(entries) = fs::read_dir(root) else {
        return Vec::new();
    };
    let mut directories: Vec<(u64, PathBuf)> = entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let metadata = entry.metadata().ok()?;
            metadata
                .is_dir()
                .then(|| (modified_ms(&metadata), entry.path()))
        })
        .collect();
    directories.sort_by(|a, b| b.cmp(a));
    directories
        .into_iter()
        .filter_map(|(_, directory)| {
            // The directory name is a hash of the identity; the identity itself
            // is only in the record, and must hash back to this directory.
            let identity: ParentRecord = read_record(&directory.join("parent.json")).ok()?;
            (parent_directory(root, &identity.parent) == directory)
                .then(|| summarize_parent(root, &identity.parent, max_turns).ok())
                .flatten()
        })
        .take(max_parents)
        .collect()
}

/// Atomically foreclose an uncreated incarnation. The caller must independently
/// authenticate a terminally refused admission and fence further starts first.
/// Directory creation races with ParentJournal::create, which MUST precede any
/// parent factory or VM launch. Existing/partial owner journals stay uncertain.
/// This proves no parent launch, not teardown of an existing VM.
pub fn fence_uncreated(root: &Path, parent: &Hash, principal: &str) -> io::Result<bool> {
    if !valid_principal(principal) {
        return Err(invalid());
    }
    fs::create_dir_all(root)?;
    let directory = parent_directory(root, parent);
    let proof =
        serde_json::json!({"version":1,"parent":parent,"principal":principal,"neverCreated":true});
    match fs::create_dir(&directory) {
        Ok(()) => {
            publish(&directory, "never-created.json", &proof)?;
            fs::File::open(root)?.sync_all()?;
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            if !fs::symlink_metadata(&directory)?.file_type().is_dir() {
                return Ok(false);
            }
            let mut options = fs::OpenOptions::new();
            options.read(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
            }
            let file = match options.open(directory.join("never-created.json")) {
                Ok(file) if file.metadata()?.is_file() => file,
                _ => return Ok(false),
            };
            let mut bytes = Vec::new();
            file.take(16385).read_to_end(&mut bytes)?;
            if bytes.len() > 16384 {
                return Ok(false);
            }
            let existing: serde_json::Value =
                serde_json::from_slice(&bytes).map_err(|_| invalid())?;
            Ok(existing == proof)
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
    if bytes.len() > MAX_RECORD_BYTES {
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

    fn turn_status(&self, turn: &str) -> io::Result<TurnStatus> {
        let reservation = self.reservation(turn)?;
        let committed = match read_record::<CommittedRecord>(
            &self.directory.join(Self::filename(turn, "committed")),
        ) {
            Ok(record) => {
                if record.version != 1
                    || record.parent != self.parent
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
        match self.destroyed(turn, &reservation.child) {
            Ok(record) if committed => Ok(TurnStatus::ParentCommitted(record)),
            Ok(record) => Ok(TurnStatus::ChildDestroyed(record)),
            Err(error) if error.kind() == io::ErrorKind::NotFound && !committed => {
                Ok(TurnStatus::Reserved(reservation))
            }
            Err(error) => Err(error),
        }
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
            || record.answer.len() > MAX_ANSWER_BYTES
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
        if &record.child != child || answer.len() > MAX_ANSWER_BYTES {
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
    fn uncreated_parent_fence_is_bound_and_excludes_native_creation() {
        let root = tempfile::tempdir().unwrap();
        let parent = Hash::of(b"never-created");
        assert!(fence_uncreated(root.path(), &parent, "review-owner").unwrap());
        assert!(fence_uncreated(root.path(), &parent, "review-owner").unwrap());
        assert!(!fence_uncreated(root.path(), &parent, "other-owner").unwrap());
        assert!(ParentJournal::create(root.path(), parent.clone()).is_err());
        let existing = Hash::of(b"existing-owner");
        ParentJournal::create(root.path(), existing.clone()).unwrap();
        assert!(!fence_uncreated(root.path(), &existing, "review-owner").unwrap());
        assert!(!parent_directory(root.path(), &existing)
            .join("never-created.json")
            .exists());
    }

    #[test]
    fn uncreated_fence_and_parent_factory_claim_cannot_both_win() {
        for iteration in 0..8 {
            let root = tempfile::tempdir().unwrap();
            let parent = Hash::of(format!("race-{iteration}").as_bytes());
            let gate = std::sync::Arc::new(std::sync::Barrier::new(2));
            let path = root.path().to_owned();
            let other = parent.clone();
            let ready = gate.clone();
            let creating = std::thread::spawn(move || {
                ready.wait();
                ParentJournal::create(&path, other).is_ok()
            });
            gate.wait();
            let fenced = fence_uncreated(root.path(), &parent, "review-owner").unwrap();
            assert_ne!(fenced, creating.join().unwrap());
        }
    }
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

    fn reserved_turn(parent: &Hash, turn_id: &str, task: &str) -> ReservedTurn {
        ParentLease::new(
            parent.clone(),
            Duration::from_secs(60),
            TurnLimits {
                memory_bytes: 4096,
                timeout: Duration::from_millis(1500),
                model_requests: 0,
                output_tokens: 0,
            },
            1,
            0,
            0,
        )
        .unwrap()
        .reserve(
            serde_json::json!({"apiVersion":"celln.parent-turn/v1","turnId":turn_id,"task":task})
                .to_string()
                .as_bytes(),
        )
        .unwrap()
    }

    #[test]
    fn listing_maps_every_stage_without_any_content_field() {
        let root = tempfile::tempdir().unwrap();
        let parent = Hash::of(b"listed");
        let mut journal = ParentJournal::create(root.path(), parent.clone()).unwrap();
        for id in ["pending", "failed", "done"] {
            let turn = reserved_turn(&parent, id, "PLANTED-TASK");
            journal.reserve(&turn).unwrap();
            if id != "pending" {
                journal
                    .child_destroyed(id, &turn.child, id == "done", "PLANTED-ANSWER")
                    .unwrap();
            }
            if id == "done" {
                journal.parent_committed(id, &turn.child).unwrap();
            }
        }
        let listed = list_parents(root.path(), 50, 32);
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].parent, parent);
        assert!(listed[0].updated_ms > 0);
        assert_eq!(listed[0].turns_total, 3);
        let stage = |id: &str| {
            let turn = listed[0].turns.iter().find(|t| t.turn_id == id).unwrap();
            assert_eq!(turn.timeout_nanos, 1_500_000_000);
            (turn.stage, turn.succeeded)
        };
        assert_eq!(stage("pending"), ("reserved", None));
        assert_eq!(stage("failed"), ("child-destroyed", Some(false)));
        assert_eq!(stage("done"), ("parent-committed", Some(true)));
        assert!(!format!("{listed:?}").contains("PLANTED"));
        // The bound keeps the total honest about what was omitted.
        let bounded = summarize_parent(root.path(), &parent, 2).unwrap();
        assert_eq!((bounded.turns.len(), bounded.turns_total), (2, 3));
    }

    #[test]
    fn listing_skips_malformed_parents_and_turns_and_bounds_parents() {
        let root = tempfile::tempdir().unwrap();
        assert!(list_parents(&root.path().join("absent"), 50, 32).is_empty());
        let parent = Hash::of(b"intact");
        let mut journal = ParentJournal::create(root.path(), parent.clone()).unwrap();
        let good = reserved_turn(&parent, "good", "task");
        journal.reserve(&good).unwrap();
        let bad = reserved_turn(&parent, "bad", "task");
        journal.reserve(&bad).unwrap();
        journal
            .child_destroyed("bad", &bad.child, true, "answer")
            .unwrap();
        fs::write(
            journal
                .directory
                .join(ParentJournal::filename("bad", "destroyed")),
            b"{not json",
        )
        .unwrap();
        // A reservation filed under another turn's name is not trusted either.
        fs::copy(
            journal
                .directory
                .join(ParentJournal::filename("good", "reserved")),
            journal
                .directory
                .join(ParentJournal::filename("moved", "reserved")),
        )
        .unwrap();
        // Garbage, an empty tombstone, and an identity filed in a foreign directory.
        fs::write(root.path().join("stray-file"), b"x").unwrap();
        fs::create_dir(root.path().join("empty")).unwrap();
        fs::create_dir(root.path().join("corrupt")).unwrap();
        fs::write(root.path().join("corrupt/parent.json"), b"{").unwrap();
        fs::create_dir(root.path().join("foreign")).unwrap();
        fs::copy(
            journal.directory.join("parent.json"),
            root.path().join("foreign/parent.json"),
        )
        .unwrap();
        let listed = list_parents(root.path(), 50, 32);
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].parent, parent);
        assert_eq!(listed[0].turns_total, 3);
        assert_eq!(listed[0].turns.len(), 1);
        assert_eq!(listed[0].turns[0].turn_id, "good");

        ParentJournal::create(root.path(), Hash::of(b"second")).unwrap();
        assert_eq!(list_parents(root.path(), 50, 32).len(), 2);
        assert_eq!(list_parents(root.path(), 1, 32).len(), 1);
        assert!(summarize_parent(root.path(), &Hash::of(b"unknown"), 32).is_err());
    }
}
