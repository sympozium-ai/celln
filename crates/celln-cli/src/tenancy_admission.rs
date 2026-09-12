//! Durable, credential-free admission ownership. This is not artifact admission:
//! callers still must independently check publisher/closure/ABI/host constraints
//! before dispatch, and must never execute a Recovery disposition.
use crate::{
    tenancy_contract::{canonical, digest},
    tenancy_credentials::{Context, Refusal, Verifier},
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
};

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Credential(Refusal),
    RequestConflict,
    Unavailable,
    Capacity,
    BudgetExhausted,
    Busy,
    Fenced,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Record {
    version: u8,
    identity: Identity,
    scope: String,
    run_scope: String,
    active_turn: Option<String>,
    accepted_turns: u64,
    decision_digest: String,
    authority_digest: String,
    fenced: bool,
    run_binding: String,
    request_digest: String,
    owner: String,
    outcome: Option<Outcome>,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Identity {
    pub cluster_id: String,
    pub namespace: String,
    pub namespace_uid: String,
    pub run_uid: String,
    pub parent_incarnation: Option<String>,
    pub turn_id: Option<String>,
}

impl Identity {
    fn from_receiver(receiver: &Context) -> Self {
        Self {
            cluster_id: receiver.cluster_id.clone(),
            namespace: receiver.namespace.clone(),
            namespace_uid: receiver.namespace_uid.clone(),
            run_uid: receiver.run_uid.clone(),
            parent_incarnation: receiver.parent["incarnation"].as_str().map(str::to_owned),
            turn_id: receiver.parent["turnId"].as_str().map(str::to_owned),
        }
    }
}

impl Record {
    pub fn identity(&self) -> &Identity {
        &self.identity
    }
    pub fn owner(&self) -> &str {
        &self.owner
    }
    pub fn fenced(&self) -> bool {
        self.fenced
    }
    pub fn outcome(&self) -> Option<&Outcome> {
        self.outcome.as_ref()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum Outcome {
    Receipt {
        digest: String,
    },
    Refused,
    /// An authenticated cleanup won the admission lock while this exact,
    /// independently enrolled operation had no admission record. Unlike
    /// `Refused`, this proves that `claim` never returned a `Fresh` handle.
    NeverStarted,
}

/// Non-cloneable fresh ownership handle. Only publication after file+directory
/// fsync constructs one. A durable row, token JTI or Recovery is not this handle.
pub struct Fresh {
    record: Record,
}
impl Fresh {
    pub fn record(&self) -> &Record {
        &self.record
    }
}
pub enum Claim {
    Fresh(Fresh),
    Recovery(Record),
}

pub struct Journal {
    directory: File,
    owner: String,
    capacity: usize,
}

fn authority_digest(raw: &[u8]) -> Result<String, Error> {
    let mut value: serde_json::Value =
        serde_json::from_slice(raw).map_err(|_| Error::Unavailable)?;
    let object = value.as_object_mut().ok_or(Error::Unavailable)?;
    object.remove("operation");
    object.remove("windows");
    Ok(digest(
        &canonical(&serde_json::to_vec(&value).map_err(|_| Error::Unavailable)?)
            .map_err(|_| Error::Unavailable)?,
    ))
}

fn root_scope(receiver: &Context) -> Result<String, Error> {
    Ok(digest(
        &serde_json::to_vec(&(
            "celln.admission-scope/v1",
            &receiver.cluster_id,
            &receiver.namespace_uid,
            &receiver.run_uid,
        ))
        .map_err(|_| Error::Unavailable)?,
    ))
}

fn scope(receiver: &Context) -> Result<(String, String), Error> {
    let root = root_scope(receiver)?;
    let scope = match receiver.parent["turnId"].as_str() {
        Some(turn) if !turn.is_empty() => digest(
            &serde_json::to_vec(&("celln.admission-turn/v1", &root, turn))
                .map_err(|_| Error::Unavailable)?,
        ),
        Some(_) => return Err(Error::Credential("AUTH_PARENT_TURN_MISMATCH")),
        None => root.clone(),
    };
    Ok((root, scope))
}

fn run_binding(decision: &serde_json::Value) -> Result<String, Error> {
    Ok(digest(
        &serde_json::to_vec(&serde_json::json!({
            "run":decision["run"], "runtime":decision["runtime"], "agent":decision["agent"],
            "route":decision["route"], "incarnation":decision["parent"]["incarnation"],
            "budgetId":decision["budget"]["budgetId"], "runCap":decision["budget"]["runCap"],
            "maxTurns":decision["budget"]["maxTurns"],
            "parentDeadlineUnix":decision["budget"]["parentDeadlineUnix"]
        }))
        .map_err(|_| Error::Unavailable)?,
    ))
}

fn blake(value: &str) -> bool {
    value.strip_prefix("blake3:").is_some_and(|s| {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

fn sha(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|s| {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

fn private_regular(file: &File) -> Result<(), Error> {
    let m = file.metadata().map_err(|_| Error::Unavailable)?;
    if !m.is_file() || m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o077 != 0 {
        return Err(Error::Unavailable);
    }
    Ok(())
}

struct Lock {
    file: File,
    pid: u32,
}
impl Drop for Lock {
    fn drop(&mut self) {
        if std::process::id() == self.pid {
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

impl Journal {
    pub fn owner(&self) -> &str {
        &self.owner
    }
    /// Each owner instance gets a fresh, non-restorable identity. Reopening this
    /// directory does not resurrect a former owner's native/model contexts.
    pub fn open(root: &Path, capacity: usize) -> Result<Self, Error> {
        if capacity == 0 || capacity > 1_000_000 {
            return Err(Error::Capacity);
        }
        match fs::DirBuilder::new().mode(0o700).create(root) {
            Ok(()) => {
                File::open(root.parent().ok_or(Error::Unavailable)?)
                    .and_then(|f| f.sync_all())
                    .map_err(|_| Error::Unavailable)?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(Error::Unavailable),
        }
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(root)
            .map_err(|_| Error::Unavailable)?;
        let metadata = directory.metadata().map_err(|_| Error::Unavailable)?;
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
            return Err(Error::Unavailable);
        }
        directory.sync_all().map_err(|_| Error::Unavailable)?;
        let mut epoch = [0; 32];
        File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut epoch))
            .map_err(|_| Error::Unavailable)?;
        Ok(Self {
            directory,
            owner: digest(&epoch),
            capacity,
        })
    }

    // Pin the opened directory inode, rather than following a caller-replaced
    // pathname after construction. Names below this fd are generated digests.
    fn root(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.directory.as_raw_fd()))
    }
    fn path(&self, scope: &str) -> PathBuf {
        self.root().join(format!("{}.json", &scope[7..]))
    }
    fn lock(&self) -> Result<Lock, Error> {
        let directory = self.directory.metadata().map_err(|_| Error::Unavailable)?;
        if directory.uid() != unsafe { libc::geteuid() } || directory.mode() & 0o077 != 0 {
            return Err(Error::Unavailable);
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(self.root().join("admission.lock"))
            .map_err(|_| Error::Unavailable)?;
        private_regular(&file)?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(Error::Unavailable);
        }
        Ok(Lock {
            file,
            pid: std::process::id(),
        })
    }
    fn load(&self, scope: &str) -> Result<Option<Record>, Error> {
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(self.path(scope))
        {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(Error::Unavailable),
        };
        private_regular(&file)?;
        let mut raw = Vec::new();
        file.take(8193)
            .read_to_end(&mut raw)
            .map_err(|_| Error::Unavailable)?;
        if raw.len() > 8192 {
            return Err(Error::Unavailable);
        }
        let record: Record = serde_json::from_slice(&raw).map_err(|_| Error::Unavailable)?;
        if record.version != 1
            || record.scope != scope
            || [
                &record.scope,
                &record.run_scope,
                &record.decision_digest,
                &record.authority_digest,
                &record.request_digest,
                &record.run_binding,
                &record.owner,
            ]
            .iter()
            .any(|v| !sha(v))
            || record.active_turn.as_ref().is_some_and(|v| !sha(v))
            || matches!(&record.outcome, Some(Outcome::Receipt { digest }) if !blake(digest))
            || (record.outcome == Some(Outcome::NeverStarted)
                && (!record.fenced || record.active_turn.is_some() || record.accepted_turns != 0))
            || (record.outcome != Some(Outcome::NeverStarted)
                && record.scope != record.run_scope
                && (record.active_turn.is_some() || record.accepted_turns != 0))
            || (record.outcome != Some(Outcome::NeverStarted)
                && record.scope == record.run_scope
                && !(1..=1024).contains(&record.accepted_turns))
        {
            return Err(Error::Unavailable);
        }
        Ok(Some(record))
    }

    /// Receiver context MUST come from authenticated routing/prepared owner
    /// state, never solely from the submitted decision. Invalid authority cannot
    /// probe duplicate state: all credential/payload checks precede lookup.
    pub fn claim(
        &self,
        verifier: &Verifier,
        token: &str,
        decision: &[u8],
        request: &[u8],
        receiver: &Context,
    ) -> Result<Claim, Error> {
        if receiver.expected_audience != "celln-execution"
            || !matches!(
                receiver.expected_operation.as_str(),
                "execution.start" | "execution.turn"
            )
        {
            return Err(Error::Credential("AUTH_OPERATION_MISMATCH"));
        }
        let replay = verifier
            .verify(token, decision, receiver)
            .map_err(Error::Credential)?
            .is_some();
        let request_digest = digest(
            &canonical(request).map_err(|_| Error::Credential("AUTH_REQUEST_BINDING_MISMATCH"))?,
        );
        if request_digest != receiver.request_digest {
            return Err(Error::Credential("AUTH_REQUEST_BINDING_MISMATCH"));
        }
        let decision_digest =
            digest(&canonical(decision).map_err(|_| Error::Credential("AUTH_CRED_MALFORMED"))?);
        // JTI and decision digest are deliberately NOT the lookup key: changing
        // a token/window/ceiling cannot purchase a fresh operation identity.
        let (root_scope, scope) = scope(receiver)?;
        let d: serde_json::Value = serde_json::from_slice(decision)
            .map_err(|_| Error::Credential("AUTH_CRED_MALFORMED"))?;
        if (receiver.expected_operation == "execution.turn") != (scope != root_scope) {
            return Err(Error::Credential("AUTH_PARENT_TURN_MISMATCH"));
        }
        let candidate = Record {
            version: 1,
            identity: Identity::from_receiver(receiver),
            scope: scope.clone(),
            run_scope: root_scope.clone(),
            active_turn: None,
            accepted_turns: u64::from(scope == root_scope),
            decision_digest,
            authority_digest: authority_digest(decision)?,
            fenced: false,
            run_binding: run_binding(&d)?,
            request_digest,
            owner: self.owner.clone(),
            outcome: None,
        };
        let _lock = self.lock()?;
        let mut parent = if receiver.expected_operation == "execution.turn" {
            let original = self
                .load(&root_scope)?
                .ok_or(Error::Credential("AUTH_CONTEXT_LOST"))?;
            let mut parent_identity = candidate.identity.clone();
            parent_identity.turn_id = None;
            if original.run_binding != candidate.run_binding || original.identity != parent_identity
            {
                return Err(Error::RequestConflict);
            }
            if original.fenced {
                return Err(Error::Fenced);
            }
            if original.owner != self.owner || original.outcome == Some(Outcome::Refused) {
                return Err(Error::Credential("AUTH_CONTEXT_LOST"));
            }
            Some(original)
        } else {
            None
        };
        if let Some(existing) = self.load(&scope)? {
            if existing.identity != candidate.identity
                || existing.decision_digest != candidate.decision_digest
                || existing.request_digest != candidate.request_digest
            {
                return Err(Error::RequestConflict);
            }
            if existing.outcome == Some(Outcome::NeverStarted) {
                return Err(Error::Fenced);
            }
            return Ok(Claim::Recovery(existing));
        }
        if replay {
            return Err(Error::Credential("AUTH_CONTEXT_LOST"));
        }
        if let Some(parent) = parent.as_mut() {
            if parent.outcome.is_none() {
                return Err(Error::Busy);
            }
            if let Some(active) = &parent.active_turn {
                let prior = self
                    .load(active)?
                    .ok_or(Error::Credential("AUTH_CONTEXT_LOST"))?;
                if prior.run_scope != root_scope || prior.owner != self.owner {
                    return Err(Error::RequestConflict);
                }
                if prior.outcome.is_none() {
                    return Err(Error::Busy);
                }
            }
            parent.accepted_turns = parent
                .accepted_turns
                .checked_add(1)
                .filter(|n| *n <= d["budget"]["maxTurns"].as_u64().unwrap_or(0))
                .ok_or(Error::BudgetExhausted)?;
            parent.active_turn = Some(scope.clone());
        }
        let mut count = 0;
        for entry in fs::read_dir(self.root()).map_err(|_| Error::Unavailable)? {
            let entry = entry.map_err(|_| Error::Unavailable)?;
            if entry.path().extension().is_some_and(|s| s == "json") {
                count += 1;
                if count >= self.capacity {
                    return Err(Error::Capacity);
                }
            }
        }
        // Fence the parent before publishing a child. A crash between these
        // writes is ContextLost/uncertain, never permission to repeat dispatch.
        if let Some(parent) = parent {
            self.publish(&parent, false)?;
        }
        self.publish(&candidate, true)?;
        Ok(Claim::Fresh(Fresh { record: candidate }))
    }

    /// Historical reads and cleanup require separately scoped, fresh credentials.
    /// They retain the original authority tuple and do not re-admit execution or
    /// require a live provider Secret/policy. A fence is not teardown confirmation.
    pub fn access(
        &self,
        verifier: &Verifier,
        token: &str,
        decision: &[u8],
        receiver: &Context,
        enrolled_decision: &[u8],
        request: &[u8],
        enrolled_owner: &str,
    ) -> Result<Record, Error> {
        if receiver.expected_audience != "celln-execution"
            || !matches!(
                receiver.expected_operation.as_str(),
                "execution.read" | "execution.cleanup"
            )
        {
            return Err(Error::Credential("AUTH_OPERATION_MISMATCH"));
        }
        verifier
            .verify(token, decision, receiver)
            .map_err(Error::Credential)?;
        // Validate the operator-independent durable enrollment before looking
        // up admission state. The cleanup credential and receiver context are
        // separately verified above; neither one can invent enrolled material.
        if !sha(enrolled_owner) {
            return Err(Error::RequestConflict);
        }
        let request_digest = digest(
            &canonical(request).map_err(|_| Error::Credential("AUTH_REQUEST_BINDING_MISMATCH"))?,
        );
        if request_digest != receiver.request_digest {
            return Err(Error::Credential("AUTH_REQUEST_BINDING_MISMATCH"));
        }
        let enrolled_canonical =
            canonical(enrolled_decision).map_err(|_| Error::Credential("AUTH_CRED_MALFORMED"))?;
        let enrolled: serde_json::Value = serde_json::from_slice(&enrolled_canonical)
            .map_err(|_| Error::Credential("AUTH_CRED_MALFORMED"))?;
        let (root, scope) = scope(receiver)?;
        let enrolled_operation = enrolled["operation"]
            .as_str()
            .ok_or(Error::Credential("AUTH_OPERATION_MISMATCH"))?;
        if !matches!(enrolled_operation, "execution.start" | "execution.turn")
            || (enrolled_operation == "execution.turn") != (scope != root)
            || enrolled["requestDigest"].as_str() != Some(receiver.request_digest.as_str())
        {
            return Err(Error::Credential("AUTH_OPERATION_MISMATCH"));
        }
        let authority = authority_digest(decision)?;
        if authority_digest(&enrolled_canonical)? != authority {
            return Err(Error::RequestConflict);
        }
        let candidate = Record {
            version: 1,
            identity: Identity::from_receiver(receiver),
            scope: scope.clone(),
            run_scope: root.clone(),
            active_turn: None,
            accepted_turns: 0,
            decision_digest: digest(&enrolled_canonical),
            authority_digest: authority.clone(),
            fenced: true,
            run_binding: run_binding(&enrolled)?,
            request_digest,
            owner: enrolled_owner.to_owned(),
            outcome: Some(Outcome::NeverStarted),
        };
        let _lock = self.lock()?;
        let mut record = match self.load(&scope)? {
            Some(record) => record,
            None if receiver.expected_operation == "execution.read" => {
                return Err(Error::Credential("AUTH_CONTEXT_LOST"))
            }
            None => {
                // A parent pointing at a missing child is an interrupted
                // parent/child publication. Do not turn partial durable state
                // into a claim that no admission handle escaped.
                if scope != root
                    && self
                        .load(&root)?
                        .is_some_and(|parent| parent.active_turn.as_deref() == Some(&scope))
                {
                    return Err(Error::Credential("AUTH_CONTEXT_LOST"));
                }
                // Execution-record capacity must not make finalization
                // impossible after admission itself was refused for capacity.
                // The receiver has already supplied an exact durable prepared
                // enrollment; this record only subtracts future authority.
                self.publish(&candidate, true)?;
                return Ok(candidate);
            }
        };
        if record.authority_digest != authority
            || record.identity != Identity::from_receiver(receiver)
            || record.scope != candidate.scope
            || record.run_scope != candidate.run_scope
            || record.decision_digest != candidate.decision_digest
            || record.run_binding != candidate.run_binding
            || record.request_digest != candidate.request_digest
            || record.owner != candidate.owner
        {
            return Err(Error::RequestConflict);
        }
        if receiver.expected_operation == "execution.cleanup" && !record.fenced {
            record.fenced = true;
            self.publish(&record, false)?;
        }
        Ok(record)
    }

    fn publish(&self, record: &Record, fresh: bool) -> Result<(), Error> {
        let mut staged =
            tempfile::NamedTempFile::new_in(self.root()).map_err(|_| Error::Unavailable)?;
        serde_json::to_writer(&mut staged, record).map_err(|_| Error::Unavailable)?;
        staged
            .flush()
            .and_then(|_| staged.as_file().sync_all())
            .map_err(|_| Error::Unavailable)?;
        if fresh {
            staged
                .persist_noclobber(self.path(&record.scope))
                .map_err(|_| Error::Unavailable)?;
        } else {
            staged
                .persist(self.path(&record.scope))
                .map_err(|_| Error::Unavailable)?;
        }
        self.directory.sync_all().map_err(|_| Error::Unavailable)
    }

    /// Record only a receipt hash or refusal, never output, prompts, credentials
    /// or copied request payloads. Repeated identical completion is idempotent.
    pub fn finish(&self, fresh: &Fresh, outcome: Outcome) -> Result<(), Error> {
        if fresh.record.owner != self.owner {
            return Err(Error::RequestConflict);
        }
        if let Outcome::Receipt { digest } = &outcome {
            if !blake(digest) {
                return Err(Error::RequestConflict);
            }
        }
        let _lock = self.lock()?;
        let mut current = self.load(&fresh.record.scope)?.ok_or(Error::Unavailable)?;
        let old_outcome = current.outcome.take();
        let fenced = current.fenced;
        current.fenced = false;
        let active = current.active_turn.take();
        let accepted_turns = current.accepted_turns;
        if accepted_turns < fresh.record.accepted_turns {
            return Err(Error::RequestConflict);
        }
        current.accepted_turns = fresh.record.accepted_turns;
        if current != fresh.record {
            return Err(Error::RequestConflict);
        }
        if let Some(old) = old_outcome {
            return if old == outcome {
                Ok(())
            } else {
                Err(Error::RequestConflict)
            };
        }
        current.active_turn = active;
        current.fenced = fenced;
        current.accepted_turns = accepted_turns;
        current.outcome = Some(outcome);
        self.publish(&current, false)
    }
}

#[cfg(test)]
#[path = "tenancy_admission_tests.rs"]
mod tests;
