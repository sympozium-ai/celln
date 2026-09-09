//! Explicit operator authority for a parent incarnation. Artifact signatures
//! alone do not grant mailbox access or permission to spawn children.
//!
//! The serving layer supplies an independently authenticated principal and
//! hashes of its complete admitted parent/worker configurations (including
//! closure, borrowed tools, inputs, model policy and execution restrictions).
//! This does not perform artifact admission, tenant authentication, node RAM
//! reservation or VM launch. Those checks remain mandatory before launch.
use crate::parent_lease::{ParentLease, TurnLimits};
use celln_manifest::Hash;
use serde::{Deserialize, Serialize};
use std::{
    io::{self, Read, Write},
    path::Path,
    time::Duration,
};

pub const VERSION: &str = "celln.parent-permit/v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Binding {
    pub principal: String,
    /// Unique run/process incarnation, never a reusable agent name.
    pub incarnation: Hash,
    pub parent_configuration: Hash,
    pub worker_configuration: Hash,
    pub parent_memory_bytes: u64,
    pub child_memory_bytes: u64,
    pub lifetime_ms: u64,
    pub turn_timeout_ms: u64,
    pub max_turns: usize,
    pub turn_model_requests: u64,
    pub turn_output_tokens: u64,
    pub total_model_requests: u64,
    pub total_output_tokens: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Permit {
    pub api_version: String,
    pub binding: Binding,
    pub boot_id: String,
    pub issued_at_boottime_ms: u64,
    pub expires_at_boottime_ms: u64,
}

/// Host observation, not accepted from a client. Exposed for local operator
/// issuance; validation always reads the current clock itself.
pub struct HostClock {
    pub boot_id: String,
    pub boottime_ms: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RunIssuance {
    api_version: String,
    scope: String,
    run_uid: String,
    intent: Hash,
    admission_window_ms: u64,
    permit: Permit,
}

/// Scope is a stable operator-selected cluster/issuer identity; run_uid is an
/// immutable run UID, never a reusable run name. Intent does not influence this
/// identity: changing intent must fail against the original issuance record.
pub fn run_incarnation(scope: &str, run_uid: &str) -> io::Result<Hash> {
    if scope.is_empty()
        || scope.len() > 512
        || run_uid.is_empty()
        || run_uid.len() > 128
        || scope.chars().chain(run_uid.chars()).any(char::is_control)
    {
        return Err(invalid(
            "bounded operator scope and immutable run UID required",
        ));
    }
    let raw = serde_json::to_vec(&("celln.parent-run-incarnation/v1", scope, run_uid))
        .map_err(|_| invalid("run incarnation serialization failed"))?;
    Ok(Hash::of(&raw))
}

/// Pin one exact permit to an independently authorized run intent. Recovery
/// returns the original unexpired permit; it never renews timestamps, replaces
/// an incarnation or dispatches work. All issuers for a scope must share this
/// pre-existing operator-owned parent-issuance directory, including on restart.
pub fn issue_for_run(
    root: &Path,
    scope: &str,
    run_uid: &str,
    intent: &Hash,
    binding: Binding,
    window: Duration,
) -> io::Result<Permit> {
    let permit = issue_for_run_at(
        root,
        scope,
        run_uid,
        intent,
        binding,
        window,
        &host_clock()?,
    )?;
    permit.validate(&permit.binding, &permit.binding.principal, &host_clock()?)?;
    Ok(permit)
}

fn issue_for_run_at(
    root: &Path,
    scope: &str,
    run_uid: &str,
    intent: &Hash,
    binding: Binding,
    window: Duration,
    now: &HostClock,
) -> io::Result<Permit> {
    let incarnation = run_incarnation(scope, run_uid)?;
    if !root.is_absolute() || !valid_hash(intent) || binding.incarnation != incarnation {
        return Err(invalid("run issuance root, intent or incarnation mismatch"));
    }
    let permit = Permit::issue_at(binding.clone(), window, now)?;
    let candidate = RunIssuance {
        api_version: "celln.parent-run-issuance/v1".into(),
        scope: scope.into(),
        run_uid: run_uid.into(),
        intent: intent.clone(),
        admission_window_ms: window.as_millis() as u64,
        permit,
    };
    let directory = root.join("parent-issuance");
    let dir = std::fs::File::open(&directory)?;
    if !dir.metadata()?.is_dir() {
        return Err(invalid("operator issuance directory required"));
    }
    let path = directory.join(format!("{}.json", &incarnation.0[7..]));
    let bytes =
        serde_json::to_vec(&candidate).map_err(|_| invalid("run issuance serialization failed"))?;
    if bytes.len() > 16384 {
        return Err(invalid("run issuance exceeds bound"));
    }
    let mut temporary = tempfile::NamedTempFile::new_in(&directory)?;
    temporary.write_all(&bytes)?;
    temporary.as_file().sync_all()?;
    if let Err(error) = temporary.persist_noclobber(&path) {
        if error.error.kind() != io::ErrorKind::AlreadyExists {
            return Err(error.error);
        }
    }
    // Read the winner, not this attempt's freshly constructed timestamps.
    let mut saved = Vec::new();
    std::fs::File::open(&path)?
        .take(16385)
        .read_to_end(&mut saved)?;
    if saved.len() > 16384 {
        return Err(invalid("stored run issuance exceeds bound"));
    }
    let saved: RunIssuance = serde_json::from_slice(&saved)
        .map_err(|_| invalid("stored run issuance corrupt; preserve original record"))?;
    if saved.api_version != candidate.api_version
        || saved.scope != scope
        || saved.run_uid != run_uid
        || saved.intent != *intent
        || saved.admission_window_ms != candidate.admission_window_ms
        || saved.permit.binding != binding
        || saved
            .permit
            .expires_at_boottime_ms
            .checked_sub(saved.permit.issued_at_boottime_ms)
            != Some(saved.admission_window_ms)
    {
        return Err(invalid("run issuance differs; preserve original permit"));
    }
    dir.sync_all()?;
    saved.permit.validate(&binding, &binding.principal, now)?;
    Ok(saved.permit)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn valid_hash(hash: &Hash) -> bool {
    hash.0.strip_prefix("blake3:").is_some_and(|s| {
        s.len() == 64
            && s.bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    })
}

fn valid_boot(id: &str) -> bool {
    id.len() == 36
        && id.bytes().enumerate().all(|(i, c)| {
            if [8, 13, 18, 23].contains(&i) {
                c == b'-'
            } else {
                c.is_ascii_digit() || (b'a'..=b'f').contains(&c)
            }
        })
}

pub fn host_clock() -> io::Result<HostClock> {
    #[cfg(all(target_os = "linux", feature = "kvm"))]
    {
        let mut boot_id = String::new();
        std::fs::File::open("/proc/sys/kernel/random/boot_id")?
            .take(128)
            .read_to_string(&mut boot_id)?;
        let boot_id = boot_id.trim().to_owned();
        let mut time = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: time is initialized writable timespec storage.
        if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut time) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if !valid_boot(&boot_id) || time.tv_sec < 0 || !(0..1_000_000_000).contains(&time.tv_nsec) {
            return Err(invalid("invalid host boot clock"));
        }
        let boottime_ms = (time.tv_sec as u64)
            .checked_mul(1000)
            .and_then(|t| t.checked_add(time.tv_nsec as u64 / 1_000_000))
            .ok_or_else(|| invalid("host boot clock overflow"))?;
        Ok(HostClock {
            boot_id,
            boottime_ms,
        })
    }
    #[cfg(not(all(target_os = "linux", feature = "kvm")))]
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "parent permits require Linux KVM host clock support",
    ))
}

impl Binding {
    fn lease(&self) -> io::Result<ParentLease> {
        if self.principal.is_empty()
            || self.principal.len() > 512
            || self.principal.chars().any(char::is_control)
            || !valid_hash(&self.incarnation)
            || !valid_hash(&self.parent_configuration)
            || !valid_hash(&self.worker_configuration)
            || self.parent_memory_bytes == 0
            || self
                .parent_memory_bytes
                .checked_add(self.child_memory_bytes)
                .is_none()
            || !(1..=86_400_000).contains(&self.lifetime_ms)
            || self.turn_timeout_ms > self.lifetime_ms
            || self.total_model_requests > 6144
            || self.total_output_tokens > 3_145_728
        {
            return Err(invalid("invalid parent permit limits or identity"));
        }
        ParentLease::new(
            self.incarnation.clone(),
            Duration::from_millis(self.lifetime_ms),
            TurnLimits {
                memory_bytes: self.child_memory_bytes,
                timeout: Duration::from_millis(self.turn_timeout_ms),
                model_requests: self.turn_model_requests,
                output_tokens: self.turn_output_tokens,
            },
            self.max_turns,
            self.total_model_requests,
            self.total_output_tokens,
        )
        .map_err(|_| invalid("invalid parent permit lease"))
    }
}

impl Permit {
    /// Construct a bounded permit from explicitly trusted local operator input.
    /// Time is observed on this host, never supplied by a remote caller. This
    /// neither publishes authority nor claims/launches an incarnation. The
    /// caller must separately authorize the complete binding and durably pin
    /// issuance to its run; calling again is not a renewal or replay mechanism.
    pub fn issue(binding: Binding, admission_window: Duration) -> io::Result<Self> {
        Self::issue_at(binding, admission_window, &host_clock()?)
    }

    /// Durably publish this exact local operator permit without replacement.
    /// The protected root and trusted-parent-permits directory must exist.
    /// A publication failure never authorizes issuing a replacement identity;
    /// callers must recover their pinned permit. This does not claim or launch.
    pub fn publish(&self, root: &Path) -> io::Result<Hash> {
        let hash = self.publish_at(root, &host_clock()?)?;
        // Publication can consume the remaining admission window. Preserve the
        // record, but do not return a now-expired permit as usable authority.
        self.validate(&self.binding, &self.binding.principal, &host_clock()?)?;
        Ok(hash)
    }

    fn publish_at(&self, root: &Path, now: &HostClock) -> io::Result<Hash> {
        self.validate(&self.binding, &self.binding.principal, now)?;
        if !root.is_absolute() {
            return Err(invalid("absolute operator root required"));
        }
        let directory = root.join("trusted-parent-permits");
        let dir = std::fs::File::open(&directory)?;
        if !dir.metadata()?.is_dir() {
            return Err(invalid("operator permit directory required"));
        }
        let bytes = serde_json::to_vec(self).map_err(|_| invalid("permit serialization failed"))?;
        if bytes.len() > 16384 {
            return Err(invalid("permit exceeds bound"));
        }
        let hash = Hash::of(&bytes);
        let path = directory.join(format!("{}.json", &hash.0[7..]));
        let mut temporary = tempfile::NamedTempFile::new_in(&directory)?;
        temporary.write_all(&bytes)?;
        temporary.as_file().sync_all()?;
        if let Err(error) = temporary.persist_noclobber(&path) {
            if error.error.kind() != io::ErrorKind::AlreadyExists {
                return Err(error.error);
            }
            let mut existing = Vec::new();
            std::fs::File::open(&path)?
                .take(16385)
                .read_to_end(&mut existing)?;
            if existing != bytes {
                return Err(invalid(
                    "existing permit differs; preserve uncertain publication",
                ));
            }
        }
        dir.sync_all()?;
        Ok(hash)
    }

    fn issue_at(binding: Binding, admission_window: Duration, now: &HostClock) -> io::Result<Self> {
        let millis = admission_window.as_millis();
        if !(1..=300_000).contains(&millis) || admission_window.subsec_nanos() % 1_000_000 != 0 {
            return Err(invalid(
                "permit admission window must be 1..=300000 whole milliseconds",
            ));
        }
        let expires = now
            .boottime_ms
            .checked_add(millis as u64)
            .ok_or_else(|| invalid("permit admission clock overflow"))?;
        let permit = Self {
            api_version: VERSION.into(),
            binding,
            boot_id: now.boot_id.clone(),
            issued_at_boottime_ms: now.boottime_ms,
            expires_at_boottime_ms: expires,
        };
        permit.validate(&permit.binding, &permit.binding.principal, now)?;
        Ok(permit)
    }

    fn validate(
        &self,
        expected: &Binding,
        principal: &str,
        now: &HostClock,
    ) -> io::Result<ParentLease> {
        if self.api_version != VERSION
            || self.binding != *expected
            || principal != self.binding.principal
            || !valid_boot(&self.boot_id)
            || self.boot_id != now.boot_id
            || !matches!(
                self.expires_at_boottime_ms
                    .checked_sub(self.issued_at_boottime_ms),
                Some(1..=300_000)
            )
            || now.boottime_ms < self.issued_at_boottime_ms
            || now.boottime_ms >= self.expires_at_boottime_ms
        {
            return Err(invalid(
                "parent permit binding or admission expiry mismatch",
            ));
        }
        self.binding.lease()
    }
}

/// Read ONLY from the operator-owned permit directory, never an upload store.
/// Recheck immediately before claiming the incarnation and starting its owner.
/// A successful check is NOT a replay claim: the serving owner must create the
/// durable ParentJournal tombstone before any VM launch. Admission expiry is
/// distinct from the lifetime enforced by ParentOwner and ParentLease.
pub fn authorize(
    root: &Path,
    permit_hash: &Hash,
    expected: &Binding,
    principal: &str,
) -> io::Result<ParentLease> {
    if !valid_hash(permit_hash) {
        return Err(invalid("invalid parent permit hash"));
    }
    let mut bytes = Vec::new();
    std::fs::File::open(
        root.join("trusted-parent-permits")
            .join(format!("{}.json", &permit_hash.0[7..])),
    )?
    .take(16385)
    .read_to_end(&mut bytes)?;
    if bytes.len() > 16384 || Hash::of(&bytes) != *permit_hash {
        return Err(invalid("parent permit revision mismatch"));
    }
    let permit: Permit =
        serde_json::from_slice(&bytes).map_err(|_| invalid("invalid parent permit"))?;
    permit.validate(expected, principal, &host_clock()?)
}

/// Final admission and durable one-use claim, before starting either VM.
/// Never remove the tombstone after a failed launch: retrying the same
/// incarnation could duplicate uncertain work or falsely restore context.
pub fn claim(
    root: &Path,
    permit_hash: &Hash,
    expected: &Binding,
    principal: &str,
) -> io::Result<(ParentLease, crate::parent_journal::ParentJournal)> {
    let lease = authorize(root, permit_hash, expected, principal)?;
    let journal = crate::parent_journal::ParentJournal::create(
        &root.join("parent-journal"),
        expected.incarnation.clone(),
    )?;
    journal.bind_owner(principal)?;
    journal.bind_process()?;
    Ok((lease, journal))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn permit() -> Permit {
        Permit {
            api_version: VERSION.into(),
            boot_id: "01234567-89ab-cdef-0123-456789abcdef".into(),
            issued_at_boottime_ms: 100,
            expires_at_boottime_ms: 200,
            binding: Binding {
                principal: "namespace/run-uid".into(),
                incarnation: Hash::of(b"incarnation"),
                parent_configuration: Hash::of(b"parent"),
                worker_configuration: Hash::of(b"worker"),
                parent_memory_bytes: 4096,
                child_memory_bytes: 4096,
                lifetime_ms: 60000,
                turn_timeout_ms: 1000,
                max_turns: 2,
                turn_model_requests: 0,
                turn_output_tokens: 0,
                total_model_requests: 0,
                total_output_tokens: 0,
            },
        }
    }
    #[test]
    fn binds_every_configuration_field_and_authenticated_principal() {
        let permit = permit();
        let now = HostClock {
            boot_id: permit.boot_id.clone(),
            boottime_ms: 150,
        };
        assert!(permit
            .validate(&permit.binding, &permit.binding.principal, &now)
            .is_ok());
        assert!(permit
            .validate(&permit.binding, "another-tenant", &now)
            .is_err());
        let fields = serde_json::to_value(&permit.binding).unwrap();
        for (key, value) in fields.as_object().unwrap() {
            let mut changed = fields.clone();
            changed[key] = if value.is_string() {
                serde_json::json!(format!("{}-changed", value.as_str().unwrap()))
            } else {
                serde_json::json!(value.as_u64().unwrap() + 1)
            };
            let binding = serde_json::from_value(changed).unwrap();
            assert!(
                permit
                    .validate(&binding, &permit.binding.principal, &now)
                    .is_err(),
                "{key}"
            );
        }
    }
    #[test]
    fn admission_is_exclusive_and_boot_specific() {
        let mut permit = permit();
        for (time, valid) in [(99, false), (100, true), (199, true), (200, false)] {
            let now = HostClock {
                boot_id: permit.boot_id.clone(),
                boottime_ms: time,
            };
            assert_eq!(
                permit
                    .validate(&permit.binding, &permit.binding.principal, &now)
                    .is_ok(),
                valid
            );
        }
        let now = HostClock {
            boot_id: permit.boot_id.clone(),
            boottime_ms: 150,
        };
        permit.boot_id = "11234567-89ab-cdef-0123-456789abcdef".into();
        assert!(permit
            .validate(&permit.binding, &permit.binding.principal, &now)
            .is_err());
    }
    #[test]
    fn invalid_limits_cannot_become_a_lease() {
        let fields = serde_json::to_value(permit().binding).unwrap();
        for (field, value) in [
            ("parentMemoryBytes", 0),
            ("childMemoryBytes", 0),
            ("parentMemoryBytes", u64::MAX),
            ("lifetimeMs", 0),
            ("lifetimeMs", 86_400_001),
            ("turnTimeoutMs", 0),
            ("turnTimeoutMs", 60_001),
            ("maxTurns", 1025),
            ("turnModelRequests", 1),
            ("turnOutputTokens", 1),
            ("totalModelRequests", 6145),
            ("totalOutputTokens", 3_145_729),
        ] {
            let mut changed = fields.clone();
            changed[field] = serde_json::json!(value);
            let binding: Binding = serde_json::from_value(changed).unwrap();
            assert!(binding.lease().is_err(), "{field}={value}");
        }
    }

    #[test]
    #[cfg(all(target_os = "linux", feature = "kvm"))]
    fn operator_file_is_required_hash_bound_and_revocable() {
        let root = tempfile::tempdir().unwrap();
        let mut permit = permit();
        let now = host_clock().unwrap();
        permit.boot_id = now.boot_id;
        permit.issued_at_boottime_ms = now.boottime_ms;
        permit.expires_at_boottime_ms = now.boottime_ms + 60_000;
        let bytes = serde_json::to_vec(&permit).unwrap();
        let hash = Hash::of(&bytes);
        let check = || {
            authorize(
                root.path(),
                &hash,
                &permit.binding,
                &permit.binding.principal,
            )
        };
        assert!(check().is_err());
        let directory = root.path().join("trusted-parent-permits");
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join(format!("{}.json", &hash.0[7..]));
        std::fs::write(&path, &bytes).unwrap();
        assert!(check().is_ok());
        assert!(authorize(root.path(), &hash, &permit.binding, "impostor").is_err());
        // Authentication failure must not consume the legitimate incarnation.
        assert!(claim(root.path(), &hash, &permit.binding, "impostor").is_err());
        let claimed = claim(
            root.path(),
            &hash,
            &permit.binding,
            &permit.binding.principal,
        )
        .unwrap();
        drop(claimed);
        // A freshly issued permit cannot renew an already consumed incarnation.
        let reissued = Permit::issue(permit.binding.clone(), Duration::from_secs(30)).unwrap();
        let reissued_bytes = serde_json::to_vec(&reissued).unwrap();
        let reissued_hash = Hash::of(&reissued_bytes);
        assert_ne!(reissued_hash, hash);
        std::fs::write(
            directory.join(format!("{}.json", &reissued_hash.0[7..])),
            reissued_bytes,
        )
        .unwrap();
        assert!(authorize(
            root.path(),
            &reissued_hash,
            &permit.binding,
            &permit.binding.principal
        )
        .is_ok());
        assert!(claim(
            root.path(),
            &reissued_hash,
            &permit.binding,
            &permit.binding.principal
        )
        .is_err());
        assert!(claim(
            root.path(),
            &hash,
            &permit.binding,
            &permit.binding.principal
        )
        .is_err());
        std::fs::write(&path, b"{}").unwrap();
        assert!(check().is_err());
        std::fs::remove_file(&path).unwrap();
        assert!(check().is_err());
        assert!(authorize(
            root.path(),
            &Hash("../../outside".into()),
            &permit.binding,
            &permit.binding.principal
        )
        .is_err());
    }

    #[test]
    fn issuance_preserves_binding_and_refuses_invalid_clock_window_or_limits() {
        let binding = permit().binding;
        let now = HostClock {
            boot_id: permit().boot_id,
            boottime_ms: 400,
        };
        for window in [1, 120_000, 300_000] {
            let issued =
                Permit::issue_at(binding.clone(), Duration::from_millis(window), &now).unwrap();
            assert_eq!(issued.binding, binding);
            assert_eq!(issued.issued_at_boottime_ms, 400);
            assert_eq!(issued.expires_at_boottime_ms, 400 + window);
            assert_eq!(issued.boot_id, now.boot_id);
            assert!(issued.validate(&binding, &binding.principal, &now).is_ok());
        }
        for window in [
            Duration::ZERO,
            Duration::from_millis(300_001),
            Duration::from_nanos(1_000_001),
        ] {
            assert!(Permit::issue_at(binding.clone(), window, &now).is_err());
        }
        for bad in [
            HostClock {
                boot_id: "client-clock".into(),
                boottime_ms: 400,
            },
            HostClock {
                boot_id: now.boot_id.clone(),
                boottime_ms: u64::MAX,
            },
        ] {
            assert!(Permit::issue_at(binding.clone(), Duration::from_secs(1), &bad).is_err());
        }
        let mut invalid = binding;
        invalid.max_turns = 1025;
        assert!(Permit::issue_at(invalid, Duration::from_secs(1), &now).is_err());
    }

    #[test]
    fn publication_is_bounded_nonreplacing_and_recovers_only_identical_bytes() {
        let root = tempfile::tempdir().unwrap();
        let permit = permit();
        let now = HostClock {
            boot_id: permit.boot_id.clone(),
            boottime_ms: 150,
        };
        assert!(permit.publish_at(root.path(), &now).is_err());
        assert!(permit.publish_at(Path::new("."), &now).is_err());
        let directory = root.path().join("trusted-parent-permits");
        assert!(!directory.exists());
        std::fs::create_dir(&directory).unwrap();
        let hash = permit.publish_at(root.path(), &now).unwrap();
        assert_eq!(permit.publish_at(root.path(), &now).unwrap(), hash);
        let path = directory.join(format!("{}.json", &hash.0[7..]));
        let raw = std::fs::read(&path).unwrap();
        assert_eq!(Hash::of(&raw), hash);
        assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 1);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        std::fs::write(&path, b"partial").unwrap();
        assert!(permit.publish_at(root.path(), &now).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"partial");
        assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 1);
        let expired = HostClock {
            boot_id: now.boot_id,
            boottime_ms: 200,
        };
        assert!(permit.publish_at(root.path(), &expired).is_err());
    }

    #[test]
    fn concurrent_identical_publication_preserves_one_record() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("trusted-parent-permits");
        std::fs::create_dir(&directory).unwrap();
        let permit = permit();
        let now = HostClock {
            boot_id: permit.boot_id.clone(),
            boottime_ms: 150,
        };
        std::thread::scope(|scope| {
            let first = scope.spawn(|| permit.publish_at(root.path(), &now).unwrap());
            let second = scope.spawn(|| permit.publish_at(root.path(), &now).unwrap());
            assert_eq!(first.join().unwrap(), second.join().unwrap());
        });
        assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 1);
    }

    #[test]
    fn run_issuance_recovers_original_permit_without_renewal_or_changed_intent() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("parent-issuance");
        let mut binding = permit().binding;
        binding.incarnation = run_incarnation("cluster-a", "run-uid").unwrap();
        let intent = Hash::of(b"complete authorized intent");
        let now = HostClock {
            boot_id: permit().boot_id,
            boottime_ms: 100,
        };
        let issue = |at: &HostClock, intent: &Hash, binding: Binding| {
            issue_for_run_at(
                root.path(),
                "cluster-a",
                "run-uid",
                intent,
                binding,
                Duration::from_millis(100),
                at,
            )
        };
        assert!(issue(&now, &intent, binding.clone()).is_err());
        assert!(!directory.exists());
        std::fs::create_dir(&directory).unwrap();
        let first = issue(&now, &intent, binding.clone()).unwrap();
        let later = HostClock {
            boot_id: now.boot_id.clone(),
            boottime_ms: 150,
        };
        let recovered = issue(&later, &intent, binding.clone()).unwrap();
        assert_eq!(
            serde_json::to_vec(&first).unwrap(),
            serde_json::to_vec(&recovered).unwrap()
        );
        assert!(issue(&later, &Hash::of(b"changed intent"), binding.clone()).is_err());
        let mut changed = binding.clone();
        changed.max_turns -= 1;
        assert!(issue(&later, &intent, changed).is_err());
        assert!(issue_for_run_at(
            root.path(),
            "cluster-a",
            "run-uid",
            &intent,
            binding.clone(),
            Duration::from_millis(200),
            &later
        )
        .is_err());
        let expired = HostClock {
            boot_id: now.boot_id,
            boottime_ms: 200,
        };
        assert!(issue(&expired, &intent, binding.clone()).is_err());
        assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 1);
        let path = directory.join(format!("{}.json", &binding.incarnation.0[7..]));
        let record: RunIssuance = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(record.permit.expires_at_boottime_ms, 200);
        std::fs::write(&path, b"partial").unwrap();
        assert!(issue(&later, &intent, binding).is_err());
        assert_eq!(std::fs::read(path).unwrap(), b"partial");
        assert_ne!(
            run_incarnation("cluster-a", "run-uid").unwrap(),
            run_incarnation("cluster-b", "run-uid").unwrap()
        );
        assert_ne!(
            run_incarnation("cluster-a", "run-uid").unwrap(),
            run_incarnation("cluster-a", "new-uid").unwrap()
        );
    }

    #[test]
    fn competing_run_issuers_cannot_replace_the_winning_intent() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("parent-issuance")).unwrap();
        let mut binding = permit().binding;
        binding.incarnation = run_incarnation("cluster", "uid").unwrap();
        let now = HostClock {
            boot_id: permit().boot_id,
            boottime_ms: 100,
        };
        let results = std::thread::scope(|scope| {
            let first = scope.spawn(|| {
                issue_for_run_at(
                    root.path(),
                    "cluster",
                    "uid",
                    &Hash::of(b"first intent"),
                    binding.clone(),
                    Duration::from_secs(1),
                    &now,
                )
            });
            let second = scope.spawn(|| {
                issue_for_run_at(
                    root.path(),
                    "cluster",
                    "uid",
                    &Hash::of(b"second intent"),
                    binding.clone(),
                    Duration::from_secs(1),
                    &now,
                )
            });
            [first.join().unwrap(), second.join().unwrap()]
        });
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            std::fs::read_dir(root.path().join("parent-issuance"))
                .unwrap()
                .count(),
            1
        );
    }

    #[test]
    #[cfg(all(target_os = "linux", feature = "kvm"))]
    fn local_issuance_uses_current_host_clock() {
        let before = host_clock().unwrap();
        let issued = Permit::issue(permit().binding, Duration::from_secs(60)).unwrap();
        let after = host_clock().unwrap();
        assert_eq!(issued.boot_id, before.boot_id);
        assert_eq!(issued.boot_id, after.boot_id);
        assert!(
            issued.issued_at_boottime_ms >= before.boottime_ms
                && issued.issued_at_boottime_ms <= after.boottime_ms
        );
        assert_eq!(
            issued.expires_at_boottime_ms - issued.issued_at_boottime_ms,
            60_000
        );
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("trusted-parent-permits")).unwrap();
        let hash = issued.publish(root.path()).unwrap();
        assert!(authorize(
            root.path(),
            &hash,
            &issued.binding,
            &issued.binding.principal
        )
        .is_ok());
        assert_eq!(issued.publish(root.path()).unwrap(), hash);
    }
    #[test]
    fn model_free_parent_permit_produces_bounded_lease() {
        let permit = permit();
        let mut lease = permit.binding.lease().unwrap();
        for id in ["one", "two"] {
            let bytes = serde_json::to_vec(&serde_json::json!({"apiVersion":crate::parent_protocol::VERSION,"turnId":id,"task":"tool input"})).unwrap();
            let turn = lease.reserve(&bytes).unwrap();
            assert_eq!(turn.limits.model_requests, 0);
            lease.confirm_child_destroyed(&turn.child).unwrap();
        }
        assert!(lease
            .reserve(br#"{"apiVersion":"celln.parent-turn/v1","turnId":"three","task":"input"}"#)
            .is_err());
    }
}
