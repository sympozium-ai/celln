//! Durable, shared owner binding. Requires a POSIX filesystem with coherent
//! flock, atomic rename and fsync semantics across every router replica.
use anyhow::{bail, Context, Result};
use celln_manifest::Hash;
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Owner {
    version: u8,
    pub backend: String,
    body_hash: String,
}

pub(super) struct Ledger {
    dir: PathBuf,
    capacity: usize,
}
pub(super) enum Claim {
    New(Owner),
    Existing(Owner),
    Conflict,
    Full,
}

impl Ledger {
    pub fn open(dir: &Path, capacity: usize) -> Result<Self> {
        if capacity == 0 {
            bail!("ownership capacity must be positive");
        }
        std::fs::create_dir_all(dir).context("creating router ownership directory")?;
        // Persist newly created directory links as well as subsequent records.
        // A filesystem that refuses directory fsync is not this backend.
        let canonical = std::fs::canonicalize(dir)?;
        for ancestor in canonical.ancestors() {
            std::fs::File::open(ancestor)?
                .sync_all()
                .context("Unsupported: ownership filesystem must support directory fsync")?;
        }
        Ok(Self {
            dir: dir.into(),
            capacity,
        })
    }
    pub(super) fn path(&self, id: &str) -> PathBuf {
        self.dir.join(format!(
            "{}.json",
            Hash::of(id.as_bytes()).0.trim_start_matches("blake3:")
        ))
    }
    pub fn lookup(&self, id: &str) -> Result<Option<Owner>> {
        let file = match std::fs::File::open(self.path(id)) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let mut bytes = Vec::new();
        file.take(4097).read_to_end(&mut bytes)?;
        if bytes.len() > 4096 {
            bail!("invalid owner record");
        }
        let owner: Owner = serde_json::from_slice(&bytes).context("invalid owner record")?;
        if owner.version != 1 || owner.backend.len() > 1024 {
            bail!("unsupported owner record");
        }
        super::backend_to_addr(&owner.backend)?;
        Ok(Some(owner))
    }
    pub fn claim(
        &self,
        id: &str,
        body: &[u8],
        choose: impl FnOnce() -> Result<String>,
    ) -> Result<Claim> {
        let _lock = self.lock()?;
        let body_hash = Hash::of(body).0;
        if let Some(owner) = self.lookup(id)? {
            return Ok(if owner.body_hash == body_hash {
                Claim::Existing(owner)
            } else {
                Claim::Conflict
            });
        }
        let count = std::fs::read_dir(&self.dir)?
            .filter(|entry| {
                entry
                    .as_ref()
                    .map_or(true, |e| e.path().extension().is_some_and(|s| s == "json"))
            })
            .take(self.capacity)
            .count();
        if count >= self.capacity {
            return Ok(Claim::Full);
        }
        let owner = Owner {
            version: 1,
            backend: choose()?,
            body_hash,
        };
        if owner.backend.len() > 1024 {
            bail!("backend URL exceeds owner record bound");
        }
        let mut staged = tempfile::NamedTempFile::new_in(&self.dir)?;
        serde_json::to_writer(&mut staged, &owner)?;
        staged.flush()?;
        staged.as_file().sync_all()?;
        staged
            .persist_noclobber(self.path(id))
            .map_err(|e| e.error)?;
        std::fs::File::open(&self.dir)?.sync_all()?;
        // Publication is durable BEFORE any side-effecting POST. A crash in
        // the following gap is ambiguous and must not authorize replay.
        Ok(Claim::New(owner))
    }
    fn retired_path(&self, id: &str) -> PathBuf {
        self.path(id).with_extension("retired")
    }
    /// Deletes a record and its retirement marker; callers hold the lock.
    fn remove_locked(&self, record: &Path) -> Result<bool> {
        let removed = match std::fs::remove_file(record) {
            Ok(()) => true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(e) => return Err(e.into()),
        };
        match std::fs::remove_file(record.with_extension("retired")) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        std::fs::File::open(&self.dir)?.sync_all()?;
        Ok(removed)
    }
    /// Retires a record whose work is finished. Only callers whose protocol
    /// proves the id can never again authorize a side effect may use this;
    /// the execution, parent and provision ledgers never do. A record claimed at least
    /// `quarantine` ago is removed now; a younger one is only marked, and
    /// [`Ledger::sweep_retired`] removes it once it has aged. The quarantine
    /// outlives any credential that could have been presented for the id.
    pub fn retire(&self, id: &str, quarantine: std::time::Duration) -> Result<bool> {
        let _lock = self.lock()?;
        let record = self.path(id);
        match aged(&record, quarantine) {
            Ok(true) => self.remove_locked(&record),
            Ok(false) => {
                std::fs::File::create(self.retired_path(id))?.sync_all()?;
                std::fs::File::open(&self.dir)?.sync_all()?;
                Ok(false)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
        }
    }
    /// Removes every retired record that has completed its quarantine.
    pub fn sweep_retired(&self, quarantine: std::time::Duration) -> Result<usize> {
        let _lock = self.lock()?;
        let mut removed = 0;
        for entry in std::fs::read_dir(&self.dir)? {
            let marker = entry?.path();
            if marker.extension().map_or(true, |e| e != "retired") {
                continue;
            }
            let record = marker.with_extension("json");
            match aged(&record, quarantine) {
                Ok(false) => continue,
                Ok(true) => removed += usize::from(self.remove_locked(&record)?),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    self.remove_locked(&record)?;
                }
                Err(e) => return Err(e.into()),
            }
        }
        Ok(removed)
    }
    #[cfg(target_os = "linux")]
    fn lock(&self) -> Result<std::fs::File> {
        use std::os::fd::AsRawFd;
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(self.dir.join("ownership.lock"))?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            bail!("ownership ledger busy or locking unsupported");
        }
        Ok(file)
    }
    #[cfg(not(target_os = "linux"))]
    fn lock(&self) -> Result<std::fs::File> {
        bail!("Unsupported: router ownership requires Linux flock");
    }
}

fn aged(record: &Path, quarantine: std::time::Duration) -> std::io::Result<bool> {
    let claimed = std::fs::metadata(record)?.modified()?;
    // A clock that moved backwards leaves the record in quarantine.
    Ok(claimed.elapsed().is_ok_and(|elapsed| elapsed >= quarantine))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn replicas_restart_conflicts_and_capacity_are_durable() {
        let dir = tempfile::tempdir().unwrap();
        let a = Ledger::open(dir.path(), 1).unwrap();
        assert!(matches!(
            a.claim("id", b"original", || Ok("http://node-a:8787".into()))
                .unwrap(),
            Claim::New(_)
        ));
        let b = Ledger::open(dir.path(), 1).unwrap();
        assert_eq!(
            b.lookup("id").unwrap().unwrap().backend,
            "http://node-a:8787"
        );
        assert!(matches!(
            b.claim("id", b"original", || panic!("must not reselect owner"))
                .unwrap(),
            Claim::Existing(_)
        ));
        assert!(matches!(
            b.claim("id", b"changed", || panic!("must not contact backend"))
                .unwrap(),
            Claim::Conflict
        ));
        assert!(matches!(
            b.claim("new", b"new", || panic!("full ledger")).unwrap(),
            Claim::Full
        ));
        drop(a);
        drop(b);
        assert_eq!(
            Ledger::open(dir.path(), 1)
                .unwrap()
                .lookup("id")
                .unwrap()
                .unwrap()
                .backend,
            "http://node-a:8787"
        );
    }
    #[test]
    fn lock_contention_and_corruption_refuse() {
        let dir = tempfile::tempdir().unwrap();
        let a = Ledger::open(dir.path(), 10).unwrap();
        let guard = a.lock().unwrap();
        let b = Ledger::open(dir.path(), 10).unwrap();
        assert!(b.claim("x", b"x", || panic!("locked")).is_err());
        drop(guard);
        std::fs::write(a.path("x"), b"partial").unwrap();
        assert!(a
            .claim("x", b"x", || panic!("corrupt owner cannot be replaced"))
            .is_err());
    }
    #[test]
    fn quarantined_retirement_frees_capacity_and_never_touches_live_records() {
        use std::time::{Duration, SystemTime};
        let dir = tempfile::tempdir().unwrap();
        let ledger = Ledger::open(dir.path(), 2).unwrap();
        let node = || Ok("http://node-a:8787".to_string());
        assert!(matches!(
            ledger.claim("a", b"a", node).unwrap(),
            Claim::New(_)
        ));
        assert!(matches!(
            ledger.claim("b", b"b", node).unwrap(),
            Claim::New(_)
        ));
        assert!(matches!(
            ledger.claim("c", b"c", node).unwrap(),
            Claim::Full
        ));
        let quarantine = Duration::from_secs(600);
        let old = SystemTime::now() - Duration::from_secs(601);
        let age = |id: &str| {
            std::fs::File::options()
                .write(true)
                .open(ledger.path(id))
                .unwrap()
                .set_modified(old)
                .unwrap()
        };
        // An aged record retires immediately; an unknown id is a no-op.
        age("a");
        assert!(ledger.retire("a", quarantine).unwrap());
        assert!(!ledger.retire("a", quarantine).unwrap());
        assert!(ledger.lookup("a").unwrap().is_none());
        assert!(!ledger.retired_path("a").exists());
        assert!(matches!(
            ledger.claim("c", b"c", node).unwrap(),
            Claim::New(_)
        ));
        // A young record is only marked; it stays routable and counted.
        assert!(!ledger.retire("b", quarantine).unwrap());
        assert!(ledger.lookup("b").unwrap().is_some());
        assert!(ledger.retired_path("b").exists());
        assert_eq!(ledger.sweep_retired(quarantine).unwrap(), 0);
        assert!(matches!(
            ledger.claim("d", b"d", node).unwrap(),
            Claim::Full
        ));
        // Once aged past the quarantine the sweep removes record and marker.
        age("b");
        assert_eq!(ledger.sweep_retired(quarantine).unwrap(), 1);
        assert!(ledger.lookup("b").unwrap().is_none());
        assert!(!ledger.retired_path("b").exists());
        // Unretired records are never swept, however old.
        age("c");
        assert_eq!(ledger.sweep_retired(quarantine).unwrap(), 0);
        assert!(ledger.lookup("c").unwrap().is_some());
        // Markers are not records: they never consume capacity.
        assert!(matches!(
            ledger.claim("d", b"d", node).unwrap(),
            Claim::New(_)
        ));
    }
}
