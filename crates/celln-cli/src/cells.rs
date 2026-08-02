//! The cell registry behind `celln ps`.
//!
//! A KVM VM has no identity outside the process that made it — it is a file
//! descriptor, and there is no `/proc/kvm` to enumerate. `virsh list` will
//! never show a nous cell, because libvirt only knows about domains libvirt
//! created. So if a cell is to be visible after the fact, something has to
//! write it down. This does.
//!
//! One JSON file per cell under `$NOUS_ROOT/cells/`, which makes the whole
//! thing greppable, diffable, and trivially removable — and means a crashed
//! `nous` leaves a record behind rather than losing the run.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Records kept before the oldest are pruned. Enough to be useful, small
/// enough that `celln ps -a` stays instant and the directory stays readable.
const KEEP: usize = 500;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    pub id: String,
    pub name: String,
    pub spec: PathBuf,
    pub backend: String,
    pub pid: u32,
    /// Unix milliseconds. Cells can live for a fraction of a second, so
    /// second granularity would report every run as "0s".
    pub started_ms: u64,
    pub finished_ms: Option<u64>,
    /// `running` | `dissolved` | `refused` | `failed`
    pub status: String,
    pub tools: Vec<String>,
    pub error: Option<String>,
}

/// What `ps` should say, which is not always what is on disk: a record still
/// marked `running` whose process is gone means `nous` was killed mid-cell.
/// The cell died with it — a VM cannot outlive the fd that holds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Live {
    Running,
    Dissolved,
    Failed,
    /// The cell ran, and its in-cell policy deliberately refused an exec.
    Refused,
    /// Marked running, but the process that held it is gone.
    Died,
}

impl Live {
    pub fn label(self) -> &'static str {
        match self {
            Live::Running => "running",
            Live::Dissolved => "dissolved",
            Live::Failed => "failed",
            Live::Refused => "refused",
            Live::Died => "died",
        }
    }
    pub fn is_live(self) -> bool {
        self == Live::Running
    }
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn pid_alive(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

impl Record {
    pub fn live(&self) -> Live {
        match self.status.as_str() {
            "running" if pid_alive(self.pid) => Live::Running,
            "running" => Live::Died,
            "failed" => Live::Failed,
            "refused" => Live::Refused,
            _ => Live::Dissolved,
        }
    }

    /// How long it ran, if it finished.
    pub fn duration_ms(&self) -> Option<u64> {
        self.finished_ms.map(|f| f.saturating_sub(self.started_ms))
    }

    /// Human duration: cells are usually sub-second.
    pub fn duration_human(&self) -> Option<String> {
        self.duration_ms().map(|ms| {
            if ms < 1000 {
                format!("{ms}ms")
            } else {
                format!("{:.1}s", ms as f64 / 1000.0)
            }
        })
    }
}

fn dir(root: &Path) -> PathBuf {
    root.join("cells")
}

/// Start a record. Written immediately so a cell is visible while it runs, not
/// only once it is over.
pub fn begin(root: &Path, name: &str, spec: &Path, tools: Vec<String>) -> std::io::Result<Record> {
    let started_ms = now_ms();
    let pid = std::process::id();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    // Short, stable, and collision-resistant enough for a local registry.
    let seed = format!("{name}:{started_ms}:{nanos}:{pid}");
    let id = celln_manifest::Hash::of(seed.as_bytes())
        .0
        .trim_start_matches("blake3:")
        .chars()
        .take(12)
        .collect::<String>();

    let rec = Record {
        id,
        name: name.to_string(),
        spec: spec.to_path_buf(),
        backend: String::new(),
        pid,
        started_ms,
        finished_ms: None,
        status: "running".into(),
        tools,
        error: None,
    };
    save(root, &rec)?;
    prune(root);
    Ok(rec)
}

/// Close a record out.
pub fn finish(root: &Path, rec: &mut Record, backend: &str, error: Option<String>) {
    rec.finished_ms = Some(now_ms());
    rec.backend = backend.to_string();
    rec.status = if error.is_some() {
        "failed"
    } else {
        "dissolved"
    }
    .into();
    rec.error = error;
    let _ = save(root, rec);
}

/// Close a run which intentionally stopped at a policy boundary. A refusal is
/// neither a VM failure nor a successful tool execution; keeping it distinct
/// makes `celln ps -a` useful after the short-lived cell is gone.
pub fn refuse(root: &Path, rec: &mut Record, backend: &str, reason: String) {
    rec.finished_ms = Some(now_ms());
    rec.backend = backend.to_string();
    rec.status = "refused".into();
    rec.error = Some(reason);
    let _ = save(root, rec);
}

fn save(root: &Path, rec: &Record) -> std::io::Result<()> {
    let d = dir(root);
    std::fs::create_dir_all(&d)?;
    let path = d.join(format!("{}.json", rec.id));
    // Write-then-rename: `celln ps` in another shell never sees half a record.
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(rec).unwrap_or_default())?;
    std::fs::rename(tmp, path)
}

/// Every record, newest first.
pub fn list(root: &Path) -> Vec<Record> {
    let mut out: Vec<Record> = match std::fs::read_dir(dir(root)) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "json"))
            .filter_map(|p| std::fs::read(&p).ok())
            .filter_map(|b| serde_json::from_slice::<Record>(&b).ok())
            .collect(),
        Err(_) => Vec::new(),
    };
    out.sort_by(|a, b| b.started_ms.cmp(&a.started_ms).then(b.id.cmp(&a.id)));
    out
}

/// Drop the oldest records past [`KEEP`].
fn prune(root: &Path) {
    let all = list(root);
    for rec in all.into_iter().skip(KEEP) {
        let _ = std::fs::remove_file(dir(root).join(format!("{}.json", rec.id)));
    }
}

/// "12 seconds ago", the way every tool that shows a timestamp does it.
pub fn ago(then_ms: u64) -> String {
    let secs = now_ms().saturating_sub(then_ms) / 1000;
    let (n, unit) = match secs {
        0..=1 => return "just now".into(),
        s if s < 60 => (s, "second"),
        s if s < 3600 => (s / 60, "minute"),
        s if s < 86_400 => (s / 3600, "hour"),
        s => (s / 86_400, "day"),
    };
    format!("{n} {unit}{} ago", if n == 1 { "" } else { "s" })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ago_reads_like_english() {
        let n = now_ms();
        assert_eq!(ago(n), "just now");
        assert_eq!(ago(n - 30_000), "30 seconds ago");
        assert_eq!(ago(n - 60_000), "1 minute ago");
        assert_eq!(ago(n - 7_200_000), "2 hours ago");
        assert_eq!(ago(n - 172_800_000), "2 days ago");
    }

    #[test]
    fn a_record_whose_process_is_gone_reads_as_died() {
        let mut rec = Record {
            id: "x".into(),
            name: "n".into(),
            spec: PathBuf::new(),
            backend: String::new(),
            // pid 1 is always alive; a very high pid almost certainly is not.
            pid: u32::MAX - 1,
            started_ms: now_ms(),
            finished_ms: None,
            status: "running".into(),
            tools: vec![],
            error: None,
        };
        assert_eq!(rec.live(), Live::Died);
        rec.pid = 1;
        assert_eq!(rec.live(), Live::Running);
    }

    #[test]
    fn records_round_trip_and_list_newest_first() {
        let tmp = std::env::temp_dir().join(format!("nous-ps-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);

        let mut a = begin(&tmp, "first", Path::new("a.toml"), vec!["/bin/ls".into()]).unwrap();
        finish(&tmp, &mut a, "kvm", None);
        let mut b = begin(&tmp, "second", Path::new("b.toml"), vec![]).unwrap();
        b.started_ms += 10_000; // deterministically newer than `a`
        finish(&tmp, &mut b, "kvm", Some("boom".into()));

        let all = list(&tmp);
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].name, "second", "newest first");
        assert_eq!(all[0].live(), Live::Failed);
        assert_eq!(all[0].error.as_deref(), Some("boom"));
        assert_eq!(all[1].live(), Live::Dissolved);
        assert_eq!(all[1].tools, vec!["/bin/ls".to_string()]);

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
