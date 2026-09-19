//! The cell registry behind `celln ps`.
//!
//! A KVM VM has no identity outside the process that made it — it is a file
//! descriptor, and there is no `/proc/kvm` to enumerate. `virsh list` will
//! never show a celln cell, because libvirt only knows about domains libvirt
//! created. So if a cell is to be visible after the fact, something has to
//! write it down. This does.
//!
//! One JSON file per cell under `$CELLN_ROOT/cells/`, which makes the whole
//! thing greppable, diffable, and trivially removable — and means a crashed
//! `celln` leaves a record behind rather than losing the run.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Records kept before the oldest are pruned. Enough to be useful, small
/// enough that `celln ps -a` stays instant and the directory stays readable.
const KEEP: usize = 500;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    pub id: String,
    #[serde(alias = "name")]
    pub description: String,
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
/// marked `running` whose process is gone means `celln` was killed mid-cell.
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
pub fn begin(
    root: &Path,
    description: &str,
    spec: &Path,
    tools: Vec<String>,
) -> std::io::Result<Record> {
    let started_ms = now_ms();
    let pid = std::process::id();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    // Short, stable, and collision-resistant enough for a local registry.
    let seed = format!("{description}:{started_ms}:{nanos}:{pid}");
    let id = celln_manifest::Hash::of(seed.as_bytes())
        .0
        .trim_start_matches("blake3:")
        .chars()
        .take(12)
        .collect::<String>();

    let rec = Record {
        id,
        description: description.to_string(),
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

/// Wire version of the read-only `GET /v1/cells` report.
pub const REPORT_VERSION: &str = "celln.cells/v1";
const DEFAULT_LIMIT: usize = 100;
/// Parents listed from the journal; owners still live in the registry are
/// listed in addition, so a busy node never hides a running parent.
const MAX_PARENTS: usize = 50;
/// Newest turns per parent. With [`MAX_PARENTS`] and [`KEEP`] this bounds one
/// node's report well below the router's per-backend response cap.
const MAX_TURNS: usize = 32;
const MAX_ERROR_BYTES: usize = 1024;

/// `?all=true&limit=N` — the HTTP spelling of `celln ps [-a]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListQuery {
    /// Include finished cells, like `ps -a`. Default: live only.
    pub all: bool,
    /// Newest cells returned, `1..=500` (the registry keeps no more).
    pub limit: usize,
}

impl ListQuery {
    /// Strict: unknown, repeated or out-of-range parameters are refused rather
    /// than ignored, so the router can forward the canonical form verbatim.
    pub fn parse(query: Option<&str>) -> Result<Self, &'static str> {
        let (mut all, mut limit) = (None, None);
        for pair in query
            .unwrap_or_default()
            .split('&')
            .filter(|p| !p.is_empty())
        {
            match pair.split_once('=') {
                Some(("all", value)) if all.is_none() => {
                    all = Some(match value {
                        "true" => true,
                        "false" => false,
                        _ => return Err("all must be true or false"),
                    });
                }
                Some(("limit", value)) if limit.is_none() => {
                    limit = Some(
                        value
                            .parse::<usize>()
                            .ok()
                            .filter(|n| (1..=KEEP).contains(n) && !value.starts_with('+'))
                            .ok_or("limit must be an integer from 1 to 500")?,
                    );
                }
                _ => return Err("unsupported or repeated cells query parameter"),
            }
        }
        Ok(Self {
            all: all.unwrap_or(false),
            limit: limit.unwrap_or(DEFAULT_LIMIT),
        })
    }

    /// Canonical request target; never echoes caller bytes.
    pub fn target(&self) -> String {
        format!("/v1/cells?all={}&limit={}", self.all, self.limit)
    }
}

/// Split `/v1/cells[?query]`; `None` when the target is some other route.
pub fn report_query(target: &str) -> Option<Option<&str>> {
    match target.split_once('?') {
        None => (target == "/v1/cells").then_some(None),
        Some(("/v1/cells", query)) => Some(Some(query)),
        Some(_) => None,
    }
}

fn bounded(text: &str) -> &str {
    let mut end = text.len().min(MAX_ERROR_BYTES);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// What an operator dashboard may see of this node: the `ps` registry plus
/// parent/turn *metadata*.
///
/// Privacy boundary: task text, messages and answers stay in the journal. Only
/// identifiers, stages, timings and outcomes are copied out, through
/// `warden::parent_journal::TurnSummary`, which has no content field at all.
/// Host paths (`spec`) and pids are omitted too. Reads files and one brief
/// registry snapshot; takes no lock a running turn waits on.
pub fn report(
    root: &Path,
    node: &str,
    live_parents: &[(celln_manifest::Hash, warden::parent_registry::Status)],
    query: ListQuery,
) -> serde_json::Value {
    use warden::parent_registry::Status;
    let cells: Vec<_> = list(root)
        .into_iter()
        .filter(|record| query.all || record.live().is_live())
        .take(query.limit)
        .map(|r| {
            serde_json::json!({
                "id": r.id, "description": r.description, "status": r.live().label(),
                "backend": r.backend, "started_ms": r.started_ms,
                "finished_ms": r.finished_ms, "duration_ms": r.duration_ms(),
                "error": r.error.as_deref().map(bounded), "tools": r.tools,
            })
        })
        .collect();

    let journal = root.join("parent-journal");
    let mut summaries = warden::parent_journal::list_parents(&journal, MAX_PARENTS, MAX_TURNS);
    for (id, status) in live_parents {
        // Released owners (context lost / stopped) age out with the journal;
        // anything still holding or possibly holding a VM is always shown.
        let holds_resources = !matches!(status, Status::ContextLost | Status::Stopped);
        if holds_resources && !summaries.iter().any(|summary| &summary.parent == id) {
            summaries.push(
                warden::parent_journal::summarize_parent(&journal, id, MAX_TURNS).unwrap_or(
                    warden::parent_journal::ParentSummary {
                        parent: id.clone(),
                        updated_ms: 0,
                        turns: Vec::new(),
                        turns_total: 0,
                    },
                ),
            );
        }
    }
    let parents: Vec<_> = summaries
        .into_iter()
        .map(|summary| {
            let live = live_parents
                .iter()
                .find(|(id, _)| id == &summary.parent)
                .map(|(_, status)| *status);
            let turns: Vec<_> = summary
                .turns
                .iter()
                .map(|turn| {
                    let mut value = serde_json::json!({
                        "turnId": turn.turn_id, "stage": turn.stage, "child": turn.child,
                        "timeout_ms": u64::try_from(turn.timeout_nanos / 1_000_000).unwrap_or(u64::MAX),
                        "reserved_ms": turn.reserved_ms,
                    });
                    if let Some(succeeded) = turn.succeeded {
                        value["succeeded"] = succeeded.into();
                    }
                    value
                })
                .collect();
            serde_json::json!({
                "incarnation": summary.parent,
                // Same labels as `GET /v1/parents/<id>`. Without a live owner in
                // this process the context is lost, whatever the journal says.
                "status": format!("{:?}", live.unwrap_or(Status::ContextLost)),
                "statusIsLiveOwnerObservation": live.is_some(),
                // Null only for a live owner whose journal is unreadable.
                "updated_ms": (summary.updated_ms != 0).then_some(summary.updated_ms),
                "turns": turns,
                "turns_total": summary.turns_total,
            })
        })
        .collect();

    serde_json::json!({
        "apiVersion": REPORT_VERSION, "node": node, "cells": cells, "parents": parents,
    })
}

/// Count cells whose owning process is still alive.
///
/// The registry is the source of truth used by `celln ps`; node admission must
/// use the same definition of "live" or its advertised capacity will disagree
/// with the operator-visible state.
pub fn live_count(root: &Path) -> u32 {
    live_count_excluding_pid(root, None)
}

/// Count live cells, optionally excluding records owned by one process.
///
/// The dispatcher reserves slots for its own workers before their cells exist,
/// so it excludes its PID here to avoid counting a running dispatch twice.
pub fn live_count_excluding_pid(root: &Path, excluded_pid: Option<u32>) -> u32 {
    list(root)
        .into_iter()
        .filter(|record| excluded_pid != Some(record.pid) && record.live().is_live())
        .count()
        .try_into()
        .unwrap_or(u32::MAX)
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
    fn list_query_is_strict_and_forwards_a_canonical_target() {
        let default = ListQuery::parse(None).unwrap();
        assert_eq!((default.all, default.limit), (false, 100));
        assert_eq!(ListQuery::parse(Some("")).unwrap(), default);
        let query = ListQuery::parse(Some("limit=500&all=true")).unwrap();
        assert_eq!(query.target(), "/v1/cells?all=true&limit=500");
        for bad in [
            "all",
            "all=TRUE",
            "limit=-1",
            "limit=1.5",
            "all=true&all=true",
            "a=b",
        ] {
            assert!(ListQuery::parse(Some(bad)).is_err(), "{bad}");
        }
        assert_eq!(report_query("/v1/cells"), Some(None));
        assert_eq!(report_query("/v1/cells?x"), Some(Some("x")));
        assert_eq!(report_query("/v1/cells/x"), None);
        assert_eq!(report_query("/v1/cellsx?all=true"), None);
    }

    #[test]
    fn long_errors_are_truncated_on_a_character_boundary() {
        let text = "é".repeat(MAX_ERROR_BYTES);
        assert_eq!(bounded(&text).len(), MAX_ERROR_BYTES);
        assert_eq!(bounded(&format!("x{text}")).len(), MAX_ERROR_BYTES - 1);
        assert_eq!(bounded("short"), "short");
    }

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
            description: "n".into(),
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
        let tmp = std::env::temp_dir().join(format!("celln-ps-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);

        let mut a = begin(&tmp, "first", Path::new("a.toml"), vec!["/bin/ls".into()]).unwrap();
        finish(&tmp, &mut a, "kvm", None);
        let mut b = begin(&tmp, "second", Path::new("b.toml"), vec![]).unwrap();
        b.started_ms += 10_000; // deterministically newer than `a`
        finish(&tmp, &mut b, "kvm", Some("boom".into()));

        let all = list(&tmp);
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].description, "second", "newest first");
        assert_eq!(all[0].live(), Live::Failed);
        assert_eq!(all[0].error.as_deref(), Some("boom"));
        assert_eq!(all[1].live(), Live::Dissolved);
        assert_eq!(all[1].tools, vec!["/bin/ls".to_string()]);

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
