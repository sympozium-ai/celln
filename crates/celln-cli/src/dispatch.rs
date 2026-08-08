//! One-shot, verified Celln dispatch.
//!
//! This is deliberately a native Celln execution path, not a Kubernetes Job
//! wrapper. Kubernetes may transport the request later; this module resolves
//! the declared immutable bundle, creates the cell, and returns a receipt.

use celln_manifest::Hash;
use celln_spec::{ExecutionRequest, RequestedLane};
use celln_store::Store;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// The serializable substrate descriptor stored under `ExecutionRequest.mote`.
/// Each referenced object is resolved by content hash before the VMM is given
/// any bytes. The in-guest pilot remains responsible for confirming that the
/// selected program hash is executable from the sealed tool filesystem.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MoteBundle {
    #[serde(rename = "apiVersion")]
    api_version: String,
    kernel: String,
    initrd: String,
    toolfs: String,
    invocation: BundleInvocation,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BundleInvocation {
    alias: String,
    tool_hash: String,
}

/// Fully resolved bytes/identities the runtime can hand to its KVM launcher.
/// This boundary makes store reads observable and prevents node admission from
/// being mistaken for artifact resolution.
#[derive(Debug, Serialize)]
pub struct ResolvedBundle {
    pub bundle_hash: String,
    pub program_hash: String,
    pub kernel_hash: String,
    pub initrd_hash: String,
    pub toolfs_hash: String,
}

pub fn resolve_bundle(
    request: &ExecutionRequest,
    mote_root: &Path,
    tool_root: &Path,
) -> Result<ResolvedBundle, String> {
    let invocation = request
        .invocation
        .as_ref()
        .ok_or_else(|| "dispatch requires invocation".to_owned())?;
    let mote_hash = Hash(request.mote.hash.clone());
    let mote_store = Store::open(mote_root).map_err(|error| error.to_string())?;
    let bytes = mote_store
        .get(&mote_hash)
        .map_err(|error| error.to_string())?;
    let bundle: MoteBundle = serde_json::from_slice(&bytes)
        .map_err(|error| format!("mote bundle is not valid JSON: {error}"))?;
    if bundle.api_version != "celln.dev/v1alpha1" {
        return Err("mote bundle has an unsupported apiVersion".to_owned());
    }
    if bundle.invocation.alias != invocation.alias {
        return Err("mote bundle invocation alias does not match request".to_owned());
    }
    let requested_tool = request
        .tools
        .iter()
        .find(|tool| tool.alias == invocation.alias)
        .ok_or_else(|| "request invocation is not a declared tool".to_owned())?;
    if requested_tool.hash != bundle.invocation.tool_hash {
        return Err("mote bundle program hash does not match request".to_owned());
    }
    let tool_store = Store::open(tool_root).map_err(|error| error.to_string())?;
    tool_store
        .get(&Hash(requested_tool.hash.clone()))
        .map_err(|error| format!("declared program cannot be resolved: {error}"))?;
    for hash in [&bundle.kernel, &bundle.initrd, &bundle.toolfs] {
        mote_store
            .get(&Hash(hash.clone()))
            .map_err(|error| format!("mote bundle object cannot be resolved: {error}"))?;
    }

    Ok(ResolvedBundle {
        bundle_hash: request.mote.hash.clone(),
        program_hash: requested_tool.hash.clone(),
        kernel_hash: bundle.kernel,
        initrd_hash: bundle.initrd,
        toolfs_hash: bundle.toolfs,
    })
}

/// What actually happened inside the cell, once it dissolved.
///
/// This is deliberately not the [`celln_spec::ExecutionReceipt`] itself: the
/// receipt is an immutable, versioned wire contract with no room for a human
/// diagnostic, and a caller polling a pending execution needs a place to put
/// one. The dispatcher builds the receipt from this after the cell is gone.
pub struct LaunchOutcome {
    pub cell_id: String,
    /// `Some` only when the program ran and produced bounded output.
    pub output: Option<Vec<u8>>,
    /// `Some` when pilot refused to run the resolved program (a safe policy
    /// verdict, not a crash) or the cell produced no output block at all.
    /// The receipt still reports `Failed` either way — this is the reason.
    pub denial: Option<String>,
}

/// Resolve, seal, and run the exact program `resolve_bundle` verified exists.
///
/// This reuses the same toolfs/initrd build and `LinuxCell` boot sequence as
/// `celln agent`, with one substitution that is the entire point: the sealed
/// program comes from `tool_root` by the hash the request declared, not from
/// a model asked to write it. The guest still boots this host's own kernel
/// (`BootConfig::host_kernel()`) — `resolve_bundle` verifies the mote
/// bundle's declared `kernel`/`initrd` hashes exist and match, but actually
/// booting an arbitrary stored kernel image would need its `/lib/modules`
/// alongside it, which the mote bundle contract does not carry yet. That
/// remains a known gap, not a hidden one.
#[cfg(target_os = "linux")]
pub fn launch(
    request: &ExecutionRequest,
    resolved: &ResolvedBundle,
    tool_root: &Path,
    runtime_root: &Path,
    assay_root: &Path,
    state_root: &Path,
) -> Result<LaunchOutcome, String> {
    use warden::vmm::boot::{BootConfig, LinuxCell};

    if !Path::new("/dev/kvm").exists() {
        return Err("no /dev/kvm — cannot seal a cell on this host".to_owned());
    }
    let invocation = request
        .invocation
        .as_ref()
        .ok_or_else(|| "dispatch requires invocation".to_owned())?;

    let tool_store = Store::open(tool_root).map_err(|error| error.to_string())?;
    let program_bytes = tool_store
        .get(&Hash(resolved.program_hash.clone()))
        .map_err(|error| error.to_string())?;

    // Admit the resolved bytes into this node's own attested manifest so
    // pilot's exec gate has an entry to check against. The hash it computes
    // is a hash of these exact bytes, so it lines up with `resolved.program_hash`
    // by construction — `resolve_bundle` already proved that hash is what the
    // request declared.
    let mut assayer = assay::Assayer::open(assay_root).map_err(|error| error.to_string())?;
    assayer
        .admit_verified(&invocation.alias, &program_bytes, false)
        .map_err(|error| error.to_string())?;

    let work = crate::agent::tempdir().map_err(|error| error.to_string())?;
    // The toolfs mount path is fixed by this file's own name — mktoolfs.sh
    // seals it into the image root under this basename, so pilot finds it at
    // `/tools/program` regardless of what alias the request declares. The
    // alias is a separate, arbitrary manifest lookup key (celln-spec.Tool
    // conventions), not the mount path.
    let bin = work.join("program");
    std::fs::write(&bin, &program_bytes).map_err(|error| error.to_string())?;

    let run_json = work.join("run.json");
    std::fs::write(
        &run_json,
        serde_json::to_vec_pretty(&serde_json::json!({
            "path": "/tools/program",
            "alias": invocation.alias,
            "args": invocation.args,
            "agent_authored_input": matches!(request.execution.lane, RequestedLane::Agent),
        }))
        .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;

    let toolfs = work.join("toolfs.img");
    crate::agent::sh(
        runtime_root,
        "scripts/mktoolfs.sh",
        &[
            toolfs.display().to_string(),
            "32".into(),
            bin.display().to_string(),
        ],
    )
    .map_err(|error| error.to_string())?;

    let initrd = work.join("initramfs.cpio");
    crate::agent::sh_env(
        runtime_root,
        "scripts/mkinitramfs.sh",
        &[initrd.display().to_string()],
        &[
            (
                "CELLN_MANIFEST",
                assay_root.join("manifest.json").display().to_string(),
            ),
            ("CELLN_RUN_JSON", run_json.display().to_string()),
            (
                "CELLN_PILOT_DIR",
                runtime_root.join("pilot").display().to_string(),
            ),
        ],
    )
    .map_err(|error| error.to_string())?;

    let kernel = BootConfig::host_kernel()
        .ok_or_else(|| "no readable /boot/vmlinuz-* with matching /lib/modules".to_owned())?;
    let payload = std::fs::read(&toolfs).map_err(|error| error.to_string())?;
    let mut cfg = BootConfig::new(&kernel)
        .with_pmem(payload.len())
        .with_initrd(&initrd);
    if request.capabilities.memory_bytes > 0 {
        cfg.mem_size = request.capabilities.memory_bytes as usize;
    }
    cfg.timeout = std::time::Duration::from_millis(request.capabilities.timeout_ms.max(1));

    let name = truncate_for_description(&request.workload.id);
    let mut record = crate::cells::begin(
        state_root,
        &name,
        Path::new("<execution-request>"),
        vec![invocation.alias.clone()],
    )
    .ok();
    let cell_id = record
        .as_ref()
        .map(|record| record.id.clone())
        .unwrap_or_default();

    let mut cell = match LinuxCell::boot(cfg) {
        Ok(cell) => cell,
        Err(error) => {
            if let Some(record) = record.as_mut() {
                crate::cells::finish(state_root, record, "kvm", Some(error.to_string()));
            }
            return Err(error.to_string());
        }
    };
    if !request.capabilities.egress.is_empty() {
        let hosts: Vec<String> = request
            .capabilities
            .egress
            .iter()
            .filter_map(|destination| destination.strip_prefix("https://"))
            .map(str::to_owned)
            .collect();
        cell.enable_http_fetch(warden::egress::HttpPolicy::new(hosts));
    }
    let toolfs_hash = Hash::of(&payload);
    if let Err(error) = cell.seal_tool(&toolfs_hash, &payload) {
        if let Some(record) = record.as_mut() {
            crate::cells::finish(state_root, record, "kvm", Some(error.to_string()));
        }
        return Err(error.to_string());
    }

    let report = match cell.run() {
        Ok(report) => report,
        Err(error) => {
            if let Some(record) = record.as_mut() {
                crate::cells::finish(state_root, record, "kvm", Some(error.to_string()));
            }
            return Err(error.to_string());
        }
    };

    let mut denied: Option<String> = None;
    for line in report.console.lines() {
        let Some(rest) = line.strip_prefix("CELLN:pilot_run_") else {
            continue;
        };
        let Some((key, value)) = rest.split_once('=') else {
            continue;
        };
        if !key.ends_with("_exit") && (value.starts_with("refused") || value == "denied") {
            denied = Some(value.to_owned());
        }
    }

    let output_cap = request.capabilities.output_bytes.max(1) as usize;
    match crate::agent::slice_output(&report.console) {
        Some(text) => {
            if let Some(record) = record.as_mut() {
                crate::cells::finish(state_root, record, "kvm", None);
            }
            let mut bytes = text.into_bytes();
            bytes.truncate(output_cap);
            Ok(LaunchOutcome {
                cell_id,
                output: Some(bytes),
                denial: None,
            })
        }
        None => {
            let reason = denied.unwrap_or_else(|| "program produced no output".to_owned());
            if let Some(record) = record.as_mut() {
                crate::cells::refuse(state_root, record, "kvm", reason.clone());
            }
            Ok(LaunchOutcome {
                cell_id,
                output: None,
                denial: Some(reason),
            })
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub fn launch(
    _request: &ExecutionRequest,
    _resolved: &ResolvedBundle,
    _tool_root: &Path,
    _runtime_root: &Path,
    _assay_root: &Path,
    _state_root: &Path,
) -> Result<LaunchOutcome, String> {
    Err("sealing cells needs Linux with /dev/kvm".to_owned())
}

#[cfg(target_os = "linux")]
fn truncate_for_description(id: &str) -> String {
    if id.len() <= 30 {
        return id.to_owned();
    }
    let mut end = 30;
    while !id.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &id[..end])
}

/// `YYYY-MM-DDTHH:MM:SSZ`, computed from a Unix timestamp with no calendar
/// dependency. [Howard Hinnant's `civil_from_days`](http://howardhinnant.github.io/date_algorithms.html),
/// which this workspace has no `chrono`/`time` crate pinned to reach for.
pub fn rfc3339_utc(unix_seconds: i64) -> String {
    let days = unix_seconds.div_euclid(86_400);
    let secs_of_day = unix_seconds.rem_euclid(86_400);
    let (hour, minute, second) = (
        secs_of_day / 3600,
        (secs_of_day / 60) % 60,
        secs_of_day % 60,
    );

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };

    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Now, as an RFC3339 UTC timestamp.
pub fn now_rfc3339() -> String {
    let unix_seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0);
    rfc3339_utc(unix_seconds)
}

#[cfg(test)]
mod tests {
    use super::*;
    use celln_spec::ExecutionRequest;
    use celln_store::Store;
    use serde_json::json;
    use tempfile::tempdir;

    #[test]
    fn resolved_bundle_binds_the_requested_invocation_to_the_declared_tool() {
        let motes = tempdir().expect("mote store");
        let tools = tempdir().expect("tool store");
        let tool_store = Store::open(tools.path()).expect("open tool store");
        let tool_hash = tool_store.put(b"static-program").expect("store program");
        let mote_store = Store::open(motes.path()).expect("open mote store");
        let kernel_hash = mote_store.put(b"kernel").expect("store kernel");
        let initrd_hash = mote_store.put(b"initrd").expect("store initrd");
        let toolfs_hash = mote_store.put(b"toolfs").expect("store toolfs");
        let bundle = json!({
            "apiVersion": "celln.dev/v1alpha1",
            "kernel": kernel_hash.0,
            "initrd": initrd_hash.0,
            "toolfs": toolfs_hash.0,
            "invocation": { "alias": "/tools/program", "toolHash": tool_hash.0 }
        });
        let mote_hash = mote_store
            .put(&serde_json::to_vec(&bundle).expect("bundle serializes"))
            .expect("store bundle");
        let request: ExecutionRequest = serde_json::from_value(json!({
            "apiVersion": "celln.dev/v1alpha1",
            "id": "one-shot-1",
            "workload": { "id": "one-shot", "caller": "sympozium:default/one-shot-1" },
            "mote": { "hash": mote_hash.0 },
            "tools": [{ "alias": "/tools/program", "hash": tool_hash.0 }],
            "invocation": { "alias": "/tools/program", "args": [] },
            "capabilities": { "workspace": "none", "timeoutMs": 1000, "memoryBytes": 268435456, "outputBytes": 1024 },
            "execution": { "lane": "agent", "requireHardwareIsolation": true }
        }))
        .expect("request parses");

        let resolved =
            resolve_bundle(&request, motes.path(), tools.path()).expect("bundle resolves");
        assert_eq!(resolved.program_hash, tool_hash.0);
        assert_eq!(resolved.bundle_hash, mote_hash.0);
        assert_eq!(resolved.kernel_hash, kernel_hash.0);
        assert_eq!(resolved.initrd_hash, initrd_hash.0);
        assert_eq!(resolved.toolfs_hash, toolfs_hash.0);
    }

    #[test]
    fn rfc3339_utc_handles_a_pre_epoch_date() {
        // 1969-12-31T23:59:59Z — one second before the epoch, the standard
        // edge case for a from-scratch civil calendar conversion.
        assert_eq!(rfc3339_utc(-1), "1969-12-31T23:59:59Z");
    }

    /// Full pipeline, on real hardware: resolve a declared program from a
    /// content-addressed store, seal it into a cell, boot it, and check the
    /// output pilot reports. Not run by default — needs /dev/kvm, the
    /// `x86_64-unknown-linux-musl` target, and a host kernel with matching
    /// `/lib/modules` (same requirement `make test-kvm`/`acceptance-kvm`
    /// have). Run explicitly with:
    ///   cargo test -p celln-cli -- --ignored launch_actually_boots_and_runs_the_resolved_program
    #[test]
    #[ignore]
    #[cfg(target_os = "linux")]
    fn launch_actually_boots_and_runs_the_resolved_program() {
        use std::process::Command;

        if !Path::new("/dev/kvm").exists() {
            eprintln!("skipping: no /dev/kvm on this runner");
            return;
        }

        // ── build a tiny static-musl payload, the same shape `celln agent`
        // would forge, but written here instead of asked of a model ──
        let work = tempdir().expect("work dir");
        let src = work.path().join("main.rs");
        std::fs::write(
            &src,
            r#"fn main() { println!("hello from an execution request"); }"#,
        )
        .expect("write source");
        let program_out = work.path().join("program-bin");
        let rustc = Command::new("rustc")
            .args([
                "--edition=2021",
                "-O",
                "--target",
                "x86_64-unknown-linux-musl",
                "-o",
            ])
            .arg(&program_out)
            .arg(&src)
            .status();
        match rustc {
            Ok(status) if status.success() => {}
            _ => {
                eprintln!("skipping: rustc --target x86_64-unknown-linux-musl unavailable");
                return;
            }
        }
        let program_bytes = std::fs::read(&program_out).expect("read compiled program");

        // ── a runtime root the launch pipeline can build an initrd/toolfs
        // from, borrowing this checkout's scripts and this workspace's own
        // already-built guest pilot binaries ──
        let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."); // crates/celln-cli -> repo root
        let repo_root = repo_root.canonicalize().expect("repo root resolves");
        let pilot_dir = repo_root.join("target/x86_64-unknown-linux-musl/release");
        if !pilot_dir.join("celln-pilot").exists() || !pilot_dir.join("pilot-fetch").exists() {
            eprintln!(
                "skipping: guest pilot binaries not built — run \
                 `cargo build --release --target x86_64-unknown-linux-musl -p celln-pilot \
                 --bin celln-pilot --bin pilot-fetch` first"
            );
            return;
        }
        let runtime_root = work.path().join("runtime");
        std::fs::create_dir_all(runtime_root.join("scripts")).unwrap();
        std::fs::create_dir_all(runtime_root.join("pilot")).unwrap();
        std::fs::create_dir_all(runtime_root.join("guest/init")).unwrap();
        for script in ["mktoolfs.sh", "mkinitramfs.sh"] {
            std::fs::copy(
                repo_root.join("scripts").join(script),
                runtime_root.join("scripts").join(script),
            )
            .unwrap_or_else(|e| panic!("copying {script}: {e}"));
        }
        std::fs::copy(
            repo_root.join("guest/init/init.c"),
            runtime_root.join("guest/init/init.c"),
        )
        .expect("copy guest init.c");
        std::fs::copy(
            pilot_dir.join("celln-pilot"),
            runtime_root.join("pilot/celln-pilot"),
        )
        .expect("copy celln-pilot");
        std::fs::copy(
            pilot_dir.join("pilot-fetch"),
            runtime_root.join("pilot/pilot-fetch"),
        )
        .expect("copy pilot-fetch");

        // ── a mote bundle and matching tool, resolvable exactly like a real
        // control plane would declare them ──
        let motes = tempdir().expect("mote store");
        let tools = tempdir().expect("tool store");
        let tool_store = Store::open(tools.path()).expect("open tool store");
        let tool_hash = tool_store.put(&program_bytes).expect("store program");
        let mote_store = Store::open(motes.path()).expect("open mote store");
        let kernel_hash = mote_store.put(b"kernel-placeholder").expect("store kernel");
        let initrd_hash = mote_store.put(b"initrd-placeholder").expect("store initrd");
        let toolfs_hash = mote_store.put(b"toolfs-placeholder").expect("store toolfs");
        let bundle = json!({
            "apiVersion": "celln.dev/v1alpha1",
            "kernel": kernel_hash.0,
            "initrd": initrd_hash.0,
            "toolfs": toolfs_hash.0,
            "invocation": { "alias": "/agent/program", "toolHash": tool_hash.0 }
        });
        let mote_hash = mote_store
            .put(&serde_json::to_vec(&bundle).expect("bundle serializes"))
            .expect("store bundle");

        let request: ExecutionRequest = serde_json::from_value(json!({
            "apiVersion": "celln.dev/v1alpha1",
            "id": "launch-smoke-test",
            "workload": { "id": "smoke-test", "caller": "test:launch" },
            "mote": { "hash": mote_hash.0 },
            "tools": [{ "alias": "/agent/program", "hash": tool_hash.0 }],
            "invocation": { "alias": "/agent/program", "args": [] },
            "capabilities": { "workspace": "none", "timeoutMs": 20000, "memoryBytes": 268435456, "outputBytes": 65536 },
            "execution": { "lane": "tool", "requireHardwareIsolation": true }
        }))
        .expect("request parses");

        let resolved =
            resolve_bundle(&request, motes.path(), tools.path()).expect("bundle resolves");

        let assay_root = work.path().join("assay");
        let state_root = work.path().join("state");
        std::fs::create_dir_all(&state_root).unwrap();

        let outcome = launch(
            &request,
            &resolved,
            tools.path(),
            &runtime_root,
            &assay_root,
            &state_root,
        )
        .expect("cell launches and runs");

        assert!(
            outcome.denial.is_none(),
            "pilot denied it: {:?}",
            outcome.denial
        );
        let output = outcome.output.expect("program produced output");
        let output = String::from_utf8(output).expect("output is utf8");
        assert!(
            output.contains("hello from an execution request"),
            "unexpected output: {output:?}"
        );
    }
}
